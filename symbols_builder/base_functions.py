import subprocess
from dataclasses import dataclass
import logging
from base64 import b64encode
import json
import lzma
from pathlib import Path
import re


def get_project_base_path():
    return Path(__file__).parent  # Arbitrary position


OUTPUT_DIR = get_project_base_path() / "generated_symbols"


@dataclass
class Container:
    kernel: str

    def __post_init__(self):
        self.image_name = "symbols-builder"
        self.container_name = re.sub("[^.a-zA-Z0-9]", "_", self.kernel)
        self.has_container_init = False 

    def __del__(self):
        if self.has_container_init:
            self.kill_container()
            self.remove_container()

    def container_init(self):
        self.build_image()
        self.kill_container()
        self.remove_container()
        self.create_container()
        self.has_container_init = True

    def build_image(self):
        check = subprocess.run(
            f"docker inspect --type=image {self.image_name} && exit 0",
            capture_output=True,
            shell=True,
            text=True,
        )
        if check.returncode == 0:
            return

        cmd = f"cd {get_project_base_path()}/Docker && docker build -t {self.image_name} -f Dockerfile ."
        p = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True
        )

        for line in iter(p.stdout.readline, b""):
            print(">>> " + line.decode().rstrip())

    def create_container(self):
        create_cmd = subprocess.run(
            f"docker run --rm -d --name {self.container_name} {self.image_name} sleep 10000".split(),
            capture_output=True,
            text=True,
        )

        if create_cmd.returncode != 0:
            raise Exception(create_cmd.stderr)

    def kill_container(self):
        kill_cmd = f'docker kill {self.container_name} && while [ "$(docker container inspect -f \'{{{{.State.Status}}}}\' {self.container_name})" != "exited" ] && docker container inspect {self.container_name} ; do sleep 0.5; done'
        subprocess.run(kill_cmd, shell=True, capture_output=True)

    def remove_container(self):
        rm_cmd = f"docker rm {self.container_name} && while docker container inspect {self.container_name}; do sleep 0.5; done"
        subprocess.run(rm_cmd, shell=True, capture_output=True)

    def docker_exec(self, cmd: str):
        exec_res = subprocess.run(
            f"docker exec {self.container_name} sh -c 'echo \"{b64encode(cmd.encode()).decode()}\" | base64 -d | sh'",
            shell=True,
            capture_output=True,
        )
        return exec_res


@dataclass
class VolBuild:
    kernel: str
    isf_name: str
    container_obj: Container
    kernel_output_path: Path

    def __post_init__(self):
        self.dl_dir = {"vol3": "/tmp/vol3_kernel"}
        self.vol3_output_path = OUTPUT_DIR / "Volatility3" / self.kernel_output_path

    def extract_kernel_rpms(self, target):
        logging.info(f"[{self.kernel}] Extracting rpms...")

        self.container_obj.docker_exec(
            f'for file in $(ls -v {self.dl_dir[target]}/*.rpm); do rpm2cpio "$file" | cpio -D / -idm; done'
        )

    def extract_kernel_debs(self, target):
        logging.info(f"[{self.kernel}] Extracting debs...")

        extract_cmd = f'for file in $(ls -v {self.dl_dir[target]}/*.deb); do dpkg --unpack "$file"; done'  # Works great but may be interactive sometimes
        self.container_obj.docker_exec(extract_cmd)

    def check_isf_existence(self):
        return (self.vol3_output_path / self.isf_name).exists()

    def vol3_build_isf(self, vmlinux_absolute_path_prefix: str):
        logging.info(f"[{self.kernel}] Building ISF (may take a few minutes)...")
        vmlinux = (
            self.container_obj.docker_exec(
                f"find {vmlinux_absolute_path_prefix} | rg -m1 'vmlinux'"
            )
            .stdout.decode()
            .strip()
        )
        if vmlinux == "":
            raise Exception(f"No vmlinux file found in {vmlinux_absolute_path_prefix}")

        json_data = self.container_obj.docker_exec(f"dwarf2json linux --elf {vmlinux}")
        if json_data.returncode != 0:
            raise Exception(
                f"Error while executing dwarf2json : '{json_data.stderr}'. Check that enough RAM is available on your system : https://github.com/volatilityfoundation/dwarf2json/issues/38."
            )
        self.vol3_output_path.mkdir(parents=True, exist_ok=True)
        with open(self.vol3_output_path / self.isf_name, "wb+") as f:
            f.write(
                lzma.compress(
                    json.dumps(
                        json.loads(json_data.stdout), separators=(",", ":")
                    ).encode()
                )
            )

        logging.info(f"[{self.kernel}] ISF generated !")
