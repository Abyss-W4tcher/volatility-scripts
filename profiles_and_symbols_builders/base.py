import subprocess
from dataclasses import dataclass
import logging
from base64 import b64encode
import json
import lzma
from pathlib import Path


def get_project_base_path():
    return Path(__file__).parent  # Arbitrary position


@dataclass
class Container:
    image_name: str
    container_name: str
    dockerfile_path: Path

    def build_image(self):
        check = subprocess.run(
            f"docker inspect --type=image {self.image_name} && exit 0",
            capture_output=True,
            shell=True,
            text=True,
        )
        if check.returncode == 0:
            return

        cmd = f"cd {self.dockerfile_path.parent} && docker build -t {self.image_name} -f {self.dockerfile_path} ."
        p = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True
        )

        for line in iter(p.stdout.readline, b""):
            print(">>> " + line.decode().rstrip())

    def create_container(self):
        cmd = subprocess.run(
            f"docker run --rm -d --name {self.container_name} {self.image_name} sleep 1000".split(),
            capture_output=True,
            text=True,
        )

        if cmd.returncode != 0:
            logging.debug(cmd.stderr)

    def kill_container(self):
        cmd = subprocess.run(
            f"docker kill {self.container_name}".split(), capture_output=True
        )
        if cmd.returncode != 0:
            logging.debug(cmd.stderr)

    def remove_container(self):
        cmd = subprocess.run(
            f"docker rm {self.container_name}".split(), capture_output=True
        )
        if cmd.returncode != 0:
            logging.debug(cmd.stderr)

    def docker_exec(self, cmd: str):
        res = subprocess.run(
            f"docker exec {self.container_name} sh -c 'echo \"{b64encode(cmd.encode()).decode()}\" | base64 -d | sh'",
            shell=True,
            capture_output=True,
        )
        return res


@dataclass
class VolBuild:
    destination_path: Path
    kernel_short: str
    kernel_full: str
    profile_name: str
    isf_name: str
    volatility_builder_path: str
    container_obj: Container

    def vol2_build_profile(self):
        logging.info(f"[{self.kernel_full}][vol2] Building profile...")

        self.container_obj.docker_exec(
            f"sed -i 's/$(shell uname -r)/{self.kernel_short}/g' {self.volatility_builder_path}/Makefile"
        )
        self.container_obj.docker_exec(
            f"echo 'MODULE_LICENSE(\"GPL\");' >> {self.volatility_builder_path}/module.c"
        )  # https://github.com/volatilityfoundation/volatility/issues/812

        system_map = (
            self.container_obj.docker_exec(f"find / | grep -m1 'System.map'")
            .stdout.decode()
            .strip()
        )
        if system_map == "":
            raise Exception("No system.map found")

        # Prevent missing gcc header, for old kernels
        self.container_obj.docker_exec(
            'kern_dir=$(dirname $(find / | grep -m 1 "include/linux/compiler.h")) && ln_src=$(find $kern_dir/compiler-*.h | grep -P "gcc\d" | sort -rn | head -n 1) && ln -s "$ln_src" "$kern_dir/compiler-gcc$(gcc -dumpversion).h"'
        )

        vol2_build = self.container_obj.docker_exec(
            f"cd {self.volatility_builder_path} && make clean ; make ; ls module.dwarf && zip /tmp/{self.profile_name} module.dwarf {system_map}"
        )

        if vol2_build.returncode != 0:
            raise Exception(vol2_build.stderr)

        vol2_profile_path = self.destination_path / self.profile_name
        profile_content = self.container_obj.docker_exec(
            f"cat /tmp/{self.profile_name}"
        ).stdout
        with open(vol2_profile_path, "wb+") as f:
            f.write(profile_content)

        logging.info(f"[{self.kernel_full}][vol2] Profile generated !")

    def vol3_build_isf(self, vmlinux_path_prefix: str):
        logging.info(f"[{self.kernel_full}][vol3] Building ISF...")
        vmlinux = (
            self.container_obj.docker_exec(
                f"find / | grep -m1 '{vmlinux_path_prefix}.\+/vmlinux'"
            )
            .stdout.decode()
            .strip()
        )
        if vmlinux == "":
            raise Exception("No vmlinux file found")

        json_data = self.container_obj.docker_exec(f"dwarf2json linux --elf {vmlinux}")
        if json_data.returncode != 0:
            raise Exception(
                f"Error while executing dwarf2json : '{json_data.stderr}'. Check that enough RAM is available on your system : https://github.com/volatilityfoundation/dwarf2json/issues/38."
            )

        with open(self.destination_path / self.isf_name, "wb+") as f:
            f.write(
                lzma.compress(
                    json.dumps(
                        json.loads(json_data.stdout), separators=(",", ":")
                    ).encode()
                )
            )

        logging.info(f"[{self.kernel_full}][vol3] ISF generated !")
