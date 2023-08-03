import subprocess
from dataclasses import dataclass
import logging
from base64 import b64encode
import json
import lzma
from pathlib import Path


@dataclass
class Container:
    image_name: str
    container_name: str

    def build_image(self):
        check = subprocess.run(
            f"docker inspect --type=image {self.image_name} && exit 0",
            capture_output=True,
            shell=True,
            text=True,
        )
        if check.returncode == 0:
            return

        cmd = f"docker build -t {self.image_name} -f Dockerfile-fedora .".split()
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

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

        vol2_build = self.container_obj.docker_exec(
            f"cd {self.volatility_builder_path} && make clean ; make ; ls module.dwarf && zip /tmp/{self.profile_name}.zip module.dwarf {system_map}"
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

    def vol3_build_isf(self):
        logging.info(f"[{self.kernel_full}][vol3] Building ISF...")
        vmlinux = (
            self.container_obj.docker_exec(f"find / | grep -m1 '/usr/lib/.\+/vmlinux'")
            .stdout.decode()
            .strip()
        )
        if vmlinux == "":
            raise Exception("No vmlinux file found")

        attempts_limit = 3  # dwarf2json may fail if not enough RAM is available
        for _ in range(attempts_limit):
            json_data = self.container_obj.docker_exec(
                f"dwarf2json linux --elf {vmlinux}"
            )
            if json_data.returncode != 0:
                continue
            else:
                break
        else:
            raise Exception(
                f"Error while installing executing dwarf2json : {json_data.stderr}"
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
