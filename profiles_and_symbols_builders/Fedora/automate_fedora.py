import sys

sys.path.insert(0, "..")

import logging
from dataclasses import dataclass
import os, signal
from pathlib import Path
import click
import re
import requests
from generators.base import Container, VolBuild


# CTRL-C instant killer
def handler(signum, frame):
    os.kill(os.getpid(), signal.SIGKILL)


signal.signal(signal.SIGINT, handler)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)


@dataclass
class Generator:
    kernel: str
    destination_path: Path

    def __post_init__(self):
        self.version = self.kernel.split("-")[0]
        self.release = self.kernel.split("-")[1].rsplit(".", 1)[0]
        self.arch = self.kernel.split(".")[-1]
        self.profile_name = f"Fedora_{self.kernel}.zip"
        self.isf_name = f"Fedora_{self.kernel}.json.xz"
        self.image_name = "fedora-volatility"
        self.volatility_builder_path = "/tmp/volatility/tools/linux"
        self.container_name = f"fedora-volatility-{self.kernel}"
        self.container_obj = Container(self.image_name, self.container_name)
        self.vol_obj = VolBuild(
            self.destination_path,
            self.kernel,
            self.kernel,
            self.profile_name,
            self.isf_name,
            self.volatility_builder_path,
            self.container_obj,
        )

        self.base_koji_url = f"https://kojipkgs.fedoraproject.org/packages/kernel/{self.version}/{self.release}/{self.arch}/"
        # (package_name, exit_on_error)
        self.vol2_packages = [
            ("kernel-core", True),
            ("kernel-modules", True),
            ("kernel-modules-core", False),
            ("kernel-devel", True),
        ]
        self.vol3_packages = [
            (f"kernel-debuginfo-common", True),
            ("kernel-debuginfo", True),
        ]

    def check_profile_existence(self):
        return (self.destination_path / self.profile_name).exists()

    def check_isf_existence(self):
        return (self.destination_path / self.isf_name).exists()

    def container_init(self):
        self.container_obj.build_image()
        self.container_obj.kill_container()
        self.container_obj.remove_container()
        self.container_obj.create_container()

    def check_rpms(self, target):
        if target == "vol2":
            packages = self.vol2_packages

        elif target == "vol3":
            packages = self.vol3_packages

        else:
            raise Exception("Invalid target")

        r = requests.get(self.base_koji_url).text
        full_packages = []
        for package in packages:
            package_name, exit_on_error = package
            try:
                package_url = re.findall(f'"({package_name}\S+\.rpm)"', r)[0]
                full_packages.append(
                    (package_url.split("/")[-1], f"{self.base_koji_url}{package_url}")
                )
            except Exception as e:
                if exit_on_error:
                    raise Exception(
                        f'Error while fetching package url for "{package_name}" : {e}. This indicates the package doesn\'t exist.'
                    )

        if target == "vol2":
            self.vol2_packages = full_packages

        elif target == "vol3":
            self.vol3_packages = full_packages

    def download_rpms(self, target):
        if target == "vol2":
            packages = self.vol2_packages

        elif target == "vol3":
            packages = self.vol3_packages

        else:
            raise Exception("Invalid target")

        logging.info(f"[{self.kernel}][{target}] Downloading rpms...")

        for package in packages:
            package_name, package_url = package
            print(package_name)
            package_dl = self.container_obj.docker_exec(f"wget {package_url}")
            if package_dl.returncode != 0:
                raise Exception(
                    f"Error while fetching {package_name} : {package_dl.stderr.decode()}"
                )

    def install_rpms(self, target: str):
        if target == "vol2":
            packages = self.vol2_packages

        elif target == "vol3":
            packages = self.vol3_packages
        else:
            raise Exception("Invalid target")

        logging.info(f"[{self.kernel}][{target}] Installing rpms...")
        for package in packages:
            package_name, package_url = package
            print(package_name)
            rpm_cmd = f"rpm -i --nodeps {package_name}"
            package_install = self.container_obj.docker_exec(rpm_cmd)
            if package_install.returncode != 0:
                raise Exception(
                    f"Error while installing {package_name} : {package_install.stderr.decode()}"
                )

    def __del__(self):
        self.container_obj.kill_container()
        self.container_obj.remove_container()


@click.command()
@click.option(
    "-k",
    "--kernel",
    type=str,
    help="Fedora kernel to generate profile against (ex: 4.2.6-200.fc22.x86_64)",
    required=True,
)
@click.option(
    "-o",
    "--output-dir",
    type=click.Path(writable=True, readable=True, exists=True),
    help="Output directory for profiles and symbols",
    required=True,
)
def main(kernel, output_dir: Path):
    gen_obj = Generator(kernel.strip(), Path(output_dir))

    if not gen_obj.check_isf_existence() or not gen_obj.check_profile_existence():
        logging.info(f"[{gen_obj.kernel}] Initializing variables...")
        gen_obj.container_init()

    if not gen_obj.check_isf_existence():
        try:
            gen_obj.check_rpms("vol3")
            gen_obj.download_rpms("vol3")
            gen_obj.install_rpms("vol3")
            gen_obj.vol_obj.vol3_build_isf()
        except Exception as e:
            logging.error(f"[{gen_obj.kernel}] Vol3 build failed : {e}")

    if not gen_obj.check_profile_existence():
        try:
            gen_obj.check_rpms("vol2")
            gen_obj.download_rpms("vol2")
            gen_obj.install_rpms("vol2")
            gen_obj.vol_obj.vol2_build_profile()
        except Exception as e:
            logging.error(f"[{gen_obj.kernel}] Vol2 build failed : {e}")


if __name__ == "__main__":
    main()
