import sys

sys.path.insert(0, "..")

import logging
from dataclasses import dataclass
import os, signal
from pathlib import Path
import click
import re
import requests
from profiles_and_symbols_builders.base import (
    Container,
    VolBuild,
    get_project_base_path,
)

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
        self.version = self.kernel.split(".el")[0]
        self.release = self.kernel.split("el")[1].split(".")[0].replace("_",".")
        self.arch = self.kernel.split(".")[-1]
        self.profile_name = f"AlmaLinux_{self.kernel}.zip"
        self.isf_name = f"AlmaLinux_{self.kernel}.json.xz"
        self.image_name = "almalinux-volatility"
        self.volatility_builder_path = "/tmp/volatility/tools/linux"
        self.container_name = f"almalinux-volatility-{self.kernel}"
        self.container_obj = Container(
            self.image_name,
            self.container_name,
            get_project_base_path() / "AlmaLinux/Dockerfile-almalinux",
        )
        self.vol_obj = VolBuild(
            self.destination_path,
            self.kernel,
            self.kernel,
            self.profile_name,
            self.isf_name,
            self.volatility_builder_path,
            self.container_obj,
        )

        self.base_repo_url_vol = [
            f"https://repo.almalinux.org/almalinux/{self.release}/BaseOS/{self.arch}/os/Packages/", 
            f"https://repo.almalinux.org/almalinux/{self.release}/AppStream/{self.arch}/os/Packages/",
            f"https://repo.almalinux.org/almalinux/{self.release}/devel/{self.arch}/os/Packages/",
            f"https://repo.almalinux.org/vault/{self.release}/BaseOS/debug/{self.arch}/Packages/",
        ]

        # (package_name, exit_on_error)
        self.vol2_packages = [
            ("kernel-core", True),
            ("kernel-devel", True),
            ("kernel-modules", True),
            ("kernel-modules-core", False),
        ]

        self.vol3_packages = [
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

        full_packages = []
        for package in packages:
            package_name, exit_on_error = package
            print(package_name)
            package_url = None
            
            for base_repo_url in self.base_repo_url_vol:
                try:
                    r = requests.get(base_repo_url).text
                    package_url = re.findall(f'"({package_name}-{self.kernel}.rpm)"', r)[0]
                    full_packages.append(
                        (package_url.split("/")[-1], f"{base_repo_url}{package_url}")
                    )
                    break  # Exit the loop if the package is found
                except Exception as e:
                    continue  # Try the next base_repo_url if the package is not found
                    
            if package_url is None and exit_on_error:
                raise Exception(
                    f'Error while fetching package url for "{package_name}" : Package not found in any repositories.'
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
    help="AlmaLinux kernel to generate profile against (ex: 4.18.0-477.10.1.el8_8.x86_64)",
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
            gen_obj.vol_obj.vol3_build_isf("/usr/lib/")
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