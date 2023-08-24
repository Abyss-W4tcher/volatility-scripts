import sys

sys.path.insert(0, "..")

import logging
from dataclasses import dataclass
from pathlib import Path
import re
import requests
from symbols_builder.base_functions import (
    Container,
    VolBuild,
)


@dataclass
class Generator:
    kernel: str

    def __post_init__(self):
        self.container_obj = Container(self.kernel)

        # Construct naming
        self.distro = "RockyLinux"
        self.version = self.kernel.split(".el")[0]
        self.release = self.kernel.split("el")[1].split(".")[0].replace("_", ".")
        self.arch = self.kernel.split(".")[-1]
        self.isf_name = f"{self.distro}_{self.kernel}.json.xz"

        # Construct path naming
        self.kernel_output_path = Path(
            f"{self.distro}/{self.arch}/{self.release}/{self.version}"
        )

        # Create vol_obj
        self.vol_obj = VolBuild(
            self.kernel,
            self.isf_name,
            self.container_obj,
            self.kernel_output_path,
        )

        self.base_repo_url_vol = [
            f"https://download.rockylinux.org/pub/rocky/{self.release}/BaseOS/{self.arch}/os/Packages/k/",
            f"https://download.rockylinux.org/pub/rocky/{self.release}/Devel/{self.arch}/os/Packages/k/",
            f"https://download.rockylinux.org/pub/rocky/{self.release}/devel/{self.arch}/os/Packages/k/",
            f"https://download.rockylinux.org/pub/rocky/{self.release}/BaseOS/{self.arch}/debug/tree/Packages/k/",
        ]
        self.vol_packages = {
            "vol3": [
                ("kernel-debuginfo", True),
            ],
        }

    def check_rpms(self, target):
        full_packages = []
        for package in self.vol_packages[target]:
            package_name, exit_on_error = package
            package_url = None

            for base_repo_url in self.base_repo_url_vol:
                try:
                    r = requests.get(base_repo_url).text
                    package_url = re.findall(
                        f'"({package_name}-{self.kernel}.rpm)"', r
                    )[0]
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

        self.vol_packages[target] = full_packages

    def download_rpms(self, target):
        logging.info(f"[{self.kernel}] Downloading rpms...")

        for package in self.vol_packages[target]:
            package_name, package_url = package
            package_dl = self.container_obj.docker_exec(
                f"wget {package_url} -P {self.vol_obj.dl_dir[target]}"
            )
            if package_dl.returncode != 0:
                raise Exception(
                    f"Error while fetching {package_name} : {package_dl.stderr.decode()}"
                )


def main_rockylinux(kernel: str):
    gen_obj = Generator(kernel)

    if gen_obj.vol_obj.check_isf_existence():
        raise Exception(f"ISF (symbols file) already exists on local filesystem.")

    logging.info(f"[{gen_obj.kernel}] Initializing container...")
    gen_obj.container_obj.container_init()

    gen_obj.check_rpms("vol3")
    gen_obj.download_rpms("vol3")
    gen_obj.vol_obj.extract_kernel_rpms("vol3")
    gen_obj.vol_obj.vol3_build_isf("/usr/lib/")
