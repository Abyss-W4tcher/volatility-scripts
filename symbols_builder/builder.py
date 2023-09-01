import logging
from pathlib import Path
import click

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)

# sources
from sources.fedora import main_fedora
from sources.almalinux import main_almalinux
from sources.rockylinux import main_rockylinux


@click.group()
def group():
    pass


@group.command()
@click.option(
    "-k",
    "--kernel",
    type=str,
    help="Fedora kernel to generate symbols against (ex: 4.2.6-200.fc22.x86_64)",
    required=True,
)
def fedora(kernel: str):
    kernel = kernel.strip()

    try:
        main_fedora(kernel)
    except Exception as e:
        logging.exception(f"[{kernel}] Vol3 build failed : {e}")


@group.command()
@click.option(
    "-k",
    "--kernel",
    type=str,
    help="AlmaLinux kernel to generate symnols against (ex: 4.18.0-477.10.1.el8_8.x86_64)",
    required=True,
)
def almalinux(kernel: str):
    kernel = kernel.strip()

    try:
        main_almalinux(kernel)
    except Exception as e:
        logging.exception(f"[{kernel}] Vol3 build failed : {e}")


@group.command()
@click.option(
    "-k",
    "--kernel",
    type=str,
    help="RockyLinux kernel to generate symbols against (ex: 4.18.0-477.10.1.el8_8.x86_64)",
    required=True,
)
def rockylinux(kernel: str):
    kernel = kernel.strip()

    try:
        main_rockylinux(kernel)
    except Exception as e:
        logging.exception(f"[{kernel}] Vol3 build failed : {e}")


if __name__ == "__main__":
    group()
