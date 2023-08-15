# Volatility profiles and symbols automated generation 

## About this project

This project provides scripts allowing to generate Volatility2 profiles and Volatility3 symbols for a set of Linux distributions. By setting up automated procedures that works against any specific version of a kernel, analysts can gain a precious time and concentrate on their evidences. 

## How does it work

By using Docker containers instead of virtual machines, we have a better control and flexibility over the process flow. 
Every distribution does not provide the same access to the needed kernel files. Doing so, and due to the instability and needed customization for some of them, scripts to generate profiles and symbols may not be directly available here. However, you can check the main README of this GitHub repository to access a large panel of already generated files. 

The scripts will output one Volatility2 profile and one Volatility3 symbols file (ISF).

## Requirements

- `python3`
- `docker`
- `docker` "rootless" (https://docs.docker.com/engine/security/rootless/) OR run the scripts as root

## Fedora generation 

Generation example :

```sh
mkdir generated_files
python3 Fedora/automate_fedora.py --kernel '4.2.6-200.fc22.x86_64' --output-dir generated_files
python3 Fedora/automate_fedora.py --kernel '6.2.9-200.fc37.x86_64' --output-dir generated_files
```

## AlmaLinux generation 

Generation example :

```sh
mkdir generated_files
python3 AlmaLinux/automate_almalinux.py --kernel '4.18.0-477.10.1.el8_8.x86_64' --output-dir generated_files
python3 AlmaLinux/automate_almalinux.py --kernel '5.14.0-284.18.1.el9_2.x86_64' --output-dir generated_files
```

## RockyLinux generation 

Generation example :

```sh
mkdir generated_files
python3 RockyLinux/automate_rockylinux.py --kernel '4.18.0-477.10.1.el8_8.x86_64' --output-dir generated_files
python3 RockyLinux/automate_rockylinux.py --kernel '5.14.0-284.25.1.el9_2.x86_64' --output-dir generated_files
```

## Contribute 

A base file including functions that should be common to any distribution is available. If you want to add your own scripts, please check out the already existing ones and import the classes from "base.py" in your file.

Code should be formatted with "black".