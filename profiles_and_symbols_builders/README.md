# Volatility profiles and symbols automated generation 

## About this project

This project provides scripts allowing to generate Volatility2 profiles and Volatility3 symbols for a set of Linux distributions. By setting up automated procedures that works against any specific version of a kernel, analysts can gain a precious time and concentrate on their evidences. 

## How does it work

By using Docker containers instead of virtual machines, we have a better control and flexibility over the process flow. 
Every distribution does not provide the same access to the needed kernel files. Doing so, and due to the instability and needed customization for some of them, scripts to generate profiles and symbols may not be directly available here. However, you can check the main README of this GitHub repository to access a large panel of already generated files. 

A base file including functions that should be common to any distribution is available. If you want to add your own scripts, please check out the already existing ones and import the classes from "base.py" in your file.

## Fedora generation 

Generation example :

```sh
mkdir generated_files
python3 Fedora/automate_fedora.py --kernel '4.2.6-200.fc22.x86_64' --output-dir generated_files
python3 Fedora/automate_fedora.py --kernel '6.2.9-200.fc37.x86_64' --output-dir generated_files
```

It will output one Volatility2 profile and one Volatility3 symbols file (ISF).