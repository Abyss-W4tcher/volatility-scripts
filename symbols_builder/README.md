# Volatility3 symbols automated generation 

## About this project

This project provides scripts allowing to generate Volatility3 symbols for a set of Linux distributions. By setting up automated procedures working against any specific version of a kernel, analysts can gain a precious time and concentrate on their evidences. 

## Requirements

- `python3`
- `docker`
- `docker` "rootless" (https://docs.docker.com/engine/security/rootless/) OR run the scripts as root

## Usage 

```sh
python3 builder.py --help # List available distributions
python3 builder.py [distribution] --help # Instructions for distribution generation
```

## Contribute 

Add scripts for a distribution directly inside the "sources" directory. Then, edit the "builder.py" to make it available as an argument.

Code should be formatted with "black".