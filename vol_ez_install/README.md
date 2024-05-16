# Volatility easy install

Bored of spending more time installing volatility than actually using it ? Here is a small script that allows you to install it with all needed dependencies easily !

One container for each volatility version will be setup. The volatility code will be **hosted directly on your host**, in the home directory ("\~/vol2" and "\~/vol3"). Containers will be able to access it via a binded mount.

## Setup

**Requirements :**

- `docker`, `sudo`, `git`

Usage : `./vol_ez_install.sh`, do not use sudo to run directly.

```sh
>>> Volatility easy install <<<
Syntax: vol_ez_install.sh [option(s)]
options:
vol2_local     Setup latest volatility2 github master on the system
vol3_local     Setup latest volatility3 github master on the system
```

The script adds two aliases `vol2d` and `vol3d` to your bashrc/zshrc, for smaller commands and better docker experience.

## Usage

Example usage, **from the docker host** :

```sh
# vol2
vol2d -f "`wvol dump.raw`" imageinfo
vol2d -f "`wvol dump.raw`" --profile [profile_name] pslist
vol2d -f "`wvol dump.raw`" --profile [profile_name] procdump -D "`wvol ./dump_dir/`" -p [pid]

# vol3
vol3d -f "`wvol dump.raw`" windows.pslist
vol3d -f "`wvol dump.raw`" -o "`wvol ./dump_dir/`" windows.dumpfiles --pid [pid]

# vol3 volshell
volshell3d -f "`wvol dump.raw`" -h
```

To reference files of your host inside the container, please use the ``` "`wvol [file_you_want_the_container_to_access]`" ``` syntax. Doing so, it translates to a path reachable by the container.
