# Volatility easy install

Bored of spending more time installing volatility than actually using it ? Here is a small script that allows you to install it with all needed dependencies easily !

One container for each volatility version will be setup. The volatility code will be **hosted directly on your host**, in the home directory ("\~/vol2" and "\~/vol3"). Containers will be able to access it via a binded mount.


Requirements :

- `docker` 
- docker "rootless" (https://docs.docker.com/engine/security/rootless/) : no need to run docker as root here*

Usage : `bash vol_ez_install.sh`

```sh
>>> Volatility easy install <<<
Syntax: vol_ez_install.sh [option(s)]
options:
vol2_local     Setup latest volatility2 github master on the system
vol3_local     Setup latest volatility3 github master on the system
```

The script adds two aliases to your bashrc/zshrc, for smaller commands and better docker experience.


Example usage (from the docker host) :

```sh
# vol2
vol2d -f `wvol dump.raw` --profile [profile_name] pslist

# vol3
vol3d -f `wvol dump.raw` windows.pslist

# Translates (without aliases) to :
docker run --rm -v /:/bind/ vol2_dck python2 /bind/home/user/vol2/volatility2/vol.py -f /bind/home/user/dump.raw --profile [profile_name] pslist
docker run --rm -v /:/bind/ vol3_dck python3 /bind/home/user/vol3/volatility2/vol.py -f /bind/home/user/dump.raw  windows.pslist
```

To reference files from your host inside the container, please use the ``` `wvol [file_you_want_the_container_to_access]` ``` syntax. Doing so, it translates to a path reachable by the container. It's basically a "readlink" command prefixed with the binded volume of the container.



\* If you do not want to run docker as rootless, just edit the aliases in your "bashrc" or "zshrc" file and prefix the docker commands with "sudo".
