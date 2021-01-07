Container Launcher is a small utility that can be used to create custom
containers for Linux-based systems.

Unlike LXC or Docker, Container Launcher is not a complete container framework;
rather, it is a shell command that makes containers directly, using the same
set of system calls that LXC and Docker use to make containers.

The motivation behind Container Launcher was mostly due to the limitations of
other container systems. For example, LXC and Docker use "overlay" filesystems,
but their irregular nature, specifically with respect to how files are added
and deleted, makes them unsuitable for our purposes. In addition, network
configuration is not very flexible. Finally, the exact details of things like
mount points, network topology, and the degree to which namespaces are shared
and unshared can vary wildly between containers. Container Launcher is our
own solution to this problem. Container Launcher simply performs the bare
minimums that are needed to create a container, leaving other things like
filesystem and network configuration to be performed by external shell or
Python scripts, where sequences of traditional commands like ip or mount can be
used.

TODO:

- [ ] Simple "mount" command (not one that is bloated with checks and mtab)
- [ ] Other simple commands that might be useful in a container setup context,
particularly ones that are fully aware of the behavior of namespaces

Container Launcher was also intended to supplement my Notes about namespaces
page on my website (https://www.peterjin.org/wiki/Notes_about_namespaces)
