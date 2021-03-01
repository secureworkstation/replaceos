# replaceos

replaceos is a script to live replace a remote operating system (called a base
system in this document) over SSH with a fresh Red Hat-based operating system
(called a target system in this document; only Fedora 33 and CentOS 8 Stream are
supported as target systems).

It is intended to be used on remote VPSes and dedicated servers where there is
only a miniscule number of older distributions available and a regular reinstall
may be a higher scale effort (possibly time and money consuming) and only older
systems are available.

The main effort of this project is to ensure this script runs flawlessly, so you
can anticipate the system to retain the network settings, SSH keys and a root
password after installation. It also aims to take as little RAM as possible, so
it's possible to (carefully) run it on 256MB systems, but 512MB is recommended.

This script assumes that the base system runs `systemd` and is fresh enough to
have the necessary facilities.

It is a very good idea to run it on a newly installed system, possibly being as
standard as possible. You should try to stop as many services prior to this
process to increase the odds of it succeeding.

DO NOTE THAT THIS SCRIPT *WILL* ERASE ALL FILES ON YOUR SERVER.

It is recommended for a user to familiarize himself with this script, as it's
not too long. It is written with default sane settings in mind, but can be
easily modified.

DO NOTE THAT THIS SCRIPT COMES WITH NO WARRANTY. IT MAY LOCK YOU OFF THE SERVER.
IT MAY ALSO NOT BE TESTED ENOUGH. MAKE SURE TO MAKE A CONTINGENCY PLAN.

## How it works?

In the upload stage (which you run on your own computer), it simply copies
itself to a server over SSH and then it runs stage1 on the server.

In stage1 it downloads a utility system of Fedora 30, which is then upgraded to
Fedora 31 (for older base systems), or Fedora 33 (for newer ones) - it is about
200MB in size. It is moved to a fresh ext4 filesystem on zram, which reduces its
size to about 100MB. Once it's ready, it kills as many system services as
possible and replaces the root filesystem with this utility system using
`systemctl switch-root` which is told to run stage3.

In stage3 it has a read-write access to the block devices and our script has
a pid 1. It now dismantles all of them, then zeroes the partition table and
netinstalls a target system. Afterwards the system is rebooted. During stage3
you are given a debug SSH session.

Now, your new system starts. The first boot will take longer, because during
this boot a SELinux relabel will happen. After it finishes it reboots again and
once it's done, the process is finished.

## Post-installation tasks

* /etc/ssh/sshd_config: replaceos adds AllowRootLogin yes. Make sure this is
  what you actually want.

## How to run?

Simply, if you connect to a server with:

```bash
$ ssh root@123.45.67.89 -p 222
```

You can run:

```bash
$ ./replaceos.rb root@123.45.67.89 -p 222
```

That is all in general. Before that process you may want to tweak the script
itself (for example to pick a target OS).

You can also upload the script to a server yourself and run (ON A SERVER):

```bash
# ./replaceos.rb
```

## Tested base systems

distribution | min.RAM | result
------------ | ------- | --------------------------
Debian 8     | 256MB   | SUCCESS
Debian 9     | 256MB   | SUCCESS
Debian 10    | 256MB   | SUCCESS
CentOS 7     | 256MB   | SUCCESS (primary focus)
CentOS 8     | 400MB   | SUCCESS
Fedora 30    | 256MB   | SUCCESS
Fedora 33    | 256MB   | SUCCESS (secondary focus)

Ubuntu systems should also work fine, but no testing has been done yet.

## Technologies tested

* lvm2 (not recommended)
* UEFI

## Technologies that may work

* mdadm
