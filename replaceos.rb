#!/bin/sh
export http_proxy=http://192.168.1.17:3128
export https_proxy=http://192.168.1.17:3128
export PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin

if [ -w /dev/console ]; then
  OUT=/dev/console
else
  OUT=/dev/null
fi

if [ -x /usr/bin/ruby ]; then
  exec ruby --disable=gems,did_you_mean -x "$0" "$@"
elif [ -x /usr/bin/apt-get ]; then
  echo "Installing Ruby using APT-GET" | tee $OUT > /dev/stderr
  apt-get update
  apt-get -y install ruby
  exec ruby --disable=gems,did_you_mean -x "$0" "$@"
elif [ -x /usr/bin/dnf ]; then
  echo "Installing Ruby using DNF" | tee $OUT > /dev/stderr
  dnf -y install ruby
  exec ruby --disable=gems,did_you_mean -x "$0" "$@"
elif [ -x /usr/bin/yum ]; then
  echo "Installing Ruby using YUM" | tee $OUT > /dev/stderr
  yum -y install ruby
  exec ruby --disable=gems,did_you_mean -x "$0" "$@"
else
  echo "Unable to run Ruby on this machine." | tee $OUT > /dev/stderr
  exit
fi

#!ruby
ENV["http_proxy"] = "http://192.168.1.17:3128"
ENV["https_proxy"] = "http://192.168.1.17:3128"
ENV["PATH"] = "/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin"

# A destination distribution selection, :FEDORA_33 and :CENTOS_8_STREAM are supported
$DIST = :FEDORA_33

# DEBUG: Snapshot point choice: false - no snapshot, 1 - create snapshot, 2 - run from snapshot
$SNAPSHOT = false

module Runtime
  def upload args
    require "socket"

    IO.popen(["ssh", *args, "cat > replaceos; chmod 0755 replaceos; exec ./replaceos --stage1"], "w") do |p|
      p.write File.read($0)
      p.close_write
    end

    sleep 2
    system "ssh", *args
  end

  def stage1
    error "Must run as root" unless `whoami`.chomp == "root"

    require "fileutils"

    unless  %w[/usr/bin/rpm /usr/bin/dnf /usr/sbin/mkfs.ext4 /bin/bash /usr/bin/curl].all? { |i| File.exist? i } ||
           (%w[/usr/bin/rpm /usr/bin/yum /usr/sbin/mkfs.ext4 /bin/bash /usr/bin/curl].all? { |i| File.exist? i } && File.exist?("/etc/debian_version"))

      if File.exist? "/usr/bin/apt-get"
        system "apt-get -y install dnf rpm e2fsprogs bash curl" or
        system "apt-get -y install yum rpm e2fsprogs bash curl" or error "Couldn't install YUM/DNF, RPM, E2FSPROGS using APT-GET"
      elsif File.exist? "/usr/bin/dnf"
        system "yum -y install e2fsprogs bash curl" or error "Couldn't install E2FSPROGS using DNF"
      elsif File.exist? "/usr/bin/yum"
        system "yum -y install dnf rpm e2fsprogs bash curl" or error "Couldn't install DNF, RPM, E2FSPROGS using YUM"
      else
        error "Can't provision YUM/DNF on this machine"
      end
    end

    dnf = if File.exist? "/usr/bin/dnf"
      "dnf"
    elsif File.exist? "/usr/bin/yum"
      "yum"
    else
      error "No DNF or YUM found."
    end

    path = "/var/tmp/replaceos"
    sysimg = path + "/sysimage"
    pivot = path + "/pivot"
    system "umount #{pivot}"

    if $SNAPSHOT != 2
      FileUtils.rm_rf path
      FileUtils.mkdir_p sysimg
      Dir.chdir sysimg

      rpmv = `rpm --version | cut -d' ' -f3`.chomp.split(".").map(&:to_i)

      FileUtils.mkdir_p "/etc/pki/rpm-gpg"

      # TODO: Attempt to replace this utility system with CentOS 8 Stream

      # rpmlib(CaretInVersions) needs 4.15
      if dnf == "dnf" && ((rpmv[0] == 4 && rpmv[1] >= 15) || rpmv[0] > 4)
        File.write "/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-33-x86_64", FEDORA_33_PUBKEY and
        %w[repos release release-common].all? do |i|
          system "rpm --nodeps --root=#{sysimg} -ivh https://download-cc-rdu01.fedoraproject.org/pub/fedora/linux/releases/33/Everything/x86_64/os/Packages/f/fedora-#{i}-33-1.noarch.rpm"
        end and
        system "#{dnf} --installroot=#{sysimg} --releasever=33 --setopt=install_weak_deps=False -y install ruby busybox rpm dnf openssh-server mdadm lvm2 e2fsprogs fedora-gpg-keys" or error "Execution failed"
      else
        # 30 is the last release compatible that CentOS 7 may install (due to lack of zstd support)
        File.write "/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-30-x86_64", FEDORA_30_PUBKEY and
        %w[repos release release-common].all? do |i|
          system "rpm --nodeps --root=#{sysimg} -ivh https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/30/Everything/x86_64/os/Packages/f/fedora-#{i}-30-1.noarch.rpm"
        end and
        system "#{dnf} --installroot=#{sysimg} --releasever=30 --setopt=install_weak_deps=False -y install ruby.x86_64 busybox rpm dnf openssh-server mdadm lvm2 e2fsprogs fedora-gpg-keys" or error "Execution failed"

        # Debian 8 needs /dev/urandom
        system "mount --bind /dev #{sysimg}/dev"
        # Install those things once more if previously installed with YUM, as they may not be registered in RPMDB
        system           "chroot #{sysimg} dnf --releasever=30 --setopt=install_weak_deps=False -y install ruby        busybox rpm dnf openssh-server mdadm lvm2 e2fsprogs fedora-gpg-keys" or error "Execution failed" if dnf == "yum"
        # Fedora 30 somehow can't install Fedora 33, but Fedora 31 can.
        system "chroot #{sysimg} dnf --releasever=31 --setopt=install_weak_deps=False -y distro-sync" or error "Execution failed"
        system "umount #{sysimg}/dev"
      end
    end

    exit if $SNAPSHOT == 1


    system "bash -c 'rm -rf #{sysimg}/{var/cache/{dnf,yum},usr/lib/locale,usr/share/{locale,doc,info,man,misc,licenses,zoneinfo,bash-completion,dbus-1}}'" and
    system "find #{sysimg} -name __pycache__ -exec rm -rf {} \\; || :" and
    system "bash -c 'mkdir -p #{sysimg}/etc/{default,sysconfig/network-scripts}'" or error "Execution failed"

    if File.exist? "/etc/network/interfaces"
      # Debian!
      network_debian_to_redhat(sysimg)
    else
      system "cp -a /etc/sysconfig/network-scripts/ifcfg-* #{sysimg}/etc/sysconfig/network-scripts/" or error "Execution failed"
    end

    system "cp -a /etc/default/grub #{sysimg}/etc/default/" and
    system "cp -a /etc/shadow #{sysimg}/etc/shadow" and
    system "cp /etc/resolv.conf #{sysimg}/etc/resolv.conf" and
    system "cp -a /root/.ssh #{sysimg}/root/ || :" and
    system "cp -a /etc/ssh #{sysimg}/etc/ || :" and
    system "cp -a #{$0} #{sysimg}/sbin/replaceos" and
    system "cp -a #{$0} #{sysimg}/sbin/replaceos-stage3" and
    system "#{sysimg}/sbin/busybox --install #{sysimg}/bin" or error "Execution failed"
    #system "#{sysimg}/sbin/busybox --install #{sysimg}/sbin" or error "Execution failed"

    # Let's try to free as much RAM as possible
    system "systemctl stop kdump"

    # Can we use zram? (~220MB -> ~110MB - so we can target 256MB vpses)
    if system "modprobe zram"
      system "swapoff /dev/zram0"
      system "echo 1 > /sys/block/zram0/reset"
      system "echo 512M > /sys/block/zram0/disksize"
      sleep 0.2
      system "echo 1 > /sys/block/zram0/reset"
      system "echo 512M > /sys/block/zram0/disksize"
      system "mkfs.ext4 /dev/zram0" and
      system "mkdir -p #{pivot}" and
      system "mount /dev/zram0 #{pivot}/" or error "Execution failed"
    else
      # We can't, so we fall back to tmpfs.
      system "mkdir -p #{pivot}" and
      system "mount -t tmpfs none #{pivot}/" or error "Execution failed"
    end
    system "cp -a #{sysimg}/* #{pivot}/" and
    system "zramctl || :" and
    Dir.chdir pivot and
    system "rm -rf #{sysimg}" or error "Execution failed"

    #system "bash -c 'mv /usr/lib/systemd/systemd{,.old} && cp -a #{$0} /usr/lib/systemd/systemd'" or
    #system "bash -c 'mv /sbin/init{,.old} && cp -a #{$0} /sbin/init" or error "Execution failed'"

    # Let's make sure nothing interrupts us.
    system "setenforce 0"
    #system "firewall-cmd --add-port=222/tcp"

    # Let's try to kill or otherwise remove what's possible.
    system "systemctl isolate multi-user.target"
    system "systemctl isolate network.target"
    system "bash -c 'for i in dbus{,-broker} systemd-journald{,-audit,-dev-log} systemd-udevd{-control,-kernel,-userdbd} avahi-daemon cups httpd sssd-kcm; do systemctl stop $i.socket; done'"
    system "bash -c 'for i in sshd rsyslog postfix httpd mysqld php-fpm crond chronyd systemd{-logind,-udevd,-journald,-userdbd,-resolved} irqbalance dbus auditd polkit gssproxy rngd atd sssd; do systemctl stop $i; done'"
    system "bash -c '#{pivot}/sbin/busybox killall -9 auditd systemd{-udevd,-hostnamed} dbus-daemon nm-online polkitd NetworkManager dhclient irqbalance chronyd'"

    puts "* Everything successful until now. We need to stop the SSH process. See you in a moment."
    sleep 1

    # This skips the stage2
    exec "systemctl switch-root #{pivot} /sbin/replaceos-stage3"

    # This method can be tried for non-systemd oses:
    #exec "systemctl daemon-reexec" or error "Execution failed"
  end

  # The stage2 is skipped on systemd systems. This stage can be used for non-systemd servers.
  # Pull requests welcome.
  def stage2
    error "Must run as root" unless `whoami`.chomp == "root"

    path = "/var/tmp/replaceos"
    sysimg = path + "/sysimage"
    pivot = path + "/pivot"

    system "echo Reached stage2 > /dev/console" or error "Couldn't write to /dev/console"
    Dir.chdir pivot or error "Couldn't chdir to pivot directory"
    mount_bind pivot
    #system "sbin/busybox killall5 -9" or error "Couldn't execute killall5"
    #apparently i don't understand killall5...
    processes = Dir["/proc/*"]
    processes.map! do |i|
      i = File.basename(i).to_i
      next if i <= 64
      i
    end
    processes.compact!
    system "kill -9 #{processes.join(" ")}"

    system "sbin/busybox swapoff -a" or error "Couldn't execute swapoff"
    system "sbin/busybox pivot_root . mnt 2>dev/console >dev/console || ps auxw >/dev/console" or error "Couldn't pivot root"
    #system "mount --move . / 2>/dev/console >/dev/console || dmesg >/dev/console" or error "Couldn't mount --move pivot_root"
    exec "/sbin/chroot . /sbin/replaceos --stage3" or error "Couldn't run stage3"
  end

  def stage3
    require "fileutils"
    error "Must run as root" unless `whoami`.chomp == "root"

    system "echo Reached stage3 > /dev/console" or error "Couldn't write to /dev/console"

    system "echo '*******************[ replaceos stage 3 ]*******************' > /etc/motd"
    system "echo '* You have  connected to  a debug shell. This is  not the *' >> /etc/motd"
    system "echo '* final system.  Please be patient while the installation *' >> /etc/motd"
    system "echo '* progresses. After we are done, you will be disconnected *' >> /etc/motd"
    system "echo '* and for a brief  time you will not  be able to connect. *' >> /etc/motd"
    system "echo '* The machine  will need  to relabel  the filesystems for *' >> /etc/motd"
    system "echo '* SELinux    and    this   will    take    some     time. *' >> /etc/motd"
    system "echo '***********************************************************' >> /etc/motd"

    #system "killall -9 dropbear"
    #system "mkdir -p /etc/dropbear; chmod 0700 /etc/dropbear"
    #system "dropbearconvert openssh dropbear /etc/ssh/ssh_host_ecdsa_key /etc/dropbear/dropbear_ecdsa_host_key"
    #system "dropbearconvert openssh dropbear /etc/ssh/ssh_host_rsa_key /etc/dropbear/dropbear_rsa_host_key"
    #system "dropbearconvert openssh dropbear /etc/ssh/ssh_host_ed25519_key /etc/dropbear/dropbear_ed25519_host_key"
    #system "dropbear -R -p 22 -b /etc/motd"

    system "chmod 0600 /etc/ssh/ssh_*_key"
    system "killall -9 sshd"
    system "/usr/sbin/sshd"

    system "rm -f /dev/log; ln -s /dev/console /dev/log"

    system "swapoff -a" or error "Couldn't execute swapoff"
    system "vgchange -a n"
    system "mdadm stop /dev/md*"

    # At this point we should be able to deal with the filesystem freely
    partjoin = ""
    dev = if File.exist? "/dev/vda"
      "/dev/vda"
    elsif File.exist? "/dev/nvme0n0"
      partjoin = "p"
      "/dev/nvme0n0"
    elsif File.exist? "/dev/sda"
      "/dev/sda"
    end

    # Are we on UEFI?
    if File.exist? "/sys/firmware/efi"
      efipart = dev+partjoin+"1"
      bootpart = dev+partjoin+"2"
      swappart = dev+partjoin+"3"
      rootpart = dev+partjoin+"4"
      pt = "g|n|||+256M|Y|n|||+1G|Y|n|||+1G|Y|n||||Y|t|1|1|w|"
    else
      efipart = false
      bootpart = dev+partjoin+"1"
      swappart = dev+partjoin+"2"
      rootpart = dev+partjoin+"3"
      pt = "o|n||||+1G|Y|n||||+1G|Y|n|||||Y|a|1|w|"
    end

    system "umount #{efipart}" if efipart
    system "umount #{bootpart}"
    system "swapoff #{swappart}"
    system "umount #{rootpart}"

    # Try to blkdiscard
    system "blkdiscard -f #{dev}"
    # Clear the partition table and initial headers
    system "dd if=/dev/zero of=#{dev} bs=1M count=1"
    system "blockdev --rereadpt #{dev}"

    system "echo '#{pt}' | tr '|' '\n' | fdisk #{dev}" or error "fdisk failed"

    system "mkswap #{swappart}" or error "mkswap failed"
    system "swapon #{swappart}" or error "swapon failed"

    system "mkfs.vfat #{efipart}" or error "mkfs.vfat /boot/efi failed" if efipart
    system "mkfs.ext4 -F #{bootpart}" or error "mkfs.ext4 /boot failed"
    system "mkfs.ext4 -F #{rootpart}" or error "mkfs.ext4 / failed"

    Dir.mkdir "/sysimage"
    system "mount #{rootpart} /sysimage" or error "Mount / failed"
    Dir.mkdir "/sysimage/boot"
    system "mount #{bootpart} /sysimage/boot" or error "Mount /boot failed"
    Dir.mkdir "/sysimage/boot/efi" if efipart
    system "mount #{efipart} /sysimage/boot/efi" or error "Mount /boot/efi failed" if efipart

    sysimg = "/sysimage"

    system "touch #{sysimg}/.autorelabel"

    %w[/proc /sys /dev /dev/pts /run].each { |i| Dir.mkdir sysimg+i }
    mount_bind sysimg

    FileUtils.mkdir_p "/var/cache/dnf"
    FileUtils.mkdir_p "#{sysimg}/var/cache/dnf"
    system "mount --bind #{sysimg}/var/cache/dnf /var/cache/dnf"

    FileUtils.mkdir_p "#{sysimg}/etc/pki/rpm-gpg"

    case $DIST
    when :FEDORA_33
      File.write          "/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-33-x86_64", FEDORA_33_PUBKEY
      File.write "#{sysimg}/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-33-x86_64", FEDORA_33_PUBKEY

      # Let's ensure this part executes. I can imagine crappy internet connections somehow making the whole process go haywire
      begin
        system "dnf --installroot=#{sysimg} --releasever=33 -y install dnf fedora-repos" or error "Execution failed"
      rescue
        sleep 10
        retry
      end

      system "chroot #{sysimg} rpm --rebuilddb"

      begin
        system "chroot #{sysimg} dnf -y groupinstall 'Minimal Install' 'Fedora Server Edition'" or error "Execution failed"
        system "chroot #{sysimg} dnf -y install kernel dracut openssh-server" or error "Execution failed"
        system "chroot #{sysimg} dnf -y install grub2-pc" or error "Execution failed" unless efipart
        system "chroot #{sysimg} dnf -y install grub2-efi-x64 shim-x64" or error "Execution failed" if efipart
      rescue
        sleep 10
        retry
      end
    when :CENTOS_8_STREAM
      File.write          "/etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial", CENTOS_8_PUBKEY
      File.write "#{sysimg}/etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial", CENTOS_8_PUBKEY

      # Let's ensure this part executes. I can imagine crappy internet connections somehow making the whole process go haywire
      begin
        system "rpm --root=#{sysimg} --nodeps -ivh https://ftp-stud.hs-esslingen.de/pub/Mirrors/centos/8-stream/BaseOS/x86_64/os/Packages/centos-stream-repos-8-2.el8.noarch.rpm" or error "Execution failed"
        system "dnf --installroot=#{sysimg} --releasever=8 -y install dnf centos-stream-repos" or error "Execution failed"
      rescue
        sleep 10
        retry
      end

      system "chroot #{sysimg} rpm --rebuilddb"

      begin
        system "chroot #{sysimg} dnf -y groupinstall 'Minimal Install' 'Server'" or error "Execution failed"
        system "chroot #{sysimg} dnf -y install kernel dracut openssh-server" or error "Execution failed"
        system "chroot #{sysimg} dnf -y install grub2-pc" or error "Execution failed" unless efipart
        system "chroot #{sysimg} dnf -y install grub2-efi-x64 shim-x64" or error "Execution failed" if efipart
      rescue
        sleep 10
        retry
      end
    end

    FileUtils.mkdir_p "#{sysimg}/etc/sysconfig/network-scripts/"
    system "cp -a /etc/sysconfig/network-scripts/ifcfg-* #{sysimg}/etc/sysconfig/network-scripts/" or error "Network scripts copy failed"

    system "cp -a /etc/ssh/ssh_*_key #{sysimg}/etc/ssh/" or error "SSH keys copy failed"
    system "chmod 0600 #{sysimg}/etc/ssh/ssh_*_key"
    system "cp -a /root/.ssh/ #{sysimg}/root/"
    system "cp -a /etc/shadow #{sysimg}/etc/shadow" or error "shadow copy failed"


    fstab = "## Generated by replaceos\n"
    fstab << "#{rootpart} / ext4 defaults 0 0\n"
    fstab << "#{bootpart} /boot ext4 defaults 1 2\n"
    fstab << "#{efipart} /boot/efi vfat umask=0077,shortname=winnt 0 2\n" if efipart
    fstab << "#{swappart} none swap defaults,x-systemd.device-timeout=0 0 0\n"
    File.write "#{sysimg}/etc/fstab", fstab

    grubcfg = File.read("/etc/default/grub").split("\n").grep(/GRUB_CMDLINE_LINUX/).join("")
    grubopts = grubcfg.scan(/\b((?:net\.ifnames|biosdevname|console|no_timer_check|nomodeset|consoleblank|scsi_mod\.use_blk_mq)(?:=[^\s]*)?)\b/).flatten.join(" ")
    grubcfg = File.read("#{sysimg}/etc/default/grub") rescue DEFAULT_GRUB_CFG
    grubcfg = grubcfg.sub('GRUB_CMDLINE_LINUX="', 'GRUB_CMDLINE_LINUX="#{grubopts} ')
    File.write("#{sysimg}/etc/default/grub", grubcfg)

    kernel = `chroot #{sysimg} rpm -q kernel-core`.split("\n").last.sub("kernel-core-", "")
    system "chroot #{sysimg} dracut -f /boot/initramfs-#{kernel}.img #{kernel}" or error "Dracut generation failed"
    system "chroot #{sysimg} grub2-mkconfig -o /etc/grub2.cfg" or error "grub2-mkconfig failed" unless efipart
    system "chroot #{sysimg} grub2-mkconfig -o /etc/grub2-efi.cfg" or error "grub2-mkconfig failed" if efipart
    system "chroot #{sysimg} grub2-install #{dev}" or error "grub2-install failed" unless efipart

    system "echo >>#{sysimg}/etc/ssh/sshd_config"
    system "echo '# This setting was set by replaceos, please remove it once' >>#{sysimg}/etc/ssh/sshd_config"
    system "echo '# you have safely connected to the server and set up some' >>#{sysimg}/etc/ssh/sshd_config"
    system "echo '# alternative way to administer it' >>#{sysimg}/etc/ssh/sshd_config"
    system "echo 'PermitRootLogin yes' >>#{sysimg}/etc/ssh/sshd_config"

    system "free"

    puts "Sending TERM to all processes"
    system "echo e > /proc/sysrq-trigger"
    puts "Sending KILL to all processes"
    system "echo i > /proc/sysrq-trigger"
    puts "Syncing filesystems"
    system "echo s > /proc/sysrq-trigger"
    puts "Unmounting filesystems"
    system "echo u > /proc/sysrq-trigger"
    puts "Rebooting"
    system "echo b > /proc/sysrq-trigger"
  rescue => e
    puts "Rescuing from... #{e.message}"
    puts e.backtrace.join("\n")
    #retry
  end

  private

  def error msg
    File.write "/dev/console", "replaceos error: #{msg}\n" if File.writable? "/dev/console"
    warn "* A critical error occured. Aborting the operation. Error:"
    warn msg
    raise
  end

  def mount_bind path
    system "mount --bind /proc #{path}/proc" or error "Couldn't mount --bind proc"
    system "mount --bind /sys #{path}/sys" or error "Couldn't mount --bind sys"
    system "mount --bind /dev #{path}/dev" or error "Couldn't mount --bind dev"
    system "mount --bind /dev/pts #{path}/dev/pts" or error "Couldn't mount --bind dev/pts"
    system "mount --bind /run #{path}/run" or error "Couldn't mount --bind run"
  end

  def network_debian_to_redhat sysimg
    input = Dir["/etc/network/interfaces.d/*"] + ["/etc/network/interfaces"]
    input = input.map { |i| File.read(i) }.join("\n")
    input = input.gsub(/\n+/, "\n").split(/\n(?!\s)/)
    config = {}

    input.each do |i|
      e = i.split(/\s+/)
      case type = e.shift
      when 'iface'
        iface = e.shift
        config[iface] ||= {"DEVICE" => iface}

        while e.length > 0
          setting = e.shift
          value = e.shift

          case setting
          when "inet"
            case value
            when "loopback"
              config[iface]["IPADDR"] = "127.0.0.1"
              config[iface]["NETMASK"] = "255.0.0.0"
              config[iface]["NETWORK"] = "127.0.0.0"
              config[iface]["BROADCAST"] = "127.255.255.255"
              config[iface]["NAME"] = "loopback"
            when "dhcp"
              config[iface]["BOOTPROTO"] = "dhcp"
            when "static"
              config[iface]["BOOTPROTO"] = "static"
            end
          when "address"
            config[iface]["ADDRESS"] = value
          when "netmask"
            config[iface]["NETMASK"] = value
          when "gateway"
            config[iface]["GATEWAY"] = value
          end
        end
      when 'auto', 'allow-hotplug'
        iface = e.shift
        config[iface] ||= {"DEVICE" => iface}
        config[iface]["ONBOOT"] = "yes"
      end
    end

    config.each do |iface,cfg|
      file = "# converted from debian by replaceos\n"
      cfg.each do |k,v|
        file << "#{k}=\"#{v}\"\n"
      end
      File.write("#{sysimg}/etc/sysconfig/network-scripts/ifcfg-#{iface}", file)
    end
  end

  FEDORA_30_PUBKEY=<<EOF
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBFturGcBEACv0xBo91V2n0uEC2vh69ywCiSyvUgN/AQH8EZpCVtM7NyjKgKm
bbY4G3R0M3ir1xXmvUDvK0493/qOiFrjkplvzXFTGpPTi0ypqGgxc5d0ohRA1M75
L+0AIlXoOgHQ358/c4uO8X0JAA1NYxCkAW1KSJgFJ3RjukrfqSHWthS1d4o8fhHy
KJKEnirE5hHqB50dafXrBfgZdaOs3C6ppRIePFe2o4vUEapMTCHFw0woQR8Ah4/R
n7Z9G9Ln+0Cinmy0nbIDiZJ+pgLAXCOWBfDUzcOjDGKvcpoZharA07c0q1/5ojzO
4F0Fh4g/BUmtrASwHfcIbjHyCSr1j/3Iz883iy07gJY5Yhiuaqmp0o0f9fgHkG53
2xCU1owmACqaIBNQMukvXRDtB2GJMuKa/asTZDP6R5re+iXs7+s9ohcRRAKGyAyc
YKIQKcaA+6M8T7/G+TPHZX6HJWqJJiYB+EC2ERblpvq9TPlLguEWcmvjbVc31nyq
SDoO3ncFWKFmVsbQPTbP+pKUmlLfJwtb5XqxNR5GEXSwVv4I7IqBmJz1MmRafnBZ
g0FJUtH668GnldO20XbnSVBr820F5SISMXVwCXDXEvGwwiB8Lt8PvqzXnGIFDAu3
DlQI5sxSqpPVWSyw08ppKT2Tpmy8adiBotLfaCFl2VTHwOae48X2dMPBvQARAQAB
tDFGZWRvcmEgKDMwKSA8ZmVkb3JhLTMwLXByaW1hcnlAZmVkb3JhcHJvamVjdC5v
cmc+iQI4BBMBAgAiBQJbbqxnAhsPBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAK
CRDvPBEfz8ZZudTnD/9170LL3nyTVUCFmBjT9wZ4gYnpwtKVPa/pKnxbbS+Bmmac
g9TrT9pZbqOHrNJLiZ3Zx1Hp+8uxr3Lo6kbYwImLhkOEDrf4aP17HfQ6VYFbQZI8
f79OFxWJ7si9+3gfzeh9UYFEqOQfzIjLWFyfnas0OnV/P+RMQ1Zr+vPRqO7AR2va
N9wg+Xl7157dhXPCGYnGMNSoxCbpRs0JNlzvJMuAea5nTTznRaJZtK/xKsqLn51D
K07k9MHVFXakOH8QtMCUglbwfTfIpO5YRq5imxlWbqsYWVQy1WGJFyW6hWC0+RcJ
Ox5zGtOfi4/dN+xJ+ibnbyvy/il7Qm+vyFhCYqIPyS5m2UVJUuao3eApE38k78/o
8aQOTnFQZ+U1Sw+6woFTxjqRQBXlQm2+7Bt3bqGATg4sXXWPbmwdL87Ic+mxn/ml
SMfQux/5k6iAu1kQhwkO2YJn9eII6HIPkW+2m5N1JsUyJQe4cbtZE5Yh3TRA0dm7
+zoBRfCXkOW4krchbgww/ptVmzMMP7GINJdROrJnsGl5FVeid9qHzV7aZycWSma7
CxBYB1J8HCbty5NjtD6XMYRrMLxXugvX6Q4NPPH+2NKjzX4SIDejS6JjgrP3KA3O
pMuo7ZHMfveBngv8yP+ZD/1sS6l+dfExvdaJdOdgFCnp4p3gPbw5+Lv70HrMjA==
=BfZ/
-----END PGP PUBLIC KEY BLOCK-----
EOF

  FEDORA_33_PUBKEY=<<EOF
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBF4wBvsBEADQmcGbVUbDRUoXADReRmOOEMeydHghtKC9uRs9YNpGYZIB+bie
bGYZmflQayfh/wEpO2W/IZfGpHPL42V7SbyvqMjwNls/fnXsCtf4LRofNK8Qd9fN
kYargc9R7BEz/mwXKMiRQVx+DzkmqGWy2gq4iD0/mCyf5FdJCE40fOWoIGJXaOI1
Tz1vWqKwLS5T0dfmi9U4Tp/XsKOZGvN8oi5h0KmqFk7LEZr1MXarhi2Va86sgxsF
QcZEKfu5tgD0r00vXzikoSjn3qA5JW5FW07F1pGP4bF5f9J3CZbQyOjTSWMmmfTm
2d2BURWzaDiJN9twY2yjzkoOMuPdXXvovg7KxLcQerKT+FbKbq8DySJX2rnOA77k
UG4c9BGf/L1uBkAT8dpHLk6Uf5BfmypxUkydSWT1xfTDnw1MqxO0MsLlAHOR3J7c
oW9kLcOLuCQn1hBEwfZv7VSWBkGXSmKfp0LLIxAFgRtv+Dh+rcMMRdJgKr1V3FU+
rZ1+ZAfYiBpQJFPjv70vx+rGEgS801D3PJxBZUEy4Ic4ZYaKNhK9x9PRQuWcIBuW
6eTe/6lKWZeyxCumLLdiS75mF2oTcBaWeoc3QxrPRV15eDKeYJMbhnUai/7lSrhs
EWCkKR1RivgF4slYmtNE5ZPGZ/d61zjwn2xi4xNJVs8q9WRPMpHp0vCyMwARAQAB
tDFGZWRvcmEgKDMzKSA8ZmVkb3JhLTMzLXByaW1hcnlAZmVkb3JhcHJvamVjdC5v
cmc+iQI4BBMBAgAiBQJeMAb7AhsPBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAK
CRBJ/XdJlXD/MZm2D/9kriL43vd3+0DNMeA82n2v9mSR2PQqKny39xNlYPyy/1yZ
P/KXoa4NYSCA971LSd7lv4n/h5bEKgGHxZfttfOzOnWMVSSTfjRyM/df/NNzTUEV
7ORA5GW18g8PEtS7uRxVBf3cLvWu5q+8jmqES5HqTAdGVcuIFQeBXFN8Gy1Jinuz
AH8rJSdkUeZ0cehWbERq80BWM9dhad5dW+/+Gv0foFBvP15viwhWqajr8V0B8es+
2/tHI0k86FAujV5i0rrXl5UOoLilO57QQNDZH/qW9GsHwVI+2yecLstpUNLq+EZC
GqTZCYoxYRpl0gAMbDLztSL/8Bc0tJrCRG3tavJotFYlgUK60XnXlQzRkh9rgsfT
EXbQifWdQMMogzjCJr0hzJ+V1d0iozdUxB2ZEgTjukOvatkB77DY1FPZRkSFIQs+
fdcjazDIBLIxwJu5QwvTNW8lOLnJ46g4sf1WJoUdNTbR0BaC7HHj1inVWi0p7IuN
66EPGzJOSjLK+vW+J0ncPDEgLCV74RF/0nR5fVTdrmiopPrzFuguHf9S9gYI3Zun
Yl8FJUu4kRO6JPPTicUXWX+8XZmE94aK14RCJL23nOSi8T1eW8JLW43dCBRO8QUE
Aso1t2pypm/1zZexJdOV8yGME3g5l2W6PLgpz58DBECgqc/kda+VWgEAp7rO2A==
=EPL3
-----END PGP PUBLIC KEY BLOCK-----
EOF

CENTOS_8_PUBKEY=<<EOF
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2.0.22 (GNU/Linux)

mQINBFzMWxkBEADHrskpBgN9OphmhRkc7P/YrsAGSvvl7kfu+e9KAaU6f5MeAVyn
rIoM43syyGkgFyWgjZM8/rur7EMPY2yt+2q/1ZfLVCRn9856JqTIq0XRpDUe4nKQ
8BlA7wDVZoSDxUZkSuTIyExbDf0cpw89Tcf62Mxmi8jh74vRlPy1PgjWL5494b3X
5fxDidH4bqPZyxTBqPrUFuo+EfUVEqiGF94Ppq6ZUvrBGOVo1V1+Ifm9CGEK597c
aevcGc1RFlgxIgN84UpuDjPR9/zSndwJ7XsXYvZ6HXcKGagRKsfYDWGPkA5cOL/e
f+yObOnC43yPUvpggQ4KaNJ6+SMTZOKikM8yciyBwLqwrjo8FlJgkv8Vfag/2UR7
JINbyqHHoLUhQ2m6HXSwK4YjtwidF9EUkaBZWrrskYR3IRZLXlWqeOi/+ezYOW0m
vufrkcvsh+TKlVVnuwmEPjJ8mwUSpsLdfPJo1DHsd8FS03SCKPaXFdD7ePfEjiYk
nHpQaKE01aWVSLUiygn7F7rYemGqV9Vt7tBw5pz0vqSC72a5E3zFzIIuHx6aANry
Gat3aqU3qtBXOrA/dPkX9cWE+UR5wo/A2UdKJZLlGhM2WRJ3ltmGT48V9CeS6N9Y
m4CKdzvg7EWjlTlFrd/8WJ2KoqOE9leDPeXRPncubJfJ6LLIHyG09h9kKQARAQAB
tDpDZW50T1MgKENlbnRPUyBPZmZpY2lhbCBTaWduaW5nIEtleSkgPHNlY3VyaXR5
QGNlbnRvcy5vcmc+iQI3BBMBAgAhBQJczFsZAhsDBgsJCAcDAgYVCAIJCgsDFgIB
Ah4BAheAAAoJEAW1VbOEg8ZdjOsP/2ygSxH9jqffOU9SKyJDlraL2gIutqZ3B8pl
Gy/Qnb9QD1EJVb4ZxOEhcY2W9VJfIpnf3yBuAto7zvKe/G1nxH4Bt6WTJQCkUjcs
N3qPWsx1VslsAEz7bXGiHym6Ay4xF28bQ9XYIokIQXd0T2rD3/lNGxNtORZ2bKjD
vOzYzvh2idUIY1DgGWJ11gtHFIA9CvHcW+SMPEhkcKZJAO51ayFBqTSSpiorVwTq
a0cB+cgmCQOI4/MY+kIvzoexfG7xhkUqe0wxmph9RQQxlTbNQDCdaxSgwbF2T+gw
byaDvkS4xtR6Soj7BKjKAmcnf5fn4C5Or0KLUqMzBtDMbfQQihn62iZJN6ZZ/4dg
q4HTqyVpyuzMXsFpJ9L/FqH2DJ4exGGpBv00ba/Zauy7GsqOc5PnNBsYaHCply0X
407DRx51t9YwYI/ttValuehq9+gRJpOTTKp6AjZn/a5Yt3h6jDgpNfM/EyLFIY9z
V6CXqQQ/8JRvaik/JsGCf+eeLZOw4koIjZGEAg04iuyNTjhx0e/QHEVcYAqNLhXG
rCTTbCn3NSUO9qxEXC+K/1m1kaXoCGA0UWlVGZ1JSifbbMx0yxq/brpEZPUYm+32
o8XfbocBWljFUJ+6aljTvZ3LQLKTSPW7TFO+GXycAOmCGhlXh2tlc6iTc41PACqy
yy+mHmSv
=kkH7
-----END PGP PUBLIC KEY BLOCK-----
EOF

  DEFAULT_GRUB_CFG=<<EOF
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR="$(sed 's, release .*$,,g' /etc/system-release)"
GRUB_DEFAULT=saved
GRUB_DISABLE_SUBMENU=true
GRUB_TERMINAL_OUTPUT="console"
GRUB_CMDLINE_LINUX="rhgb quiet"
GRUB_DISABLE_RECOVERY="true"
GRUB_ENABLE_BLSCFG=true
EOF

  extend self
end

if $0 == "/sbin/replaceos-stage3"
  Runtime.stage3
elsif ARGV.include? "--system"
  Runtime.stage2
elsif ARGV.length == 0
  puts "WARNING!!! This COMPUTER will be formatted in a moment and all data"
  puts "will be permanently lost. If you believe this is a mistake, "
  puts "ABORT WITH CTRL+C NOW!!!"
  puts "Computer hostname: #{`hostname`}"
  puts
  30.downto(0) { |i| print "\r#{i} seconds until launch..."; sleep 1 }
  Runtime.stage1
elsif ARGV[0] == "--stage1"
  Runtime.stage1
elsif ARGV[0] == "--stage3"
  Runtime.stage3
else
  Runtime.upload(ARGV)
end
