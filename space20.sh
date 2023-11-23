if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

yes_no() {
    while true; do
        read -p "$1 [y/n]: " answer
        case $answer in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer yes or no.";;
        esac
    done
}




  #Chage Wallpaper
	echo "Changing The Wallpaper"
  wget -O /tmp/spacebeans.png "https://i.imgur.com/gngtbRq.png"
  gsettings set org.gnome.desktop.background picture-uri 'file:///tmp/spacebeans.png'

	cat > /etc/apt/sources.list <<EOL
deb http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse

deb http://archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse

deb http://archive.ubuntu.com/ubuntu/ focal-security main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ focal-security main restricted universe multiverse
EOL
	 echo "Restored Ubuntu 20.04 LTS default sources.list"
	 # You can also run 'sudo apt update' here to update the package cache

	 echo "Upgrading!"

	 apt update && apt upgrade -y
	 apt-get install unattended-upgrades -y && dpkg-reconfigure --priority=low unattended-upgrades

	 echo "Editing Password Policy's"
	 sudo apt-get install -y libpam-pwquality

	 cat > /etc/security/pwquality.conf <<EOL
	 minlen = 12
	 minclass = 4
	 minrepeat = 0
	 maxrepeat = 2
	 minsequence = 4
	 mincomplex = 3
	 maxconsecutive = 0
	 maxclassrepeat = 0
	 reject_username = true
	 gecoscheck = true
	 maxsequence = 3
	 maxempty = 0
	 dictcheck = 1
	 dictpath = /usr/share/dict/words
EOL

	 grep -qxF 'password requisite pam_pwquality.so retry=3' /etc/pam.d/common-password || echo 'password requisite pam_pwquality.so retry=3' >> /etc/pam.d/common-password

	 # Set password expiration policies
	 sed -i '/^PASS_MAX_DAYS/c\PASS_MAX_DAYS 90' /etc/login.defs
	 sed -i '/^PASS_MIN_DAYS/c\PASS_MIN_DAYS 7' /etc/login.defs
	 sed -i '/^PASS_WARN_AGE/c\PASS_WARN_AGE 14' /etc/login.defs

   echo "Turning On Account Lockout After Multiple Failed Attempts"
   cat >> /etc/pam.d/common-auth << EOF
   auth required pam_faillock.so preauth silent audit deny=5 unlock_time=1800
   auth required pam_faillock.so authfail audit deny=5 unlock_time=1800
EOF

  echo "Setup UFW (Remember To Manually Allow anything requested)"
  apt install ufw
  ufw enable
  ufw default deny incoming
  ufw default allow outgoing
  ufw logging on
  systemctl enable ufw
  ufw reload

  echo "Moving / Renaming Files in the /home Directory (This Could Cause Errors)"
  find /home -type f \( -iname "*.txt" -o -iname "*.md" -o -iname "*.jpg" -o -iname "*.png" -o -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.avi" -o -iname "*.mkv" -o -iname "*.mov" -o -iname "*.wav" -o -iname "*.flac" \) > script_output.txt

  if yes_no "Should SSH be configured and maintained?"; then
    echo "Configuring SSH"
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#Port.*/Port 2222/' /etc/ssh/sshd_config
    sed -i 's/#Protocol 2/Protocol 2/' /etc/ssh/sshd_config
    sed -i '/^PermitRootLogin/c\PermitRootLogin no' /etc/ssh/sshd_config
    sed -i '/^X11Forwarding/c\X11Forwarding no' /etc/ssh/sshd_config
    sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's,^#AuthorizedKeysFile.*,AuthorizedKeysFile .ssh/authorized_keys,' /etc/ssh/sshd_config
    echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config
    echo 'LoginGraceTime 60' >> /etc/ssh/sshd_config
    ufw allow 2222
    systemctl restart sshd
  else
    echo "Removing SSH"
    sudo apt-get remove --purge openssh-server -y
    sudo apt-get remove --purge openssh-client -y
    rm -rf ~/.ssh/
    sudo rm -rf /home/*/.ssh/
    sudo rm -rf /root/.ssh/
    sudo rm /etc/ssh/ssh_config
    sudo rm /etc/ssh/sshd_config
    sudo rm -rf /etc/ssh/ssh*key*
    sudo apt-get autoremove -y
    sudo systemctl disable sshd
    sudo ufw deny 22
  fi

  echo "GNOME Guest&Root Login Disabled + Extra Config"
  cp "/etc/gdm3/custom.conf" "/etc/gdm3/custom.conf.backup"
  sed -i '/^AllowGuest/c\AllowGuest=false' "/etc/gdm3/custom.conf"
  sed -i '/^\[daemon\]/a AllowGuest=false' "/etc/gdm3/custom.conf"
  sed -i '/^AllowRoot/c\AllowRoot=false' "/etc/gdm3/custom.conf"
  sed -i '/^\[security\]/a AllowRoot=false' "/etc/gdm3/custom.conf"
  sudo -i '/\[daemon\]/a AutomaticLoginEnable=False' "/etc/gdm3/custom.conf"
  sudo -i 's/^AutomaticLoginEnable=True/AutomaticLoginEnable=False/' "/etc/gdm3/custom.conf"
  gsettings set org.gnome.desktop.session idle-delay 120
  gsettings set org.gnome.desktop.screensaver lock-enabled true


  echo "Changing Systme File Permissions"
    # Correct file permissions on important system files
  chmod 644 /etc/passwd
  chmod 600 /etc/shadow
  chmod 644 /etc/group
  chmod 600 /etc/gshadow
  chmod 600 /etc/ssh/ssh_host_*_key
  chmod 644 /etc/ssh/ssh_host_*_key.pub
  chmod 644 /etc/ssh/sshd_config
  chmod 644 /etc/ssh/ssh_config
  # Ensure the SSH directory itself is set properly
  chmod 755 /etc/ssh

  echo "Kernel level hardening"
  cat >> /etc/sysctl.conf << EOF
  # Kernel level security enhancements
  fs.suid_dumpable = 0
  kernel.randomize_va_space = 2
  kernel.kptr_restrict = 2
  kernel.exec-shield = 1
  kernel.dmesg_restrict = 1
EOF
  sysctl -p

  echo "Changing Root PASSWD To Space!B3ans5"
  echo 'root:Space!B3ans5' | chpasswd

  echo "Updating Kernel"
  apt install --only-upgrade linux-generic -y

  echo "Checking Installed Programs for Games and Hacking tools, This is out putted to script_output.txt"
  echo "Games:" >> script_output.txt
  dpkg-query -Wf '${Package;-40}${Description}\n' | grep -i game >> script_output.txt
  echo "Potential Hacking Tools:" >> script_output.txt
  dpkg-query -Wf '${Package;-40}${Description}\n' | grep -E -i 'nmap|wireshark|metasploit|aircrack-ng|burpsuite|hydra|john|sqlmap|nikto|kali|pentest|exploit|crack|sniff|forensic|keylogger|hacker|phishing|spoofer|mitm|enum4linux|hashcat|netcat|tcpdump|ettercap|wpscan|owasp|recon-ng' >> script_output.txt

  echo "Install & Run AIDE"
  apt-get install aide -y
  aideinit
  mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
  echo "0 3 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" | crontab -

  echo "Disabling Unused File Systems"
  cat >> /etc/modprobe.d/unused_filesystems.conf << EOF
  install cramfs /bin/true
  install freevxfs /bin/true
  install jffs2 /bin/true
  install hfs /bin/true
  install hfsplus /bin/true
  install squashfs /bin/true
  install udf /bin/true
  install vfat /bin/true
EOF

  echo "Disable core dumps"
  echo '* hard core 0' >> /etc/security/limits.conf
  echo 'fs.suid_dumpable = 0' >> /etc/sysctl.conf

  echo "Disable USB storage for security"
  echo "install usb-storage /bin/true" >> /etc/modprobe.d/disable-usb-storage.conf

  echo "Limiting access to su command"
  dpkg-statoverride --update --add root sudo 4750 /bin/su

  echo "Some Ip Tables Editing (Could Cuase Issues With SHH/CSS)"
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT
  iptables-save > /etc/iptables/rules.v4

  if yes_no "Would You Like To Install APP_ARMOR?"; then
    echo "Installing"
    apt-get install apparmor apparmor-utils -y
    aa-enforce /etc/apparmor.d/*
  else
    echo "Ok"
  fi
