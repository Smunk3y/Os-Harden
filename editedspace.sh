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
  wget -O /home/spacebeans.png "https://i.imgur.com/gngtbRq.png"


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

   cp /etc/security/pwquality.conf /etc/security/pwquality.conf.backup
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
ucredit = -1
lcrdeit = -1
ocredit = -1
dcredit = -1
usercheck = 1
EOL


   cp /etc/login.defs /etc/login.defs.backup
   sed -i '/^ENCRYPT_METHOD/c\ENCRYPT_METHOD SHA512' /etc/login.defs
   sed -i '/^LOGIN_RETRIES/c\LOGIN_RETRIES 4' /etc/login.defs
	 grep -qxF 'password requisite pam_pwquality.so retry=3' /etc/pam.d/common-password || echo 'password requisite pam_pwquality.so retry=3' >> /etc/pam.d/common-password
   sudo sed -i '/pam_unix.so/ s/remember=[0-9]*/remember=5/' /etc/pam.d/common-password
   echo "password requisite pam_unix.so remember=5" | tee -a /etc/pam.d/common-password

	 # Set password expiration policies
   sed -i '/^PASS_MAX_DAYS/c\PASS_MAX_DAYS 30' /etc/login.defs
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

  echo " Lisiting Files in the /home Directory to script_output.txt"
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
    sudo ufw allow OpenSSH
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
  sed -i '/^User=/d' /etc/gdm3/custom.conf
  sed -i '/^Group=/d' /etc/gdm3/custom.conf
  sudo sed -i '/^DisallowTCP=/d' /etc/gdm3/custom.conf && echo 'DisallowTCP=true' | sudo tee -a /etc/gdm3/custom.conf
  sed -i '/^AllowRoot/c\AllowRoot=false' "/etc/gdm3/custom.conf"
  sed -i '/^\[security\]/a AllowRoot=false' "/etc/gdm3/custom.conf"
  sudo -i '/\[daemon\]/a AutomaticLoginEnable=False' "/etc/gdm3/custom.conf"
  sudo -i 's/^AutomaticLoginEnable=True/AutomaticLoginEnable=False/' "/etc/gdm3/custom.conf"
  gsettings set org.gnome.desktop.session idle-delay 120
  gsettings set org.gnome.desktop.screensaver lock-enabled true

    echo "What is the Main user?"
    read DAUSER

    export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u $USER)/bus
    sudo -u $DAUSER gsettings set org.gnome.desktop.session idle-delay 300
    sudo -u $DAUSER gsettings set org.gnome.desktop.screensaver lock-enabled true
    sudo -u $DAUSER gsettings set org.gnome.desktop.remote-desktop.rdp enable falsecc
    sudo -u $DAUSER gsettings set org.gnome.desktop.screensaver lock-delay 10
    sudo -u $DAUSER gsettings set org.gnome.desktop.lockdown disable-user-switching true
    sudo -u $DAUSER gsettings set org.gnome.desktop.lockdown disable-lock-screen false
    sudo -u $DAUSER gsettings set org.gnome.desktop.background picture-uri 'file:///home/spacebeans.png'


  echo "Changing Systme File Permissions"
    # Correct file permissions on important system files
  chmod 644 /etc/passwd
  chmod 600 /etc/shadow
  chmod 644 /etc/group
  chmod 600 /etc/gshadow
  chmod 700 /home
  chmod 700 /home/*
  chmod 600 /swapfile
  chmod 600 /etc/ssh/ssh_host_*_key
  chmod 644 /etc/ssh/ssh_host_*_key.pub
  chmod 644 /etc/ssh/sshd_config
  chmod 644 /etc/ssh/ssh_config
  chmod 700 /root
  chmod 600 /boot/grub/grub.cfg
  chmod 600 /etc/fstab
  chmod 600 /etc/crontab
  chmod 700 /etc/cron.*  # This secures all cron directories
  chmod 755 /etc /bin /sbin /lib /usr/bin /usr/sbin /usr/lib
  chmod 440 /etc/sudoers
  chmod 750 /etc/sudoers.d
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

  echo "Enabling Kernel Lockdown"
  sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT=/ s/"$/ lockdown=integrity"/' /etc/default/grub && update-grub
  
  sudo passwd --lock root

  echo "Setting Common System Accounts to NOLOGIN"
  for user in syslog nobody games gnats; do
    sudo usermod -s /usr/sbin/nologin $user
  done
  
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

  echo "Max Process Limit Added"
  echo '* hard nproc 1980' | sudo tee -a /etc/security/limits.conf


  echo "Limiting access to su command"
  dpkg-statoverride --update --add root sudo 4750 /bin/su

  echo "Confiuring Auditd"
  sed -i '/^local_events/ c\local_events = yes' /etc/audit/auditd.conf
  auditctl -w /var/log/lastlog -p war -k logins
  sed -i '/^max_log_file/ c\max_log_file = 64' /etc/audit/auditd.conf
  sed -i '/^max_log_file_action/ c\max_log_file_action = ROTATE' /etc/audit/auditd.conf
  sed -i '/^num_logs/ c\num_logs = 128 ' /etc/audit/auditd.conf
  auditctl -w /var/run/faillock/ -p war -k login_failures
  auditctl -w /etc/passwd -p wa -k passwd_changes
  auditctl -w /etc/shadow -p wa -k shadow_changes
  sudo auditctl -w /path/to/sensitive_file -p rwxa -k file_monitor
  sudo auditctl -w /home/specific_user -p wa -k user_monitor
  sudo echo "-e 2" >> /etc/audit/rules.d/audit.rules
  sudo sed -i '/^space_left_action/ c\space_left_action = EMAIL' /etc/audit/auditd.conf
  sudo sed -i '/^action_mail_acct/ c\action_mail_acct = root@localhost' /etc/audit/auditd.conf
  sudo sed -i '/^admin_space_left_action/ c\admin_space_left_action = SUSPEND' /etc/audit/auditd.conf
  sudo sed -i '/^log_format/ c\log_format = ENRICHED' /etc/audit/auditd.conf
  systemctl restart auditd

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

  if yes_no "Should NFS Be Upkept"; then
    sudo sed -i 's/^#NFS4_SUPPORT="no"/NFS4_SUPPORT="yes"/' /etc/default/nfs-common
    echo "Upkept"
  else
    sudo systemctl stop nfs-blkmap
    sudo systemctl disable nfs-blkmap
    sudo systemctl stop nfs-idmapd
    sudo systemctl disable nfs-idmapd
    sudo systemctl stop nfs-mountd
    sudo systemctl disable nfs-mountd
    sudo systemctl stop nfsdcld
    sudo systemctl disable nfsdcld
    sudo systemctl stop nfs-server
    sudo systemctl disable nfs-server
    sudo systemctl stop nfs-kernel-server
    sudo systemctl disable nfs-kernel-server
    echo "All specified NFS services have been disabled."
  fi

  if yes_no "Should Apache Be Upkept"; then

      sudo systemctl enable apache2
      sudo systemctl start apache2

      sudo sed -i '/^ServerSignature\s*On/d' /etc/apache2/conf-enabled/security.conf
      grep -q '^ServerSignature\s*Off$' /etc/apache2/conf-enabled/security.conf || echo 'ServerSignature Off' | sudo tee -a /etc/apache2/conf-enabled/security.conf

      sudo sed -i '/^ServerTokens\s*Full/d' /etc/apache2/conf-enabled/security.conf
      grep -q '^ServerTokens\s*Prod$' /etc/apache2/conf-enabled/security.conf || echo 'ServerTokens Prod' | sudo tee -a /etc/apache2/conf-enabled/security.conf

      sudo sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/Options Indexes FollowSymLinks/Options FollowSymLinks/' /etc/apache2/apache2.conf
      sudo systemctl restart apache2

      # Configure the firewall
      echo "Configuring the firewall to allow HTTP and HTTPS..."
      sudo ufw allow "Apache Secure"
      sudo ufw reload
      echo "Apache has been configured for basic security and allowed through the firewall."
  else
      # Stop and disable Apache service
      sudo systemctl stop apache2
      sudo systemctl disable apache2

      echo "Apache service has been stopped and disabled."
  fi

  if yes_no "Should FTP (VSFTPD) Be Maintained?"; then
    cp /etc/vsftpd.conf /etc/vsftpd.conf.copy
    sudo apt-get update && sudo apt-get install vsftpd
    systemctl start vsftpd
    systemctl enable vsftpd

    sudo sed -i '/^anonymous_enable\s*=\s*YES/d' /etc/vsftpd.conf
    grep -q '^anonymous_enable\s*=\s*NO$' /etc/vsftpd.conf || echo 'anonymous_enable=NO' | sudo tee -a /etc/vsftpd

    grep -q '^ssl_enable=YES$' /etc/vsftpd.conf || echo 'ssl_enable=YES' | sudo tee -a /etc/vsftpd.conf
    grep -q '^ssl_tlsv1=YES$' /etc/vsftpd.conf || echo 'ssl_tlsv1=YES' | sudo tee -a /etc/vsftpd.conf
    sed -i '/^ssl_sslv2=YES/d' /etc/vsftpd.conf
    sed -i '/^ssl_sslv3=YES/d' /etc/vsftpd.conf
    sed -i '/^allow_anon_ssl=YES/d' /etc/vsftpd.conf

    grep -q '^pasv_min_port=50000$' /etc/vsftpd.conf || echo 'pasv_min_port=50000' | sudo tee -a /etc/vsftpd.conf
    grep -q '^pasv_max_port=50100$' /etc/vsftpd.conf || echo 'pasv_max_port=50100' | sudo tee -a /etc/vsftpd.conf
    ufw allow 50000:50100/tcp
    ufw allow vsftpd

    sudo systemctl restart vsftpd
    sudo ufw reload
  else
    sudo systemctl stop vsftpd
    sudo apt-get remove --purge vsftpd
    sudo apt-get autoremove

    echo "Removed VSFTPD"
  fi


  if yes_no "Should Edits Be Made To sysctl.conf?"; then

    sudo cp /etc/sysctl.conf /etc/sysctl.conf.backup


    # IPv4 TIME-WAIT ASSASSINATION Protection
    sudo sed -i '/^net\.ipv4\.tcp_rfc1337/d' /etc/sysctl.conf
    echo 'net.ipv4.tcp_rfc1337 = 1' | sudo tee -a /etc/sysctl.conf > /dev/null

    #Disable ipv6
    grep -q '^net.ipv6.conf.all.disable_ipv6\s*=\s*1$' /etc/sysctl.conf || echo 'net.ipv6.conf.all.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf
    grep -q '^net.ipv6.conf.default.disable_ipv6\s*=\s*1$' /etc/sysctl.conf || echo 'net.ipv6.conf.default.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf

    # IPv4 TCP SYN Cookies
    sudo sed -i '/^net\.ipv4\.tcp_syncookies/d' /etc/sysctl.conf
    echo 'net.ipv4.tcp_syncookies = 1' | sudo tee -a /etc/sysctl.conf > /dev/null

    # Disable IPv4 forwarding
    sudo sed -i '/^net\.ipv4\.ip_forward/d' /etc/sysctl.conf
    echo 'net.ipv4.ip_forward = 0' | sudo tee -a /etc/sysctl.conf > /dev/null

    # Disable Source Routing
    sudo sed -i '/^net\.ipv4\.conf\.all\.accept_source_route/d' /etc/sysctl.conf
    echo 'net.ipv4.conf.all.accept_source_route = 0' | sudo tee -a /etc/sysctl.conf > /dev/null
    sudo sed -i '/^net\.ipv4\.conf\.default\.accept_source_route/d' /etc/sysctl.conf
    echo 'net.ipv4.conf.default.accept_source_route = 0' | sudo tee -a /etc/sysctl.conf > /dev/null

    # Disable Send Redirects
    sudo sed -i '/^net\.ipv4\.conf\.all\.send_redirects/d' /etc/sysctl.conf
    echo 'net.ipv4.conf.all.send_redirects = 0' | sudo tee -a /etc/sysctl.conf > /dev/null
    sudo sed -i '/^net\.ipv4\.conf\.default\.send_redirects/d' /etc/sysctl.conf
    echo 'net.ipv4.conf.default.send_redirects = 0' | sudo tee -a /etc/sysctl.conf > /dev/null

    # Enable Martian Packet Logging
    sudo sed -i '/^net\.ipv4\.conf\.all\.log_martians/d' /etc/sysctl.conf
    echo 'net.ipv4.conf.all.log_martians = 1' | sudo tee -a /etc/sysctl.conf > /dev/null

    # Source Address Verification
    sudo sed -i '/^net\.ipv4\.conf\.default\.rp_filter/d' /etc/sysctl.conf
    echo 'net.ipv4.conf.default.rp_filter = 1' | sudo tee -a /etc/sysctl.conf > /dev/null
    sudo sed -i '/^net\.ipv4\.conf\.all\.rp_filter/d' /etc/sysctl.conf
    echo 'net.ipv4.conf.all.rp_filter = 1' | sudo tee -a /etc/sysctl.conf > /dev/null

    # Ignore ICMP Redirects
    sudo sed -i '/^net\.ipv4\.conf\.all\.accept_redirects/d' /etc/sysctl.conf
    echo 'net.ipv4.conf.all.accept_redirects = 0' | sudo tee -a /etc/sysctl.conf > /dev/null
    sudo sed -i '/^net\.ipv4\.conf\.default\.accept_redirects/d' /etc/sysctl.conf
    echo 'net.ipv4.conf.default.accept_redirects = 0' | sudo tee -a /etc/sysctl.conf > /dev/null

    # Apply sysctl changes
    sudo sysctl -p

    echo "Sysctl configurations have been updated for security."
  else
    echo "Keep in mind that points are ussaly found in editing sysctl.conf"
  fi



  if yes_no "Remove All Known Hacking Tools From this Computer?"; then
    hackingtools=(
    "hydra"
    "nmap"
    "john"
    "metasploit-framework"
    "aircrack-ng"
    "wireshark"
    "burpsuite"
    "sqlmap"
    "ettercap"
    "kismet"
    "nikto"
    "wpscan"
    "hashcat"
    "netcat"
    "tcpdump"
    "zenmap"
    "hping3"
    "ophcrack"
    "yersinia"
    "dsniff"
    "ferret"
    "sid"
    "gqrx-sdr"
    "maltego"
    "reaver"
    "bluesnarfer"
    "redsocks"
    "mimikatz"
    "beef-xss"
    "king-phisher"
    "gobuster"
    "snort"
    "suricata"
    "masscan"
    "radare2"
    "cuckoo"
    "exploitdb"
    "seclists"
    "binwalk"
    "foremost"
    "volatility"
    "wireshark"
    "scapy"
    "socat"
    "zaproxy"
    "arp-scan"
    "angry-ip-scanner"
    "lynis"
    "chkrootkit"
    "rkhunter"
    "tcpflow"
    "sslsplit"
    "sslstrip"
)

  # Loop through each tool and remove it
  for hackingtools in "${hackingtools[@]}"; do
      echo "Removing $hackingtools..."
      sudo apt-get remove "$hackingtools"
      sudo apt-get purge "$hackingtools"
  done

  sudo apt-get autoremove

  echo "Uninstallation process completed."

  else
    echo "Make Sure only allowed tools are installed"
  fi


  if yes_no "Enable GRUB Signature Checks"; then
    echo "set check_signatures=enforce" | sudo tee -a /etc/grub.d/40_custom
    echo "export check_signatures" | sudo tee -a /etc/grub.d/40_custom
  else
    echo "Ok"
  fi



  echo "Force Updates"
  update-manager -d
