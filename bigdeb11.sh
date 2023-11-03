# Might not Run, Useful Commands in here that should be run on own if looking for points late onto the comp

# Check if running as root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# Upgrade & Update System
apt update && apt upgrade -y

# Install security updates automatically
apt-get install unattended-upgrades -y && dpkg-reconfigure --priority=low unattended-upgrades

# Update password requirements
# The 'nano' command has been removed since we're directly adding configurations to files.
cat > /etc/security/pwquality.conf << EOF
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
EOF

# Reload password service
systemctl restart systemd-logind

# Ensure pwquality is enforced
grep -qxF 'password requisite pam_pwquality.so retry=3' /etc/pam.d/common-password || echo 'password requisite pam_pwquality.so retry=3' >> /etc/pam.d/common-password

# Set password expiration policies
sed -i '/^PASS_MAX_DAYS/c\PASS_MAX_DAYS 90' /etc/login.defs
sed -i '/^PASS_MIN_DAYS/c\PASS_MIN_DAYS 7' /etc/login.defs
sed -i '/^PASS_WARN_AGE/c\PASS_WARN_AGE 14' /etc/login.defs

# Add brute force security measures
cat >> /etc/pam.d/common-auth << EOF
auth required pam_faillock.so preauth silent audit deny=5 unlock_time=1800
auth required pam_faillock.so authfail audit deny=5 unlock_time=1800
EOF

# Enable the firewall and set default policies
ufw enable
ufw default deny incoming
ufw default allow outgoing

# Install and configure Fail2ban for additional security against brute force
apt-get install fail2ban -y
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
systemctl enable fail2ban
systemctl start fail2ban

# Schedule daily system updates
(crontab -l ; echo "0 0 * * * apt update && apt upgrade -y") | crontab -

# Rename disallowed personal media files
find /home -type f \( -iname "*.txt" -o -iname "*.md" -o -iname "*.jpg" -o -iname "*.png" -o -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.avi" -o -iname "*.mkv" -o -iname "*.mov" -o -iname "*.wav" -o -iname "*.flac" \) -exec rename 's/^(.*)$/disallowed-$1/' {} +

# Configure SSH server settings
sed -i '/^PermitRootLogin/c\PermitRootLogin no' /etc/ssh/sshd_config
sed -i '/^X11Forwarding/c\X11Forwarding no' /etc/ssh/sshd_config
echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config
echo 'LoginGraceTime 60' >> /etc/ssh/sshd_config
systemctl restart sshd

# Install and update antivirus software and run scans
apt-get install clamav clamav-daemon -y && freshclam
clamscan -r / --exclude-dir=/sys/

# Disable the Guest Account on Gnome
sed -i '/^AllowGuest/c\AllowGuest=false' /etc/gdm3/custom.conf
systemctl restart gdm

# Correct file permissions on important system files
chmod 600 /etc/passwd
chmod 600 /etc/shadow
chmod 600 /etc/group
chmod 600 /etc/gshadow
chmod -R 700 /etc/ssh

# Kernel level hardening
cat >> /etc/sysctl.conf << EOF
# Kernel level security enhancements
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.exec-shield = 1
kernel.dmesg_restrict = 1
EOF

# Apply sysctl changes without reboot
sysctl -p

# Set strong root password
# Note: Change 'Space!Beans5' to a strong password of your choice.
echo 'root:Space!Beans5' | chpasswd

# Install and run checks for rootkits and backdoors
apt-get update
apt-get install rkhunter chkrootkit -y
rkhunter --update
rkhunter --propupd
rkhunter --check
chkrootkit

# Look for Perl backdoors and suspicious Perl processes
find / -type f -name "*.pl"
ps aux | grep perl
netstat -tulpn | grep perl
# Manual checks with crontab for each user is advised.

# Update the Linux Kernel to the latest version available
apt install --only-upgrade linux-generic -y

# Ensure no unauthorized services are running
systemctl --type=service --state=active

# Install and configure AIDE (Advanced Intrusion Detection Environment)
apt-get install aide -y
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Configure AIDE to run daily
echo "0 3 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" | crontab -

# Disable unused filesystems
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

# Disable core dumps
echo '* hard core 0' >> /etc/security/limits.conf
echo 'fs.suid_dumpable = 0' >> /etc/sysctl.conf

# Disable USB storage for security
echo "install usb-storage /bin/true" >> /etc/modprobe.d/disable-usb-storage.conf

# Limiting access to su command
dpkg-statoverride --update --add root sudo 4750 /bin/su

# Harden network with iptables
# You might want to adjust the iptables rules according to your network needs
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -L -v

# Save iptables rules
iptables-save > /etc/iptables/rules.v4

# Ensure AppArmor is enabled and in enforce mode
apt-get install apparmor apparmor-utils -y
aa-enforce /etc/apparmor.d/*

# Disable compilers for unauthorized users
chmod 700 /usr/bin/gcc*
chmod 700 /usr/bin/cc
chmod 700 /usr/bin/g++*
chmod 700 /usr/bin/make

# Auditd installation and configuration
apt-get install auditd -y
# Add your specific audit rules to /etc/audit/audit.rules, then restart auditd

# Set secure boot loader permissions
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg

# Prevent IP spoofing
echo "nospoof on" >> /etc/host.conf

# Additional backdoor scanning with Lynis
apt-get install lynis -y
lynis audit system

# Enforce execution of Secure Boot
if [ -d /sys/firmware/efi ]; then
    echo "EFI Secure Boot enabled."
else
    echo "Warning: EFI Secure Boot is not enabled. It is recommended to enable it if possible."
fi

# Disable compilers for all users except root
for compiler in gcc cc g++ make; do
    chmod o-x /usr/bin/$compiler
done

# Configure audit rules for watching sensitive files' access and modification
auditctl -w /etc/passwd -p wa -k watch_passwd
auditctl -w /etc/shadow -p wa -k watch_shadow
auditctl -w /etc/group -p wa -k watch_group
auditctl -w /etc/gshadow -p wa -k watch_gshadow
auditctl -w /etc/sudoers -p wa -k watch_sudoers
auditctl -w /etc/ssh/sshd_config -p wa -k watch_sshdconfig

# Install and configure ModSecurity and ModEvasive for web server protection (if a web server is in use)
apt-get install libapache2-modsecurity libapache2-mod-evasive -y
a2enmod security2
a2enmod evasive

# Configure ModSecurity and ModEvasive (requires further tuning based on the web application)
# cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
# sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
# cp /etc/modsecurity/modsecurity.conf /etc/modsecurity/modsecurity.conf.bak

# Setup system accounting with acct
apt-get install acct -y
touch /var/log/wtmp /var/log/btmp
chown root:utmp /var/log/wtmp /var/log/btmp
chmod 664 /var/log/wtmp
chmod 600 /var/log/btmp

# Harden network with sysctl parameters
cat >> /etc/sysctl.conf << EOF
# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0 

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_all = 1
EOF

# Load new sysctl values
sysctl -p

# Ensure users can’t see processes that aren’t theirs
echo "proc    /proc    proc    defaults,hidepid=2    0    0" >> /etc/fstab

# Install and configure Tripwire
apt-get install tripwire -y
# The configuration of Tripwire requires interaction to generate local and site keys

# Restrict access to su by adding pam_wheel.so to /etc/pam.d/su
if ! grep -q "pam_wheel.so" /etc/pam.d/su; then
    echo "auth required pam_wheel.so" >> /etc/pam.d/su
fi

# Set immutable bit on critical files to prevent modification
chattr +i /etc/passwd
chattr +i /etc/shadow
chattr +i /etc/gshadow
chattr +i /etc/group

# Remove SUID/SGID from unauthorized files
find / -type f \( -perm -4000 -o -perm -2000 \) -exec chmod u-s,g-s {} +

# Set up Iptables rules to limit the rate of incoming connections
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT


echo "Script execution completed. Please check the output and logs for any issues or required manual actions. Reboot your system to apply all changes."

# Reboot system to apply all changes
# Comment out the following line if you want to manually reboot later
# reboot
