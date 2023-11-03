#!/bin/bash

# Check if running as root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# Upgrade & Update
apt update && apt upgrade -y

# Install security updates
apt-get install unattended-upgrades -y && dpkg-reconfigure --priority=low unattended-upgrades

# Change password, remove unnecessary accounts, and add new user account if needed
# passwd [username]
# userdel [username]
# adduser [username]

# Update password requirements
nano /etc/security/pwquality.conf << EOF
minlen = 8
minclass = 3
minrepeat = 3
maxrepeat = 3
minsequence = 4
mincomplex = 2
maxconsecutive = 3
maxclassrepeat = 2
reject_username = true
gecoscheck = true
maxsequence = 3
maxempty = 3
dictcheck = 1
dictpath = /usr/share/dict/words
EOF

# Reload password service
systemctl restart systemd-logind

# Ensure pwquality is configured in pam
grep -qxF 'password requisite pam_pwquality.so retry=3' /etc/pam.d/common-password || echo 'password requisite pam_pwquality.so retry=3' >> /etc/pam.d/common-password

# Set password expiration
sed -i '/^PASS_MAX_DAYS/c\PASS_MAX_DAYS 90' /etc/login.defs
sed -i '/^PASS_MIN_DAYS/c\PASS_MIN_DAYS 7' /etc/login.defs
sed -i '/^PASS_WARN_AGE/c\PASS_WARN_AGE 14' /etc/login.defs

# Add brute force security
cat >> /etc/pam.d/common-auth << EOF
auth required pam_faillock.so preauth silent audit deny=5 unlock_time=1800
auth required pam_faillock.so authfail audit deny=5 unlock_time=1800
EOF

# Enable Firewall
ufw enable

# List user-installed programs and check for malicious ones
comm -23 <(apt-mark showmanual | sort -u) <(gzip -dc /var/log/installer/initial-status.gz | sed -n 's/^Package: //p' | sort -u)
# Manual inspection is required here

# Daily Update
(crontab -l ; echo "0 0 * * * apt update && apt upgrade -y") | crontab -

# Search for disallowed personal media and rename
find /home -type f \( -iname "*.txt" -o -iname "*.md" -o -iname "*.jpg" -o -iname "*.png" -o -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.avi" -o -iname "*.mkv" -o -iname "*.mov" -o -iname "*.wav" -o -iname "*.flac" \) -exec rename 's/^(.*)$/ww$1/' {} +

# SSH root login
sed -i '/^PermitRootLogin/c\PermitRootLogin no' /etc/ssh/sshd_config
sed -i '/^X11Forwarding/c\X11Forwarding no' /etc/ssh/sshd_config
systemctl restart sshd

# Install and update antivirus software
apt-get install clamav clamav-daemon -y && freshclam && clamscan -r /


# Disable Guest Account on Gnome
sed -i '/^AllowGuest/c\AllowGuest=false' /etc/gdm3/custom.conf
sed -i '/^AllowRoot/c\AllowRoot=false' /etc/gdm3/custom.conf
systemctl restart gdm


# Correct file permissions on important system files
chmod -R 444 /var/log
chmod 440 /etc/passwd
chmod 440 /etc/shadow
chmod 440 /etc/group
chmod -R 444 /etc/ssh

# Safer edits to /etc/sysctl.conf
cat >> /etc/sysctl.conf << EOF
# Security Enhancements
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=1
net.ipv4.conf.default.secure_redirects=1
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
EOF

# Apply sysctl changes
sysctl -p

# Make sure root password isn't blank
# Make sure root password isn't blank
echo 'root:Space!Beans5' | chpasswd

# Check For Backdoors
apt-get update
apt-get install rkhunter chkrootkit -y
rkhunter --update
freshclam
rkhunter --check
clamscan -r /
chkrootkit

# Additional checks for Perl backdoors
find / -type f -name "*.pl"
ps aux | grep perl
netstat -tulpn | grep perl
# crontab -u username -l (for each user)

# Update The Kernel
apt install linux-generic -y

echo "Script execution completed. Please check the output and logs for any issues or required manual actions.  PLEASE REBOOT QUICKLY"
