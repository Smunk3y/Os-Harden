if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

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
