
# Stuff To Start Right Away, this is heavy and comment out Ansible code if points are removed that cant be restored
#=========================================================================================================
#=========================================================================================================
#=========================================================================================================
#=========================================================================================================
cd "$(dirname "$0")"

# disable sleeping
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target

# add ansible repo so we can use version 2.9+
add-apt-repository --yes --update ppa:ansible/ansible

# Install dependencies
apt install ansible git openssh-server systemd-timesyncd -y

# create config files
touch /etc/rsyslog.d/50-default.conf
touch /etc/ssh/sshd_config
mkdir /etc/ansible
cd /etc/ansible

#Ansible Code - Comment or delete out if needed
#=========================================================================================================

# set up configuration of roles
cat > /etc/ansible/requirements.yml << EOF
- src: https://github.com/florianutz/ubuntu2004_cis.git
EOF

# install all roles
ansible-galaxy install -p roles -r /etc/ansible/requirements.yml

# set up configuration of ansible
cat > /etc/ansible/harden.yml << EOF
- name: Harden Server
  hosts: localhost
  connection: local
  become: yes
  ignore_errors: yes
  roles:
    - ubuntu2004_cis
EOF

# start all scripts
ansible-playbook /etc/ansible/harden.yml

#=========================================================================================================

# re-install 'gdm3' ( Display manager for the linux its short form for GNOME Display Manager 3)
apt install gdm3 -y

# unlock main user
usermod -U $(whoami)

# set user password to root
usermod -p $(whoami) root
#=========================================================================================================
#=========================================================================================================
#=========================================================================================================
#=========================================================================================================


#Run a older script, its long and messy
bash WuTangClan.sh
