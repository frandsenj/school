#!/bin/bash
#script which installs and configures samba / nfs / apache / dns / ssh / postfix / ldap
#creates some web pages, user, mail accounts. basic stuff like that
#jason frandsen

#sets up samba and configures a read only public share
function setup_samba() {
yum install -y samba samba-client samba-common cifs-utils nfs-utils
systemctl start smb
systemctl enable smb
mkdir -p /srv/samba/public
chmod 777 -R /srv/samba/public
mv /etc/samba/smb.conf /etc/samba/smb.conf.backup
cat > /etc/samba/smb.conf << SAMBACONFIG
[global]
workgroup = WORKGROUP
security = user
passdb backend = tdbsam
map to guest = Never
netbios name = centosVM
[homes]
comment = Home Directories
valid users = %S, %D%w%S
browseable = No
read only = no
inherit acls = Yes
[public]
comment = public read only share
path = /srv/samba/public
public = yes
guest ok = yes
writable = no
SAMBACONFIG
read -p "SAMBA CONFIG: Enter the username to access share: " smbuser
smbpasswd -a $smbuser
cat > /srv/samba/public/readme.smb <<< "Jason Frandsen fran0558-srv.example20.lab"
}

#installs and configures ldap. adds a DIT with container and hosts
function setup_ldap() {
yum install -y openldap-clients openldap-servers
read -p "Enter the LDAP organization name: " ldaporg
read -p "Enter the container name: " ldapcont
read -p "Enter the name: " ldapname
ldapfirst=$(awk -F '.' '{print $1}' <<< $ldaporg)
ldaplast=$(awk -F '.' '{print $2}' <<< $ldaporg)
mkdir -p /var/lib/ldap/$ldaporg
chown ldap:ldap /var/lib/ldap/$ldaporg
cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/$ldaporg/DB_CONFIG
chown ldap:root /var/lib/ldap/$ldaporg/DB_CONFIG
mv /etc/openldap/slapd.d /etc/openldap/slapd.d.backup
cat > /etc/openldap/slapd.conf << SLAPCONFIG
### Global Section ###
include "/etc/openldap/schema/core.schema"
include "/etc/openldap/schema/cosine.schema"
include "/etc/openldap/schema/inetorgperson.schema"
include "/etc/openldap/schema/nis.schema"
pidfile "/var/run/openldap/slapd.pid"
loglevel "256"
#### Database section ####
database "bdb"
suffix "dc=$ldapfirst,dc=$ldaplast"
directory "/var/lib/ldap/$ldaporg"
rootdn "cn=ldapadm,dc=$ldapfirst,dc=$ldaplast"
rootpw "secret"
SLAPCONFIG
chmod 770 /etc/openldap/slapd.conf
chown root:ldap /etc/openldap/slapd.conf
slaptest -u
systemctl start slapd
systemctl enable slapd
cat >> /etc/openldap/ldap.conf << LDAPCONFIG
BASE dc=$ldapfirst,dc=$ldaplast
URI ldap://172.16.30.20 ldap://127.0.0.1
LDAPCONFIG
mkdir -p /etc/openldap/ldif.$ldapfirst
cat > /etc/openldap/ldif.$ldapfirst/base.ldif << LDAPCONFIG
dn: dc=$ldapfirst,dc=$ldaplast
objectclass: domain
LDAPCONFIG
cat > /etc/openldap/ldif.$ldapfirst/ou.ldif << LDAPCONFIG
dn: ou=$ldapcont,dc=$ldapfirst,dc=$ldaplast
objectClass: organizationalUnit
ou: $ldapcont
description: $ldapcont OU
LDAPCONFIG
ldap_cn=$(awk -F ' ' '{print $1}' <<< $ldapname)
ldap_sn=$(awk -F ' ' '{print $2}' <<< $ldapname)
useradd $ldap_cn$ldap_sn
cat > /etc/openldap/ldif.$ldapfirst/accounts.ldif << LDAPCONFIG
dn: uid=$ldap_cn$ldap_sn,ou=$ldapcont,dc=$ldapfirst,dc=$ldaplast
objectclass: inetOrgPerson
objectclass: posixAccount
cn: $ldap_cn
sn: $ldap_sn
uid: $ldap_cn$ldap_sn
uidNumber: 1001
gidNumber: 1000
homeDirectory: /home/$ldap_cn$ldap_sn
loginShell: /bin/bash
mail: $ldap_cn$ldap_sn@example.lab
userPassword:
LDAPCONFIG
#cat > /etc/openldap/ldif.$ldapfirst/groups.ldif << LDAPCONFIG
#dn: cn=users,ou=groups,dc=$ldapfirst,dc=$ldaplast
#objectClass: posixGroup
#cn: users
#gidNumber: 1000
#memberUid: $ldap_cn$ldap_sn
#LDAPCONFIG
cat > /etc/openldap/ldif.$ldapfirst/hosts.ldif << LDAPCONFIG
dn: ou=hosts,dc=$ldapfirst,dc=$ldaplast
objectClass: organizationalUnit
ou: hosts

dn: cn=www.$ldaporg+ipHostNumber=172.16.32.20,ou=hosts,dc=$ldapfirst,dc=$ldaplast
objectClass: ipHost
objectClass: device
ipHostNumber: 172.16.32.20
cn: www.$ldaporg
description: the $ldapfirst server
LDAPCONFIG
ldapadd -x -D "cn=ldapadm,dc=$ldapfirst,dc=$ldaplast" -w secret -f /etc/openldap/ldif.$ldapfirst/base.ldif
ldapadd -x -D "cn=ldapadm,dc=$ldapfirst,dc=$ldaplast" -w secret -f /etc/openldap/ldif.$ldapfirst/ou.ldif
ldapadd -x -D "cn=ldapadm,dc=$ldapfirst,dc=$ldaplast" -w secret -f /etc/openldap/ldif.$ldapfirst/accounts.ldif
#ldapadd -x -D "cn=ldapadm,dc=$ldapfirst,dc=$ldaplast" -w secret -f /etc/openldap/ldif.$ldapfirst/groups.ldif
ldapadd -x -D "cn=ldapadm,dc=$ldapfirst,dc=$ldaplast" -r -w secret -f /etc/openldap/ldif.$ldapfirst/hosts.ldif
}

#installs postfix and does a basic configuration
function setup_postfix() {
yum install -y postfix telnet
cp /etc/postfix/main.cf /etc/postfix/main.cf.backup
read -p "What is the postfix domain?: " postfixdomain
read -p "What is the alias? " aliasname
read -p "Who is this alias for? " aliauser
sed -i "s/#myhostname = host.domain.tld/myhostname = mail.$postfixdomain/g" /etc/postfix/main.cf
sed -i "s/#mydomain = domain.tld/mydomain = $postfixdomain/g" /etc/postfix/main.cf
sed -i 's/inet_interfaces = localhost/inet_interfaces = all/g' /etc/postfix/main.cf
sed -i 's/mydestination = $myhostname, localhost.$mydomain, localhost/#mydestination = $myhostname, localhost.$mydomain, localhost/g' /etc/postfix/main.cf
sed -i 's/#mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain/mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain/g' /etc/postfix/main.cf
sed -i 's/#mynetworks = 168.100.189.0\/28, 127.0.0.0\/8/mynetworks = 172.16.0.0\/16, 127.0.0.0\/8/g' /etc/postfix/main.cf
sed -i 's/#home_mailbox = Maildir\//home_mailbox = Maildir\//g' /etc/postfix/main.cf
cat >> /etc/postfix/main.cf <<< "masquerade_domains = $postfixdomain"
systemctl start postfix
systemctl enable postfix
systemctl status postfix
sudo sed -i "/support:        postmaster/a $aliasname:        $aliasuser" /etc/aliases
postalias /etc/aliases
}

function setup_dns() {
yum install -y openssh openssh-server bind bind-utils bind-libs iptables iptables-services
systemctl stop firewalld
setenforce 0
clear
echo "DNS CONFIG"
read -p "Enter the name of the server (ie: dns1, ns1): " nameserv
read -p "Enter the name of the domain you are creating (ie: happy.lab): " userzone
read -p "Enter the ip of the nameserver: " ipadd
echo "Generating foward zone named: fwd.$userzone"
cat > /var/named/fwd.$userzone << FWDZONE
\$TTL 86400
@    IN    SOA    $nameserv.$userzone. dnsadm.$userzone. (
                                  0      ; serial
                                  1D     ; refresh
                                  1H     ; retry
                                  1W     ; expire
                                  3H )   ; minimum
@   IN   NS   $nameserv.$userzone.
@   IN   NS   dns2.$userzone.
@   IN   MX   10    mail.example.lab.
$nameserv IN   A    $ipadd
dns2    IN    A    $ipadd
mail    IN    A    $ipadd
www1    IN    A    $ipadd
www2    IN    A    $ipadd
secure   IN   A    172.16.32.20
FWDZONE
echo
ipadd_rvs=$(awk -F '.' '{print $4"."$3}' <<< $ipadd)
ipadd_first=$(awk -F '.' '{print $2"."$1}' <<< $ipadd)
echo "Generating reverse zone named: rvs.$userzone"
cat > /var/named/rvs.$userzone << RVSZONE
\$TTL 86400
@    IN    SOA    $nameserv.$userzone. dnsadm.$userzone. (
                                  0      ; serial
                                  1D     ; refresh
                                  1H     ; retry
                                  1W     ; expire
                                  3H )   ; minimum
@   IN   NS   $nameserv.$userzone.
@   IN   NS   dns2.$userzone.
$ipadd_rvs   IN   PTR   $nameserv.$userzone.
$ipadd_rvs   IN   PTR   dns2.$userzone.
20.30    IN    PTR   www1.$userzone.
20.30    IN    PTR   www2.$userzone.
20.32    IN    PTR   secure.$userzone.
RVSZONE
chown root:named /var/named/fwd.$userzone
chown root:named /var/named/fwd.$userzone
echo "Checking forward zone file..."
named-checkzone forward /var/named/fwd.$userzone
echo "Checking reverse zone file..."
named-checkzone reverse /var/named/rvs.$userzone
echo "Adding zone entry to named.conf..."
cat >> /etc/named.conf << ADDZONE
zone "$userzone" IN {
    type master;
    file "fwd.$userzone";
    allow-update { none; };
    allow-transfer { 172.16.31.20; };
};
zone "$ipadd_first.in-addr.arpa" IN {
    type master;
    file "rvs.$userzone";
    allow-update { none; };
    allow-transfer { 172.16.31.20; };
};
ADDZONE
echo "Verifying /etc/named.conf..."
named-checkconf -z
#read -p "Enter the ip address for the recursive nameserver: " ipadd
echo "Configuring /etc/named.conf..."
first2=$(awk -F '.' '{print $1"."$2}' <<< $ipadd)
sudo sed -i 's/listen-on port 53 { 127.0.0.1; };/listen-on port 53 { 127.0.0.1; '"$ipadd"'; };/g' /etc/named.conf
sudo sed -i '/allow-query     { localhost; };/a \        allow-recursion { '"$first2"'.0.0\/16; };' /etc/named.conf
sudo sed -i 's/allow-query\     { localhost; };/allow-query\     { localhost; '"$first2"'.0.0\/16; };/g' /etc/named.conf
echo "Verifying /etc/named.conf..."
named-checkconf -z
echo "This machine is now configured for Master/Slave DNS and as a recursive nameserver."
}


function dns_slave() {
clear
read -p "What is the name of the zone? " ZONESLAV
read -p "What is the ip address of the master initiating the zone transfer? " IPMAST
IPRVS=$(awk -F '.' '{print $2"."$1}' <<< $IPMAST)
cat >> /etc/named.conf << ADDZONE
        zone "$ZONESLAV" IN {
        type slave;
        file "slaves/fwd.$ZONESLAV";
        masters { $IPMAST; };
};
       zone "$IPRVS.in-addr.arpa" IN {
       type slave;
       file "slaves/rvs.$ZONESLAV";
       masters { $IPMAST; };
};
ADDZONE
echo "Fwd/rvs entries for slave zone added to /etc/named.conf"
echo "Verifying named.conf..."
named-checkconf -z
}

function install_packages() {
yum install -y openssh openssh-server bind bind-utils bind-libs iptables iptables-services postfix cifs-utils nfs-utils
setenforce 0
systemctl stop firewalld
read -p "Enter the username being used for the sba: " sbauser
read -p "Enter the password for the user: " sbauserpwd
useradd $sbauser
useradd cst8246
echo "$sbauserpwd" | passwd --stdin $sbauser
echo "cst8246" | passwd --stdin cst8246
firewall-cmd --zone=public --add-service=ssh --permanent
firewall-cmd --reload
}

function new_apache() {
yum install -y httpd mod_ssl
systemctl start httpd
systemctl enable httpd
read -p "APACHE CONFIG: What is the domain name being used? (ie green, blue): " apachedomain
mv /etc/httpd/conf/httpd.conf /etc/httpd/conf/httpd.conf.backup
cat > /etc/httpd/conf/httpd.conf << APACHECONFIG
ServerName fran0558-srv.example20.lab
ServerRoot /etc/httpd
User apache
Group apache
Listen 172.16.30.20:80
Listen 172.16.32.20:443
ServerAdmin webmaster@example23.lab
DocumentRoot /var/www/html
ErrorLog logs/error_log
LogLevel info
TransferLog logs/access_log
TypesConfig /etc/mime.types
DirectoryIndex index.php index.html

Include conf.modules.d/*.conf
EnableSendfile on
IncludeOptional conf.d/*.conf

LoadModule mpm_prefork_module    modules/mod_mpm_prefork.so
LoadModule unixd_module    modules/mod_unixd.so
LoadModule systemd_module    modules/mod_systemd.so
LoadModule log_config_module    modules/mod_log_config.so
Transferlog logs/access_log
LoadModule mime_module    modules/mod_mime.so
TypesConfig /etc/mime.types
LoadModule authz_core_module    modules/mod_authz_core.so
LoadModule dir_module    modules/mod_dir.so
LoadModule ssl_module    modules/mod_ssl.so

<Directory />
    AllowOverride none
    Require all denied
</Directory>

<Directory "/var/www">
    AllowOverride None
    Require all granted
</Directory>

<Directory "/var/www/html">
    Options Indexes FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>

<IfModule dir_module>
    DirectoryIndex index.html
</IfModule>

<Files ".ht*">
    Require all denied
</Files>

<IfModule log_config_module>
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
    LogFormat "%h %l %u %t \"%r\" %>s %b" common

    <IfModule logio_module>
      LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %I %O" combinedio
    </IfModule>

    CustomLog "logs/access_log" combined
</IfModule>

<IfModule alias_module>
    ScriptAlias /cgi-bin/ "/var/www/cgi-bin/"

</IfModule>

<Directory "/var/www/cgi-bin">
    AllowOverride None
    Options None
    Require all granted
</Directory>

<IfModule mime_module>
    TypesConfig /etc/mime.types

    AddType application/x-compress .Z
    AddType application/x-gzip .gz .tgz

    AddType text/html .shtml
    AddOutputFilter INCLUDES .shtml
</IfModule>

AddDefaultCharset UTF-8

<IfModule mime_magic_module>
    MIMEMagicFile conf/magic
</IfModule>

<VirtualHost 172.16.30.20:80>
DocumentRoot /var/www/html/
ServerName 172.16.30.20
</VirtualHost>

<VirtualHost 172.16.30.20:80>
ServerAdmin root@fran0558-srv.$apachedomain.lab
DocumentRoot /var/www/vhosts/www1.$apachedomain.lab/html
ServerName www1.$apachedomain.lab
Errorlog /var/www/vhosts/www1.$apachedomain.lab/logs/error_log
Transferlog /var/www/vhosts/www1.$apachedomain.lab/logs/access_log
</VirtualHost>

<VirtualHost 172.16.30.20:80>
ServerAdmin root@fran0558-srv.example20.lab
DocumentRoot /var/www/vhosts/www2.$apachedomain.lab/html
ServerName www2.$apachedomain.lab
ErrorLog /var/www/vhosts/www2.$apachedomain.lab/logs/error_log
TransferLog /var/www/vhosts/www2.$apachedomain.lab/logs/access_log
</VirtualHost>

<VirtualHost 172.16.32.20:443>
ServerAdmin root@fran0558-srv.example20.lab
DocumentRoot /var/www/vhosts/secure.$apachedomain.lab/html
ServerName secure.$apachedomain.lab
ErrorLog /var/www/vhosts/secure.$apachedomain.lab/logs/error_log
TransferLog /var/www/vhosts/secure.$apachedomain.lab/logs/access_log
SSLCertificateFile /etc/httpd/tsl/cert/example20.cert
SSLCertificateKeyFile /etc/httpd/tsl/key/example20.key
SSLEngine On
</VirtualHost>
APACHECONFIG
mkdir -p /var/www/html
cat > /var/www/html/index.html << APACHECONFIG
<head><title>The default page for 172.16.30.20</title></head>
<h2>Magic Number 20</h2>
<h1>172.16.30.20</h1>
APACHECONFIG
mkdir -p /var/www/vhosts/www1.$apachedomain.lab/{html,logs}
mkdir -p /var/www/vhosts/www2.$apachedomain.lab/{html,logs}
mkdir -p /var/www/vhosts/secure.$apachedomain.lab/{html,logs}
mkdir -p /etc/httpd/tsl/key
mkdir -p /etc/httpd/tsl/cert
chmod 700 /etc/httpd/tsl/key
chmod 755 /etc/httpd/tsl/cert
openssl req -x509 -newkey rsa -days 120 -nodes -keyout /etc/httpd/tsl/key/example20.key -out /etc/httpd/tsl/cert/example20.cert
chmod 600 /etc/httpd/tsl/key/example20.key
chown root:apache /etc/httpd/tsl/key/example20.key
chmod 644 /etc/httpd/tsl/cert/example20.cert
chown root:apache /etc/httpd/tsl/cert/example20.cert
sed -i 's/Listen 443 https/#Listen 443 https/g' /etc/httpd/conf.d/ssl.conf
cat > /var/www/vhosts/www1.$apachedomain.lab/html/index.html << APACHECONFIG
<head><title>The default page for 172.16.30.20</title></head>
<h2>Magic Number 20</h2>
<h1>www1.$apachedomain.lab 172.16.30.20</h1>
APACHECONFIG
cat > /var/www/vhosts/www2.$apachedomain.lab/html/index.html << APACHECONFIG
<head><title>The default page for 172.16.30.20</title></head>
<h2>Magic Number 20</h2>
<h1>www2.$apachedomain.lab 172.16.30.2</h1>
APACHECONFIG
cat > /var/www/vhosts/secure.$apachedomain.lab/html/index.html << APACHECONFIG
<head><title>The default page for 172.16.32.20</title></head>
<h2>Magic Number 20</h2>
<h1>secure.$apachedomain.lab 172.16.30.20</h1>
APACHECONFIG
systemctl restart httpd
}


function create_virtualhost() {
read -p "Enter vhost name (ie www.asdf.com): " vhostname
read -p "Enter ip for vhost: " vhostip
read -p "Enter text for default page: " vhostdefault
read -p "Is this a secure site? (yes/no) " secvhost
mkdir -p /var/www/vhosts/$vhostname/html
mkdir -p /var/www/vhosts/$vhostname/logs
cat > /var/www/vhosts/$vhostname/html/index.html << APACHECONFIG
<head><title>The default page for $vhostname</title></head>
<h2>MAGIC NUMBER</h2>
<h2>$vhostdefault</h2>
<h1>$vhostname</h1>
<h1>$vhostip</h1>
APACHECONFIG
if [ $secvhost = "no" ]; then
    cat >> /etc/httpd/conf/httpd.conf << APACHECONFIG
<VirtualHost $vhostip:80>
    ServerName $vhostname
    DocumentRoot /var/www/vhosts/$vhostname/html
    ErrorLog /var/www/vhosts/$vhostname/logs/error.log
</VirtualHost>
APACHECONFIG
else
    mkdir -p /etc/httpd/tsl/key
    mkdir -p /etc/httpd/tsl/cert
    chmod 700 /etc/httpd/tsl/key
    chmod 755 /etc/httpd/tsl/cert
    openssl req -x509 -newkey rsa -days 120 -nodes -keyout /etc/httpd/tsl/key/example20.key -out /etc/httpd/tsl/cert/example20.cert
    chmod 600 /etc/httpd/tsl/key/example20.key
    chmod 644 /etc/httpd/tsl/cert/example20.cert
cat >> /etc/httpd/conf/httpd.conf << APACHECONFIG
<VirtualHost $vhostip:443>
    ServerName $vhostname
    DocumentRoot /var/www/vhosts/$vhostname/html
    ErrorLog /var/www/vhosts/$vhostname/logs/error.log
    SSLCertificateFile /etc/httpd/tsl/cert/example20.cert
    SSLCertificateKeyFile /etc/httpd/tsl/key/example20.key
</VirtualHost>
APACHECONFIG
fi
}

function setup_nfs() {
yum install -y cifs-utils nfs-utils
mkdir -p /srv/nfs/share
mkdir -p /srv/nfs/download
chmod 777 -R /srv/nfs/share
cat >> /etc/exports << EXPORTS
/srv/nfs/share *(rw)
/srv/nfs/download *(ro)
EXPORTS
cat > /srv/nfs/download/sba.nfs <<< "Jason Frandsen MN 20"
cat >> /srv/nfs/share/readme.nfs <<< "Jason Frandsen MN 20"
systemctl start nfs
systemctl enable nfs
showmount -e
exportfs -v
}

function client_nfs_config() {
yum install -y cifs-utils nfs-utils
read -p "Enter the ip address for the NFS share: " nfsipadd
mkdir -p $nfsclientdir
showmount -e $nfsipadd
read -p "Enter the NFS share path you would like to mount: " nfsdir
read -p "Enter the directory to mount share on: " nfsclientdir
mount $nfsipadd:$nfsdir $nfsclientdir
mount | grep "type nfs"
df -h
}


function create_samba_share() {
read -p "Read only share? Enter yes/no " readonly
if [ $readonly = "no" ]; then
    readwrite="yes"
else
    readwrite="no"
fi
read -p "Enter the share name: " sambaname
read -p "Enter the directory which will be shared: " sambadir
read -p "Enter a comment: " sambacomment
mkdir -p $sambadir
chmod 777 -R $sambadir
cat >> /etc/samba/smb.conf << SAMBACONFIG
[$sambaname]
comment = $sambacomment
path = $sambadir
public = yes
guest ok = yes
read only = $readonly
writable = $readwrite
SAMBACONFIG
cat > $sambadir/readme.smb <<< "Jason Frandsen fran0558-srv.example20.lab"
}

function client_samba_config() {
yum install -y cifs-utils
read -p "Enter the username to connect as: " usernam
read -p "Enter the password: " passw
read -p "Enter the ip address: " ipadd
read -p "Enter the named of the shared folder: " sambashare
read -p "Enter the directory to mount samba share on: " sambadir
mkdir -p $sambadir
sudo mount -t cifs -o user=$usernam,pass=$passw //$ipadd/$sambashare $sambadir
ls -la /TestMount/samba
}


function cont() {
read -p "Press any key to continue" -n1
clear
}


#generates a public/private keypair
function ssh_keygen() {
clear
echo "Generating a new key for SSH"
echo "Reminder: ssh key will be for the current user running this script...root is a user!"
cont
echo "Generating keypair"
ssh-keygen -t rsa
cont
}

function enable_disable() {
read -sp "Enable this option? y/n " -n1 CONF
if  [ "$CONF" == "y" ] || [ $CONF == "Y" ]; then
    userchoice='yes'
else
    userchoice='no'
fi
}

#adds a user to sshd_config
function ssh_usracct() {
read -p "Enter the username: " NEWUSER
sudo cat >> /etc/ssh/sshd_config <<< "AllowUsers $NEWUSER"
echo "$NEWUSER added"
cont
}

#configures sshd_configure to allow/deny root login
function ssh_rootlogin() {
sudo sed -i 's/#PermitRootLogin/PermitRootLogin/g' /etc/ssh/sshd_config 2>/dev/null
enable_disable
if [ $userchoice = 'yes' ]; then
    sudo sed -i 's/PermitRootLogin no/PermitRootLogin yes/g' /etc/ssh/sshd_config 2>/dev/null
else
    sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config 2>/dev/null
fi
}

#configures sshd_config to allow/deny pubkey authentication
function ssh_pubkeyauth() {
sudo sed -i 's/#PubkeyAuthentication/PubkeyAuthentication/g' /etc/ssh/sshd_config 2>/dev/null
enable_disable
if [ $userchoice = 'yes' ]; then
    sudo sed -i 's/PubkeyAuthentication no/PubkeyAuthentication yes/g' /etc/ssh/sshd_config 2>/dev/null
else
    sudo sed -i 's/PubkeyAuthentication yes/PubkeyAuthentication no/g' /etc/ssh/sshd_config 2>/dev/null
fi
}

#configure sshd_config to allow/deny password auth
function ssh_passwdauth() {
sudo sed -i 's/#PasswordAuthentication/PasswordAuthentication/g' /etc/ssh/sshd_config 2>/dev/null
enable_disable
if [ $userchoice = 'yes' ]; then
    sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config 2>/dev/null
else
    sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config 2>/dev/null
fi
}

function get_sshcreds() {
read -p "Enter the username for the remote terminal: " SSHUSER
read -p "Enter the ip address for the remote terminal: " SSHIP
}

#used to get status of different fields in sshd_config
function get_remote() {
clear
get_sshcreds
ssh -tt $SSHUSER@$SSHIP "sudo grep -E '^PermitRootLogin|^PasswordAuthentication|^AllowUsers|^PubkeyAuthentication' /etc/ssh/sshd_config"
cont
}

#transfers public key to a destination
function ssh_keytransfer() {
get_sshcreds
echo
echo "Transferring public key to $SSHIP"
cat ~/.ssh/id_rsa.pub | ssh $SSHUSER@$SSHIP "mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && chmod -R go= ~/.ssh && cat >> ~/.ssh/authorized_keys"
echo "Key transferred"
cont
}


#clears the ~/.ssh directory
function clear_ssh() {
clear
echo "Are you sure you wish to clear the .ssh directory? y/n"
read -sp "" -n1 CONF
if  [ "$CONF" == "y" ] || [ $CONF == "Y" ]; then
    rm ~/.ssh/* 2>/dev/null
    echo ""
    echo ".ssh directory was cleared!"
    echo ""
else
    echo ""
    echo ".ssh directory was NOT cleared!"
    echo ""
fi
cont
}

function config_ssh() {
while [ true ] ; do
clear
cat << MENU
************************************************
*            MODIFY LOCAL SSH CONFIG           *
************************************************
******* CURRENT LOCAL SSHD_CONFIG STATUS *******
$(sudo grep -E '^PermitRootLogin|^PasswordAuthentication|^AllowUsers|^PubkeyAuthentication' /etc/ssh/sshd_config)
************************************************
* (1) Allow user account access                *
* (2) Permit root login                        *
* (3) Enable/disable password authentication   *
* (4) Enable/disable PubkeyAuthentication      *
* (5) Generate ssh key
* (6) Transfer ssh key                         *
* (Q/q) Quit                                   *
************************************************
MENU
read -sp "" -n1 ANS
    case $ANS in
        1)
            ssh_usracct
            ;;
        2)
            ssh_rootlogin
            ;;
        3)
            ssh_passwdauth
            ;;
        4)
            ssh_pubkeyauth
            ;;
        5)
            ssh_keygen
            ;;
        6)
            ssh_keytransfer
            ;;

        Q|q)
            break
    esac
done
}

function sba_config(){
sed -i 's/nameserver 192.168.133.2/nameserver 172.16.30.20/g' /etc/resolv.conf
sudo sed -i 's/PermitRootLogin no/PermitRootLogin yes/g' /etc/ssh/sshd_config
iptables -F
iptables -A INPUT -s 172.16.30.0/16 -p tcp --dport 22 -j ACCEPT
systemctl restart named
}

function sbahelper_help() {
echo "Here are some command examples:"
echo "setup samba"
echo "setup postfix"
echo "setup apache"
echo "create samba_share"
echo "create nfs_share"
echo "create virtualhost"
}

if [ -z $1 ]; then
    echo "You must provide a command!"
else
    action=$1
    service=$2
    case "${action}_${service}" in
        setup_samba) setup_samba ;;
        setup_postfix) setup_postfix ;;
        setup_nfs) setup_nfs ;;
        setup_dns) setup_dns ;;
        dns_slave) dns_slave ;;
        create_samba) create_samba_share ;;
        create_nfs) create_nfs_share ;;
        install_packages) install_packages ;;
        setup_apache) new_apache ;;
        create_virtualhost) create_virtualhost ;;
        client_samba) client_samba_config ;;
        client_nfs) client_nfs_config ;;
        show_help) sbahelper_help ;;
        config_ssh) config_ssh ;;
        ssh_keygen) ssh_keygen ;;
        setup_ldap) setup_ldap ;;
        setup_all) install_packages
                   new_apache
                   setup_dns
                   setup_postfix
                   setup_ldap
                   setup_samba
                   setup_nfs
                   sba_config
                   config_ssh ;;
        *) echo "Invalid input. Type show help for proper syntax" ;;
    esac
fi
