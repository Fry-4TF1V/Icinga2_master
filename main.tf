provider "ovh" {
  # Configuration options
  endpoint = "ovh-eu"
  application_key    = var.ovh_application_key
  application_secret = var.ovh_application_secret
  consumer_key       = var.ovh_consumer_key
}

# Import SSH Public Key
resource openstack_compute_keypair_v2 keypair {
  name       = var.keypair_name
  public_key = file(var.public_key)
  region     = var.ovh_region
}

# Define a Security group for this project
resource openstack_networking_secgroup_v2 secgroup {
  name        = "Icinga2_secgroup"
  description = "Security group for Icinga2"
  region      = var.ovh_region
}

# Define an Ingress policy for https
resource openstack_networking_secgroup_rule_v2 ingress_https {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = "0.0.0.0/0"
  region            = var.ovh_region
  security_group_id = openstack_networking_secgroup_v2.secgroup.id
}

# Define an Ingress policy for http
resource openstack_networking_secgroup_rule_v2 ingress_http {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 80
  port_range_max    = 80
  remote_ip_prefix  = "0.0.0.0/0"
  region            = var.ovh_region
  security_group_id = openstack_networking_secgroup_v2.secgroup.id
}

# Define an Ingress policy for ssh
resource openstack_networking_secgroup_rule_v2 ingress_ssh {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "0.0.0.0/0"
  region            = var.ovh_region
  security_group_id = openstack_networking_secgroup_v2.secgroup.id
}

# Define an Ingress policy for icinga_agents
resource openstack_networking_secgroup_rule_v2 ingress_agents {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 5665
  port_range_max    = 5665
  remote_ip_prefix  = "0.0.0.0/0"
  region            = var.ovh_region
  security_group_id = openstack_networking_secgroup_v2.secgroup.id
}

# Get Ext-Net network ID
data openstack_networking_network_v2 network_ext_net {
  name   = "Ext-Net"
  region = var.ovh_region
}

# Create Ext-Net network port
resource openstack_networking_port_v2 server_port {
  name                = "Icinga2_server_port"
  network_id          = data.openstack_networking_network_v2.network_ext_net.id
  admin_state_up      = "true"
  region              = var.ovh_region
  security_group_ids  = [openstack_networking_secgroup_v2.secgroup.id]
}

locals {
  # Retreive IP v4 of the created port
  ipv4 = [
    for ip in openstack_networking_port_v2.server_port.all_fixed_ips :
      ip
      if length(replace(ip, "/[[:alnum:]]+:[^,]+/", "")) > 0
    ][0]

  # Retreive IP v6 of the created port
  ipv6 = [
    for ip in openstack_networking_port_v2.server_port.all_fixed_ips :
      ip
      if length(replace(ip, "/[[:alnum:]]+\\.[^,]+/", "")) > 0
    ][0]
}

# Create an A (ipv4) record inside the DNS zone
resource ovh_domain_zone_record server_record_A {
  zone = var.dns_domain
  subdomain = var.fqdn
  fieldtype = "A"
  ttl = "60"
  target = local.ipv4
}

# Create an A (ipv4) record inside the DNS zone for WWW
resource ovh_domain_zone_record server_record_A_www {
  zone = var.dns_domain
  subdomain = "www.${var.fqdn}"
  fieldtype = "A"
  ttl = "60"
  target = local.ipv4
}

# Create an AAAA (ipv6) record inside the DNS zone
resource ovh_domain_zone_record server_record_AAAA {
  zone = var.dns_domain
  subdomain = var.fqdn
  fieldtype = "AAAA"
  ttl = "60"
  target = local.ipv6
}

# Create an AAAA (ipv6) record inside the DNS zone for WWW
resource ovh_domain_zone_record server_record_AAAA_www {
  zone = var.dns_domain
  subdomain = "www.${var.fqdn}"
  fieldtype = "AAAA"
  ttl = "60"
  target = local.ipv6
}

# Create a Icinga2 server on PCI
resource openstack_compute_instance_v2 server {
  count            = 1
  region           = var.ovh_region
  name             = "icinga2"
  image_name       = var.image
  flavor_name      = var.flavor
  key_pair         = var.keypair_name
  network {
    port           = openstack_networking_port_v2.server_port.id
    access_network = true
  }

  depends_on = [
    openstack_compute_keypair_v2.keypair,
    ovh_domain_zone_record.server_record_A,
    ovh_domain_zone_record.server_record_A_www,
    ovh_domain_zone_record.server_record_AAAA,
    ovh_domain_zone_record.server_record_AAAA_www,
    openstack_networking_secgroup_rule_v2.ingress_ssh,
    openstack_networking_secgroup_rule_v2.ingress_http,
    openstack_networking_secgroup_rule_v2.ingress_https,
    openstack_networking_secgroup_rule_v2.ingress_agents,
  ]
}

# Run the Icinga2 "master" install script inside the instance
resource null_resource install_icinga2 {
  triggers = {
     server_id =  openstack_compute_instance_v2.server[0].id
  }

  provisioner "remote-exec" {
    connection {
      type     = "ssh"
      user     = "debian"
      host     =  openstack_compute_instance_v2.server[0].access_ip_v4
    }

    inline = [
      # Set hostname
      "sudo hostnamectl set-hostname ${var.fqdn}.${var.dns_domain}",
      # Update distribution
      "sudo apt-get -y update && sudo apt-get -y upgrade",
      # Install GIT as requirement
      "sudo apt-get install -y git",

      ### Install Icinga2
      # Install required packages
      "sudo apt-get -y install apt-transport-https wget gnupg",
      # Install required repository key
      "sudo wget -O - https://packages.icinga.com/icinga.key | sudo apt-key add -",
      # Install required repository

      # DEBIAN
      "sudo DIST=$(awk -F\"[)(]+\" '/VERSION=/ {print $2}' /etc/os-release); echo \"deb https://packages.icinga.com/debian icinga-$${DIST} main\" > /etc/apt/sources.list.d/$${DIST}-icinga.list",
      "sudo echo \"deb-src https://packages.icinga.com/debian icinga-$${DIST} main\" >> /etc/apt/sources.list.d/$${DIST}-icinga.list",
      # UBUNTU
      # "sudo . /etc/os-release; if [ ! -z $${UBUNTU_CODENAME+x} ]; then DIST=\"$${UBUNTU_CODENAME}\"; else DIST=\"$(lsb_release -cs)\"; fi; echo \"deb https://packages.icinga.com/ubuntu icinga-$${DIST} main\" | sudo tee -a /etc/apt/sources.list.d/$${DIST}-icinga.list > /dev/null",
      # "sudo . /etc/os-release; if [ ! -z $${UBUNTU_CODENAME+x} ]; then DIST=\"$${UBUNTU_CODENAME}\"; else DIST=\"$(lsb_release -cs)\"; fi; echo \"deb-src https://packages.icinga.com/ubuntu icinga-$${DIST} main\" | sudo tee -a /etc/apt/sources.list.d/$${DIST}-icinga.list > /dev/null",

      # Install icinga2
      "sudo apt-get -y update && sudo apt-get install -y icinga2",
      # Install additional monitoring plugins for Icinga2
      "sudo apt-get install -y monitoring-plugins",
      # Start Icinga2
      "sudo systemctl enable icinga2 && sudo systemctl restart icinga2",
    ]
  }
}

# Run the Icingaweb2 install script inside the instance
resource null_resource install_icingaweb2 {
  triggers = {
      id = null_resource.install_icinga2.id
  }

  provisioner "remote-exec" {
    connection {
      type     = "ssh"
      user     = "debian"
      host     =  openstack_compute_instance_v2.server[0].access_ip_v4
    }

    inline = [

      ### Install Icingaweb2
      # Install MariaDB
      "sudo apt-get install -y mariadb-server mariadb-client",
      # Install Icinga2 IDO for Mariadb
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -yq install icinga2-ido-mysql",
      # Secure Mysql access
      "sudo mysql -e \"SET PASSWORD FOR root@localhost = PASSWORD('${var.mariadb_root_pwd}');FLUSH PRIVILEGES;\"",
      # Redefine Mysql Icinga2 password
      "sudo mysql -p'${var.mariadb_root_pwd}' -e \"SET PASSWORD FOR icinga2@localhost = PASSWORD('${var.mariadb_icinga2_pwd}');FLUSH PRIVILEGES;\"",
      # Change password for IDO feature in conf file to match previous step
      "sudo sed -i 's/password = .*/password = \"${var.mariadb_icinga2_pwd}\",/g' /etc/icinga2/features-available/ido-mysql.conf",
      # Activate Icinga2 IDO for Mysql/MariaDB
      "sudo icinga2 feature enable ido-mysql && sudo systemctl restart icinga2",
      # Create database for IcingaWeb2
      "sudo mysql -p'${var.mariadb_root_pwd}' -e \"CREATE DATABASE icingaweb2;\"",
      "sudo mysql -p'${var.mariadb_root_pwd}' -e \"CREATE USER 'icingaweb2'@'localhost' IDENTIFIED BY '${var.mariadb_icingaweb2_pwd}';\"",
      "sudo mysql -p'${var.mariadb_root_pwd}' -e \"GRANT ALL ON icingaweb2.* TO 'icingaweb2'@'localhost';\"",
      # Install Nginx web server
      "sudo apt-get install -y nginx-full php-fpm php-gd php-mbstring",
      # Change Nginx Timezone
      "PHPPATH=\"$(pgrep -a php-fpm | grep \"master process\" | awk -F '(' '{print $2}' | awk -F 'php-fpm.conf' '{print$1}')\"; sudo sed -i -e \"s/^;date.timezone =/date.timezone = Europe\\/Paris/\"  $${PHPPATH}php.ini | grep date.timezone",
      # Restart PHP-FPM
      "sudo systemctl restart php*",
      # Tune Nginx
      "sudo sed -i -e \"s/# server_names_hash_bucket_size/server_names_hash_bucket_size/\" /etc/nginx/nginx.conf | grep server_names_hash_bucket_size",
      # Configure Server block in Nginx
      "sudo wget -O /etc/nginx/sites-available/${var.fqdn}.${var.dns_domain} https://gist.githubusercontent.com/Fry-4TF1V/73818853eb3809f6cb00c3a0d82332b0/raw/8cea158383e58f4107ca5e3aff66c30824e000de/icinga2.conf",
      # Tune Server block with url
      "sudo sed -i \"s/server_name .*;/server_name ${var.fqdn}.${var.dns_domain} www.${var.fqdn}.${var.dns_domain};/g\" /etc/nginx/sites-available/${var.fqdn}.${var.dns_domain} | grep server_name",
      # Activate PHP-FPM for Nginx
      "PHPSOCK=\"$(grep php /proc/net/unix | awk '{print$8}')\"; sudo sed -i \"s#fastcgi_pass unix:/var/run/php5-fpm.sock;#fastcgi_pass unix:/var$PHPSOCK;#g\" /etc/nginx/sites-available/${var.fqdn}.${var.dns_domain} | grep \"fastcgi_pass unix:\"",
      # Activate Nginx Server block
      "sudo ln -s /etc/nginx/sites-available/${var.fqdn}.${var.dns_domain} /etc/nginx/sites-enabled/",
      # Restart Nginx
      "sudo systemctl restart nginx",
      # Install Certbot for Nginx
      "sudo apt-get install -y certbot python3-certbot-nginx",
      # Configure SSL certificate through CertBot
      "sudo certbot --nginx -d ${var.fqdn}.${var.dns_domain} -d www.${var.fqdn}.${var.dns_domain} --non-interactive --agree-tos -m ${var.letsencrypt_email} --redirect",
      # Install IcingaWeb2
      "sudo apt-get install -y icingaweb2 icingacli --install-recommends",
      # Import Icingaweb2 schema
      "sudo mysql -p'${var.mariadb_root_pwd}' icingaweb2 < /usr/share/icingaweb2/etc/schema/mysql.schema.sql",
      # Insert icingaadmin user on Icingaweb2
      "MYPWD=$(php -r \"echo password_hash('${var.icingaadmin_pwd}', PASSWORD_DEFAULT);\"); sudo mysql -p'${var.mariadb_root_pwd}' -e \"INSERT INTO icingaweb2.icingaweb_user (name, active, password_hash) VALUES ('icingaadmin', 1, '$${MYPWD}');\"",
      # Add icingaadmin user to group Administrators
      "sudo mysql -p'${var.mariadb_root_pwd}' -e \"INSERT into icingaweb2.icingaweb_group (id, name) VALUES (1, 'Administrators');\"",
      "sudo mysql -p'${var.mariadb_root_pwd}' -e \"INSERT INTO icingaweb2.icingaweb_group_membership (group_id, username) VALUES (1, 'icingaadmin');\"",
      # Activate Icinga2 API
      "sudo icinga2 api setup",
      # Create Icingaweb2 API user for Icinga2
      "printf '\\nobject ApiUser \"icingaweb2\" {\\n  password = \"%s\"\\n  permissions = [ \"status/query\", \"actions/*\", \"objects/modify/*\", \"objects/query/*\" ]\\n}\\n' '${var.icingaweb2_api_pwd}' | sudo tee -a /etc/icinga2/conf.d/api-users.conf > /dev/null",
      # Restart Icinga2
      "sudo systemctl restart icinga2",
      # Activate Icinga2 Command
      "sudo icinga2 feature enable command && sudo systemctl restart icinga2",
      
      # "sudo icingacli setup token create",

      # Create Icingaweb2 root directory
      "sudo icingacli setup config directory",
      # Change directory owner to www-data and group to icingaweb2
      "sudo chown -R www-data:icingaweb2 /etc/icingaweb2/",
      # Create file authentication.ini
      "printf '[icingaweb2]\\nbackend  = \"db\"\\nresource = \"icingaweb2\"\\n' | sudo -u www-data tee /etc/icingaweb2/authentication.ini > /dev/null",
      # Create folder monitoring
      "sudo -u www-data mkdir /etc/icingaweb2/modules/monitoring",
      # Create file monitoring/config.ini
      "printf '[security]\\nprotected_customvars = \"*pw*,*pass*,community\"\\n' | sudo -u www-data tee /etc/icingaweb2/modules/monitoring/config.ini > /dev/null",
      # Create file backend.ini
      "printf '[icinga2]\\ntype     = \"ido\"\\nresource = \"icinga2\"\\n' | sudo -u www-data tee /etc/icingaweb2/modules/monitoring/backends.ini > /dev/null",
      # Create file commandtransports.ini
      "printf '[icinga2]\\ntransport = \"api\"\\nhost      = \"localhost\"\\nport      = \"5665\"\\nusername  = \"%s\"\\npassword  = \"%s\"\\n' 'icingaweb2' '${var.icingaweb2_api_pwd}' | sudo -u www-data tee /etc/icingaweb2/modules/monitoring/commandtransports.ini > /dev/null",
      # Create file roles.ini
      "printf '[admins]\\nusers       = \"icingaadmin\"\\npermissions = \"*\"\\n' | sudo -u www-data tee /etc/icingaweb2/roles.ini > /dev/null",
      # Create file config.ini
      "printf '[logging]\\nlog         = \"syslog\"\\nlevel       = \"ERROR\"\\napplication = \"icingaweb2\"\\n\\n[preferences]\\ntype        = \"db\"\\nresource    = \"icingaweb2\"\\n' | sudo -u www-data tee /etc/icingaweb2/config.ini > /dev/null",
      "sudo -u www-data mkdir -p /etc/icingaweb2/enabledModules/",
      # Activate Monitoring module
      "sudo -u www-data ln -s /usr/share/icingaweb2/modules/monitoring /etc/icingaweb2/enabledModules/",
      # Create file resources.ini
      "printf '[icingaweb2]\\ntype     = \"db\"\\ndb       = \"mysql\"\\nhost     = \"localhost\"\\nport     = \"3306\"\\ndbname   = \"icingaweb2\"\\nusername = \"icingaweb2\"\\npassword = \"%s\"\\n\\n[icinga2]\\ntype     = \"db\"\\ndb       = \"mysql\"\\nhost     = \"localhost\"\\nport     = \"3306\"\\ndbname   = \"icinga2\"\\nusername = \"icinga2\"\\npassword = \"%s\"\\n' '${var.mariadb_icingaweb2_pwd}' '${var.mariadb_icinga2_pwd}' | sudo -u www-data tee /etc/icingaweb2/resources.ini > /dev/null",
      
      # Define this host as Icinga2 master
      "sudo icinga2 node setup --master",
      # "sudo chown -R www-data:icingaweb2 /usr/share/icingaweb2",
    ]
  }
}

# # Run the Icinga2 Director install script inside the instance
resource null_resource install_icinga2_director {
  # triggers = {
  #     id = null_resource.install_icingaweb2.id
  # }

  provisioner "remote-exec" {
    connection {
      type     = "ssh"
      user     = "debian"
      host     =  openstack_compute_instance_v2.server[0].access_ip_v4
    }

    inline = [

      ### Install Director
      # Install required modules
      "sudo git clone 'https://github.com/Icinga/icingaweb2-module-ipl' '/usr/share/icingaweb2/modules/ipl' --branch v0.5.0",
      "sudo -u www-data icingacli module enable ipl",
      "sudo git clone 'https://github.com/Icinga/icingaweb2-module-incubator' '/usr/share/icingaweb2/modules/incubator' --branch v0.12.0",
      "sudo -u www-data icingacli module enable incubator",
      "sudo git clone 'https://github.com/Icinga/icingaweb2-module-reactbundle' '/usr/share/icingaweb2/modules/reactbundle' --branch v0.9.0",
      "sudo -u www-data icingacli module enable reactbundle",
      # Create database for Director
      "sudo mysql -p'${var.mariadb_root_pwd}' -e \"CREATE DATABASE director;\"",
      "sudo mysql -p'${var.mariadb_root_pwd}' -e \"CREATE USER 'director'@'localhost' IDENTIFIED BY '${var.mariadb_director_pwd}';\"",
      "sudo mysql -p'${var.mariadb_root_pwd}' -e \"GRANT ALL ON director.* TO 'director'@'localhost';\"",
      # Add Director config in resources.ini
      "printf '\\n[Director DB]\\ntype =     \"db\"\\ndb =       \"mysql\"\\nhost =     \"localhost\"\\ndbname =   \"director\"\\nusername = \"director\"\\npassword = \"%s\"\\ncharset =  \"utf8\"\\n' '${var.mariadb_director_pwd}' | sudo -u www-data tee -a /etc/icingaweb2/resources.ini > /dev/null",
      "sudo git clone 'https://github.com/icinga/icingaweb2-module-director' '/usr/share/icingaweb2/modules/director' --branch v1.8.1",
      "sudo -u www-data mkdir -p /etc/icingaweb2/modules/director/",
      # Create director/config.ini
      "printf '[db]\\nresource = \"Director DB\"\\n' | sudo -u www-data tee /etc/icingaweb2/modules/director/config.ini > /dev/null",
      # Create API user director
      "printf '\\nobject ApiUser \"director\" {\\n  password = \"%s\"\\n  permissions = [ \"*\" ]\\n}\\n' '${var.icinga_director_api_pwd}' | sudo tee -a /etc/icinga2/conf.d/api-users.conf > /dev/null",
      # Restart Icinga2
      "sudo systemctl restart icinga2",
      # Create kickstart.ini
      "printf '[config]\\nendpoint = ${var.fqdn}.${var.dns_domain}\\n; host = 127.0.0.1\\n; port = 5665\\nusername = director\\npassword = %s\\n' '${var.icinga_director_api_pwd}' | sudo -u www-data tee /etc/icingaweb2/modules/director/kickstart.ini > /dev/null",
      # Enable Director
      "sudo -u www-data icingacli module enable director",

      "sudo -u www-data icingacli director migration pending --verbose",
      "sudo -u www-data icingacli director migration run --verbose",
      "sudo -u www-data icingacli director kickstart required --verbose",
      "sudo -u www-data icingacli director kickstart run",
      # "sudo -u www-data icingacli director migration run --verbose",
      # "sudo -u www-data icingacli director migration pending --verbose",
      "sudo -u www-data icingacli director config deploy",
      # Restart Icinga2
      "sudo systemctl restart icinga2",
      # Enable Director daemon
      "sudo useradd -r -g icingaweb2 -d /var/lib/icingadirector -s /bin/false icingadirector",
      "sudo install -d -o icingadirector -g icingaweb2 -m 0750 /var/lib/icingadirector",
      "sudo cp /usr/share/icingaweb2/modules/director/contrib/systemd/icinga-director.service /etc/systemd/system/",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable icinga-director.service && sudo systemctl start icinga-director.service",
    ]
  }
}

# # Run the Icinga2 vSphere module install script inside the instance
resource null_resource install_icinga2_vsphere {
  # triggers = {
  #   id = null_resource.install_icinga2_director.id
  # }

  provisioner "remote-exec" {
    connection {
      type     = "ssh"
      user     = "debian"
      host     =  openstack_compute_instance_v2.server[0].access_ip_v4
    }

    inline = [

      ### Install vSphere module
      # Install requirements
      "sudo apt-get install -y php-soap",
      # # Install module
      # "sudo git clone 'https://github.com/Icinga/icingaweb2-module-vspheredb' '/usr/share/icingaweb2/modules/vspheredb'",
      # Create database for vSphereDB
      "sudo mysql -p'${var.mariadb_root_pwd}' -e \"CREATE DATABASE vspheredb CHARACTER SET 'utf8mb4' COLLATE utf8mb4_bin;\"",
      "sudo mysql -p'${var.mariadb_root_pwd}' -e \"CREATE USER 'vspheredb'@'localhost' IDENTIFIED BY '${var.mariadb_vspheredb_pwd}';\"",
      "sudo mysql -p'${var.mariadb_root_pwd}' -e \"GRANT ALL ON vspheredb.* TO 'vspheredb'@'localhost';\"",
      # Import vSphereDB schema
      "sudo mysql -p'${var.mariadb_root_pwd}' vspheredb < /usr/share/icingaweb2/modules/vspheredb/schema/mysql.sql",
      # Add resource in resources.ini
      "printf '\\n[vSphereDB]\\ntype     = \"db\"\\ndb       = \"mysql\"\\nhost     = \"localhost\"\\n; port   = 3306\\ndbname   = \"vspheredb\"\\nusername = \"vspheredb\"\\npassword = \"%s\"\\ncharset  = \"utf8mb4\"\\n' '${var.mariadb_vspheredb_pwd}' | sudo -u www-data tee -a /etc/icingaweb2/resources.ini > /dev/null",
      
      "sudo getent passwd \"icingavspheredb\" > /dev/null || sudo useradd -r -g \"icingaweb2\" -d /var/lib/icingavspheredb -s /bin/false icingavspheredb",
      "sudo install -d -o \"icingavspheredb\" -g \"icingaweb2\" -m 0750 /var/lib/icingavspheredb",
      "sudo install -d -m 0755 \"/usr/share/icingaweb2/modules/vspheredb\"",

      "sudo test -d \"/usr/share/icingaweb2/modules/vspheredb_TMP\" && sudo rm -rf \/usr/share/icingaweb2/modules/vspheredb_TMP\"",
      "sudo test -d \"/usr/share/icingaweb2/modules/vspheredb_BACKUP\" && sudo rm -rf \"/usr/share/icingaweb2/modules/vspheredb_BACKUP\"",
      "sudo install -d -o root -g root -m 0755 \"/usr/share/icingaweb2/modules/vspheredb_TMP\"",
      "sudo wget -q -O - \"https://github.com/icinga/icingaweb2-module-vspheredb/archive/refs/tags/v1.2.1.tar.gz\" | sudo tar xfz - -C \"/usr/share/icingaweb2/modules/vspheredb_TMP\" --strip-components 1 && sudo mv \"/usr/share/icingaweb2/modules/vspheredb\" \"/usr/share/icingaweb2/modules/vspheredb_BACKUP\" && sudo mv \"/usr/share/icingaweb2/modules/vspheredb_TMP\" \"/usr/share/icingaweb2/modules/vspheredb\" && sudo rm -rf \"/usr/share/icingaweb2/modules/vspheredb_BACKUP\"",

      "echo \"d /run/icinga-vspheredb 0755 icingavspheredb icingaweb2 -\" | sudo tee \"/etc/tmpfiles.d/icinga-vspheredb.conf\"",
      "sudo cp -f \"/usr/share/icingaweb2/modules/vspheredb/contrib/systemd/icinga-vspheredb.service\" /etc/systemd/system/",
      "sudo systemd-tmpfiles --create \"/etc/tmpfiles.d/icinga-vspheredb.conf\"",

      "sudo icingacli module enable vspheredb",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable icinga-vspheredb.service",
      "sudo systemctl restart icinga-vspheredb.service",

      # Install postfix for email notifications
      # "sudo DEBIAN_FRONTEND=noninteractive apt-get install postfix -y",
      "echo \"postfix postfix/mailname string ${var.dns_domain}\" | sudo debconf-set-selections";
      "echo \"postfix postfix/main_mailer_type string 'Internet Site'\" | sudo debconf-set-selections";
      "sudo apt-get install postfix -y";
      # Configure relay host
      "sudo sed -i 's/relayhost =.*/relayhost = ${var.smtp_relayhost}/g' /etc/postfix/main.cf",

      "sudo sed -i 's/smtp_tls_security_level.*/smtp_tls_security_level=encrypt/g' /etc/postfix/main.cf",
      "printf 'smtp_tls_wrappermode = yes' | sudo tee -a /etc/postfix/main.cf  > /dev/null",

      # Activate SASL Support on Postfix
      "printf '\\n#Activate SASL support to send mails' | sudo tee -a /etc/postfix/main.cf  > /dev/null",
      "printf '\\nsmtp_sasl_auth_enable = yes' | sudo tee -a /etc/postfix/main.cf  > /dev/null",
      "printf '\\nsmtp_sasl_security_options = noanonymous' | sudo tee -a /etc/postfix/main.cf  > /dev/null",
      "printf '\\nsmtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd' | sudo tee -a /etc/postfix/main.cf  > /dev/null",
      "printf '\\nsmtp_always_send_ehlo = yes' | sudo tee -a /etc/postfix/main.cf  > /dev/null",
      
      # Define login and password for relay host
      "printf '${var.smtp_relayhost} ${var.smtp_relayhost_login}:${var.smtp_relayhost_pwd}' | sudo tee -a /etc/postfix/sasl_passwd  > /dev/null",
      "sudo chmod 600 /etc/postfix/sasl_passwd";
      "sudo postmap /etc/postfix/sasl_passwd";

      "sudo systemctl restart postfix";


      # # Create file config.ini
      # "sudo -u www-data mkdir -p /etc/icingaweb2/modules/vspheredb/",
      # "printf '[db]\\nresource = \"vSphereDB\"\\n' | sudo -u www-data tee /etc/icingaweb2/modules/vspheredb/config.ini > /dev/null",
      # # Enable vSphereDB
      # "sudo -u www-data icingacli module enable vspheredb",
      # # Enable vSphereDB daemon
      # "sudo cp /usr/share/icingaweb2/modules/vspheredb/contrib/systemd/icinga-vspheredb.service /etc/systemd/system/",
      # "sudo sed -i 's/User=.*/User=www-data/g' /etc/systemd/system/icinga-vspheredb.service",
      # "sudo systemctl daemon-reload",
      # "sudo systemctl enable icinga-vspheredb.service && sudo systemctl start icinga-vspheredb.service",
    ]
  }
}
