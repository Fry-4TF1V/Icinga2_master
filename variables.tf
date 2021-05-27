variable ovh_region {
  type        = string
  description = "OVHcloud Public Cloud region used"
}

variable ovh_application_key {
  type        = string
  description = "OVHcloud Application Key"
}

variable ovh_application_secret {
  type        = string
  description = "OVHcloud Application Secret"
}

variable ovh_consumer_key {
  type        = string
  description = "OVHcloud Consumer Key"
}

variable dns_domain {
  type        = string
  description = "OVHcloud DNS domain"
}

variable puppet_master_fqdn {
  type        = string
  description = "Puppet Master subdomain (without OVHcloud DNS domain)"
}

variable fqdn {
  type        = string
  description = "Icinga2 Server subdomain (without OVHcloud DNS domain)"
}

variable image {
  type        = string
  description = "BBB Server Linux distribution"
}

variable flavor {
  type        = string
  description = "BBB Server Flavor"
}

variable letsencrypt_email {
  type        = string
  description = "Email address for Let's Encrypt to generate a valid SSL certificate for the host"
}

variable keypair_name {
  type        = string
  description = "Keypair name stored in Openstack"
}

variable public_key {
  type        = string
  description = "Public Key used by Openstack"
}

variable mariadb_root_pwd{
  type        = string
  description = "Mariadb root password"
}

variable mariadb_icinga2_pwd{
  type        = string
  description = "Mariadb icinga2 password"
}

variable mariadb_icingaweb2_pwd{
  type        = string
  description = "Mariadb icingaweb2 password"
}

variable mariadb_director_pwd{
  type        = string
  description = "Mariadb Icinga Director password"
}

variable mariadb_vspheredb_pwd{
  type        = string
  description = "Mariadb Icinga vSphereDB password"
}

variable icingaadmin_pwd{
  type        = string
  description = "icingaadmin password"
}

variable icingaweb2_api_pwd{
  type        = string
  description = "Icingaweb2 API password"
}

variable icinga_director_api_pwd{
  type        = string
  description = "Icinga Director API password"
}