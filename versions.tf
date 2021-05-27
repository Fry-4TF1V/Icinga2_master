# Definition of needed providers
terraform {
  required_providers {
    openstack = {
      source = "terraform-provider-openstack/openstack"
        }
    ovh = {
      source = "ovh/ovh"
      # version = "0.10.0"
        }
  }
  required_version = ">= 0.13"
}
