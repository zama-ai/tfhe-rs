terraform {
  required_providers {
    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.73"
    }
  }
  required_version = "~> 1.14"
}

provider "scaleway" {
  zone = "fr-par-2"
}

# Provided via Slab server env
variable "project_id" {
  type        = string
  description = "Scaleway project ID to attached to"
}

# Provided via ci/slab.toml
variable "instance_type" {
  type        = string
  description = "Scaleway instance type to be used"
}

# Provided by Slab server
variable "instance_label" {
  type        = string
  description = "Instance name to display in console"
}

# Provided by Slab server
variable "user_data" {
  type        = string
  description = "Script that will be run at instance startup"
}

resource "scaleway_instance_ip" "github_runner" {
  project_id = var.project_id
}

resource "scaleway_instance_security_group" "github_runner" {
  project_id              = var.project_id
  inbound_default_policy  = "drop"
  outbound_default_policy = "accept"
}

resource "scaleway_instance_server" "multi_h100_sxm5" {
  project_id = var.project_id
  image      = "ubuntu_noble_gpu_os_12"
  type       = var.instance_type
  name       = var.instance_label

  root_volume {
    size_in_gb = 200
  }

  ip_id = scaleway_instance_ip.github_runner.id

  user_data = {
    "cloud-init" = var.user_data
  }

  security_group_id = scaleway_instance_security_group.github_runner.id
}

output "instance_id" {
  value       = scaleway_instance_server.multi_h100_sxm5.id
  description = "Unique ID of the Scaleway instance"
}
