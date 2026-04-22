terraform {
  required_providers {
    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.73"
    }
  }
  required_version = ">= 0.13"
}
provider "scaleway" {
  zone   = "fr-par-2"
  region = "fr-par"
}

variable "instance_type" {
  type        = string
  description = "Scaleway instance type to be used"
}

variable "instance_label" {
  type        = string
  description = "Instance name to display in console"
}

variable "user_data" {
  type        = string
  description = "Script that will be run at instance startup"
}

locals {
  project_id = "7af36573-4180-41de-8c27-890ed9d919fa"
}

resource "scaleway_instance_ip" "github_runner" {
  project_id = local.project_id
}

resource "scaleway_instance_security_group" "github_runner" {
  project_id              = local.project_id
  inbound_default_policy  = "drop"
  outbound_default_policy = "accept"
}

resource "scaleway_instance_server" "multi-h100-sxm5" {
  project_id = local.project_id
  image      = "ba7d8136-7ec3-4efb-8e36-b891a4685a36" // Local image: tfhe-rs-ubuntu-noble-cuda
  type       = var.instance_type
  name       = var.instance_label

  ip_id = scaleway_instance_ip.github_runner.id

  user_data = {
    "cloud-init" = var.user_data
  }

  security_group_id = scaleway_instance_security_group.github_runner.id
}

output "instance_id" {
  value       = scaleway_instance_server.multi-h100-sxm5.id
  description = "Unique ID of the Scaleway instance"
}
