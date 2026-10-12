terraform {
  required_providers {
    nebius = {
      source  = "terraform-provider.storage.eu-north1.nebius.cloud/nebius/nebius"
      version = "~> 0.5"
    }
  }
  required_version = "~> 1.14"
}

provider "nebius" {
  domain = "api.nebius.cloud:443"

  service_account = {
    account_id       = var.nebius_sa_account_id
    public_key_id    = var.nebius_sa_public_key_id
    private_key_file = "/app/nebius/slab_ci_service_account_private.pem"
  }
}

variable "nebius_sa_account_id" {
  type        = string
  description = "Nebius service account used by Slab"
  default     = "serviceaccount-e00ja4a60pzcaabtm0"
}

variable "nebius_sa_public_key_id" {
  type        = string
  description = "ID of the service account authorized key"
  default     = "publickey-e00vtny4sn819pm0pg"
}

variable "nebius_project_id" {
  type        = string
  description = "Nebius project ID to attach to"
  default     = "project-e00g2md3pr003aqkq1v4q0"
}

variable "nebius_subnet_id" {
  type        = string
  description = "Nebius VPC subnet ID to attach the instance to"
  default     = "vpcsubnet-e00zwv8bkn6dxmk91s"
}

variable "nebius_security_group_id" {
  type        = string
  description = "Nebius VPC security group ID to attach to the instance network interface"
  default     = "vpcsecuritygroup-e00kvyx503efvsc4br"
}

# Provided via ci/slab.toml
variable "instance_type" {
  type        = string
  description = "Nebius instance preset to be used (e.g. 1gpu-16vcpu-200gb)"
}

# Presets are platform specific, a different GPU type needs its own script
variable "platform" {
  type        = string
  description = "Nebius compute platform (GPU type)"
  default     = "gpu-h100-sxm"
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
  sensitive   = true
}

resource "nebius_compute_v1_disk" "boot_disk" {
  parent_id        = var.nebius_project_id
  name             = "${var.instance_label}-boot-disk"
  type             = "NETWORK_SSD"
  size_gibibytes   = 200
  block_size_bytes = 4096

  # Pinned ubuntu24.04-cuda12 image (CUDA 12.8, driver 570), the family alone would drift between runs
  source_image_id = "computeimage-e00q003g5k851wjgpn"
}

resource "nebius_compute_v1_instance" "runner" {
  parent_id = var.nebius_project_id
  name      = var.instance_label

  resources = {
    platform = var.platform
    preset   = var.instance_type
  }

  boot_disk = {
    attach_mode = "READ_WRITE"
    existing_disk = {
      id = nebius_compute_v1_disk.boot_disk.id
    }
  }

  network_interfaces = [
    {
      name              = "eth0"
      subnet_id         = var.nebius_subnet_id
      security_groups   = [{ id = var.nebius_security_group_id }]
      ip_address        = {}
      public_ip_address = {}
    }
  ]

  # Nebius expects a #cloud-config document, so the Slab script is shipped as a file and run from it
  cloud_init_user_data = <<-EOT
    #cloud-config
    write_files:
      - path: /opt/slab/runner_start.sh
        permissions: "0755"
        encoding: b64
        content: ${base64encode(var.user_data)}
    runcmd:
      - /opt/slab/runner_start.sh
  EOT
}

output "instance_id" {
  value       = nebius_compute_v1_instance.runner.id
  description = "Unique ID of the Nebius instance"
}
