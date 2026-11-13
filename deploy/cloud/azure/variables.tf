variable "subscription_id" {
  type        = string
  description = "Subscription that hosts the Vigil VM"
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "name" {
  type    = string
  default = "vigil"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}$", var.name))
    error_message = "lowercase letters, digits and dashes, 2-31 chars"
  }
}

variable "monitored_subscription_ids" {
  type        = list(string)
  default     = []
  description = "Subscriptions Vigil reads (default: subscription_id). The managed identity gets Monitoring Reader on each; they must be in the same Entra ID tenant."
}

variable "vigil_version" {
  type        = string
  description = "Vigil release to install, e.g. 0.1.0 (never 'latest')"
  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.vigil_version))
    error_message = "must be X.Y.Z"
  }
}

variable "get_sh_sha256" {
  type    = string
  default = ""
  validation {
    condition     = var.get_sh_sha256 == "" || can(regex("^[0-9a-f]{64}$", var.get_sh_sha256))
    error_message = "64 lowercase hex characters"
  }
}

variable "admin_email" {
  type = string
  validation {
    condition     = can(regex("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", var.admin_email))
    error_message = "must be an email address"
  }
}

variable "admin_name" {
  type = string
  validation {
    condition     = can(regex("^[A-Za-z0-9 ._-]{1,80}$", var.admin_name))
    error_message = "letters, digits, spaces, . _ - (max 80)"
  }
}

variable "org_name" {
  type = string
  validation {
    condition     = can(regex("^[A-Za-z0-9 ._&-]{1,80}$", var.org_name))
    error_message = "letters, digits, spaces, . _ & - (max 80)"
  }
}

variable "domain" {
  type    = string
  default = ""
  validation {
    condition     = var.domain == "" || can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", var.domain))
    error_message = "must be a lowercase FQDN"
  }
}

variable "acme_email" {
  type    = string
  default = ""
  validation {
    condition     = var.acme_email == "" || can(regex("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", var.acme_email))
    error_message = "must be an email address"
  }
}

variable "dns_zone_name" {
  type        = string
  default     = ""
  description = "Optional Azure DNS zone (e.g. example.com) to create var.domain's A record in"
}

variable "dns_zone_resource_group" {
  type    = string
  default = ""
}

variable "vm_size" {
  type        = string
  default     = "Standard_F4s_v2" # 4 vCPU / 8 GiB (recommended). Minimum 2 vCPU / 4 GiB, e.g. Standard_B2s.
  description = "VM size"
}

variable "architecture" {
  type    = string
  default = "amd64"
  validation {
    condition     = contains(["amd64", "arm64"], var.architecture)
    error_message = "amd64 or arm64 (arm64 needs a Dpsv5/Epsv5 size)"
  }
}

variable "disk_gb" {
  type    = number
  default = 64
  validation {
    condition     = var.disk_gb >= 30
    error_message = "at least 30 GiB"
  }
}

variable "admin_username" {
  type    = string
  default = "vigiladmin"
}

variable "ssh_public_key" {
  type        = string
  description = "SSH public key for the VM admin user (password login is disabled)"
}

variable "web_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

variable "ssh_cidrs" {
  type        = list(string)
  default     = []
  description = "CIDRs allowed to SSH (empty = none; use Azure Bastion)"
}

variable "tags" {
  type    = map(string)
  default = {}
}
