variable "project_id" {
  type        = string
  description = "Project that hosts the Vigil VM"
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "zone" {
  type    = string
  default = "us-central1-a"
}

variable "name" {
  type        = string
  default     = "vigil"
  description = "Name prefix for all resources"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,24}$", var.name))
    error_message = "lowercase letters, digits and dashes, 2-25 chars"
  }
}

variable "monitored_project_ids" {
  type        = list(string)
  default     = []
  description = "Projects whose logs Vigil reads (default: project_id). The VM's service account gets read-only logging roles on each."
}

variable "read_data_access_logs" {
  type        = bool
  default     = false
  description = "Also grant roles/logging.privateLogViewer (Data Access audit logs)"
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
  type        = string
  default     = ""
  description = "Optional: pin get.sh to this SHA-256 in addition to the SHA256SUMS check"
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
  type        = string
  default     = ""
  description = "FQDN for built-in HTTPS. Empty = UI on 127.0.0.1:3000 (reach it with an IAP SSH tunnel)"
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

variable "dns_managed_zone" {
  type        = string
  default     = ""
  description = "Optional Cloud DNS managed zone (in project_id) for var.domain's A record"
}

variable "machine_type" {
  type        = string
  default     = "e2-standard-4" # 4 vCPU / 16 GiB. Minimum: e2-medium is too small; use e2-standard-2 (2 vCPU / 8 GiB).
  description = "Compute Engine machine type"
}

variable "architecture" {
  type    = string
  default = "amd64"
  validation {
    condition     = contains(["amd64", "arm64"], var.architecture)
    error_message = "amd64 or arm64 (arm64 needs a T2A/C4A machine type)"
  }
}

variable "disk_gb" {
  type    = number
  default = 50
  validation {
    condition     = var.disk_gb >= 30
    error_message = "at least 30 GiB"
  }
}

variable "web_cidrs" {
  type        = list(string)
  default     = ["0.0.0.0/0"]
  description = "Who may reach 80/443 (Let's Encrypt HTTP validation needs 80 from the internet)"
}

variable "ssh_cidrs" {
  type        = list(string)
  default     = ["35.235.240.0/20"] # IAP TCP forwarding only
  description = "CIDRs allowed to SSH; default is Identity-Aware Proxy only (gcloud compute ssh --tunnel-through-iap)"
}
