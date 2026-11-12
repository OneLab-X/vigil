variable "region" {
  type        = string
  description = "AWS region"
}

variable "name" {
  type        = string
  default     = "vigil"
  description = "Name prefix for all resources"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}$", var.name))
    error_message = "lowercase letters, digits and dashes, 2-31 chars"
  }
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
  description = "Optional: pin get.sh to this SHA-256 (from the release's SHA256SUMS) in addition to the SHA256SUMS check"
  validation {
    condition     = var.get_sh_sha256 == "" || can(regex("^[0-9a-f]{64}$", var.get_sh_sha256))
    error_message = "64 lowercase hex characters"
  }
}

variable "admin_email" {
  type        = string
  description = "First owner's email"
  validation {
    condition     = can(regex("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", var.admin_email))
    error_message = "must be an email address"
  }
}

variable "admin_name" {
  type        = string
  description = "First owner's display name"
  validation {
    condition     = can(regex("^[A-Za-z0-9 ._-]{1,80}$", var.admin_name))
    error_message = "letters, digits, spaces, . _ - (max 80)"
  }
}

variable "org_name" {
  type        = string
  description = "Organization name"
  validation {
    condition     = can(regex("^[A-Za-z0-9 ._&-]{1,80}$", var.org_name))
    error_message = "letters, digits, spaces, . _ & - (max 80)"
  }
}

variable "domain" {
  type        = string
  default     = ""
  description = "FQDN for built-in HTTPS (Let's Encrypt). Empty = no TLS proxy; UI on 127.0.0.1:3000 (use SSM port forwarding)"
  validation {
    condition     = var.domain == "" || can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", var.domain))
    error_message = "must be a lowercase FQDN"
  }
}

variable "acme_email" {
  type        = string
  default     = ""
  description = "Let's Encrypt account email (optional)"
  validation {
    condition     = var.acme_email == "" || can(regex("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", var.acme_email))
    error_message = "must be an email address"
  }
}

variable "route53_zone_id" {
  type        = string
  default     = ""
  description = "Optional Route 53 hosted zone to create the A record for var.domain in"
}

variable "instance_type" {
  type        = string
  default     = "c6i.xlarge" # 4 vCPU / 8 GiB (recommended). Minimum: 2 vCPU / 4 GiB, e.g. t3.medium.
  description = "EC2 instance type"
}

variable "architecture" {
  type        = string
  default     = "amd64"
  description = "amd64 or arm64 (use a Graviton instance type such as c7g.xlarge with arm64)"
  validation {
    condition     = contains(["amd64", "arm64"], var.architecture)
    error_message = "amd64 or arm64"
  }
}

variable "disk_gb" {
  type        = number
  default     = 50
  description = "Root disk size (GiB); size for evidence retention"
  validation {
    condition     = var.disk_gb >= 30
    error_message = "at least 30 GiB"
  }
}

variable "web_cidrs" {
  type        = list(string)
  default     = ["0.0.0.0/0"]
  description = "Who may reach 80/443. Let's Encrypt HTTP validation needs 80 open to the internet."
}

variable "ssh_cidrs" {
  type        = list(string)
  default     = []
  description = "CIDRs allowed to SSH (empty = no SSH; use SSM Session Manager)"
}

variable "ssh_key_name" {
  type        = string
  default     = null
  description = "Optional EC2 key pair for SSH"
}

variable "enable_ssm" {
  type        = bool
  default     = true
  description = "Attach AmazonSSMManagedInstanceCore so admins can use Session Manager instead of SSH"
}

variable "reader_account_ids" {
  type        = list(string)
  default     = ["*"]
  description = "AWS account ids whose reader roles Vigil may assume (default any; the customer's trust policy + ExternalId is the gate)"
}

variable "reader_role_name_pattern" {
  type        = string
  default     = "vigil-reader*"
  description = "IAM role name (pattern) customers create for Vigil in their accounts"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Extra tags"
}
