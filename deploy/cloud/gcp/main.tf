# Vigil on Google Compute Engine — example Terraform module.
# One Ubuntu 24.04 VM with a dedicated service account (no key file): Vigil's GCP connector uses Application Default
# Credentials, which on GCE resolve to this service account through the metadata server. The account gets
# roles/logging.viewer (+ optionally roles/logging.privateLogViewer) on each monitored project — read-only.
# Firewall: 80/443 from var.web_cidrs, 22 only from IAP TCP forwarding (35.235.240.0/20) unless overridden.

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 7.0" }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

locals {
  monitored_projects = length(var.monitored_project_ids) > 0 ? var.monitored_project_ids : [var.project_id]
  reader_roles       = var.read_data_access_logs ? ["roles/logging.viewer", "roles/logging.privateLogViewer"] : ["roles/logging.viewer"]
  bindings           = { for p in setproduct(local.monitored_projects, local.reader_roles) : "${p[0]}|${p[1]}" => { project = p[0], role = p[1] } }
}

resource "google_project_service" "compute" {
  service            = "compute.googleapis.com"
  disable_on_destroy = false
}

# ---------------------------------------------------------------- identity (keyless)
resource "google_service_account" "vigil" {
  account_id   = "${var.name}-vm"
  display_name = "Vigil VM (read-only log access)"
}

resource "google_project_iam_member" "reader" {
  for_each = local.bindings
  project  = each.value.project
  role     = each.value.role
  member   = "serviceAccount:${google_service_account.vigil.email}"
}

# ---------------------------------------------------------------- network
resource "google_compute_network" "vigil" {
  name                    = var.name
  auto_create_subnetworks = false
  depends_on              = [google_project_service.compute]
}

resource "google_compute_subnetwork" "vigil" {
  name          = var.name
  ip_cidr_range = "10.42.1.0/24"
  network       = google_compute_network.vigil.id
  region        = var.region
}

resource "google_compute_firewall" "web" {
  name          = "${var.name}-web"
  network       = google_compute_network.vigil.name
  source_ranges = var.web_cidrs
  target_tags   = [var.name]
  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
}

resource "google_compute_firewall" "ssh" {
  count         = length(var.ssh_cidrs) > 0 ? 1 : 0
  name          = "${var.name}-ssh"
  network       = google_compute_network.vigil.name
  source_ranges = var.ssh_cidrs
  target_tags   = [var.name]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_address" "vigil" {
  name   = var.name
  region = var.region
}

# ---------------------------------------------------------------- VM
resource "google_compute_instance" "vigil" {
  name         = var.name
  zone         = var.zone
  machine_type = var.machine_type
  tags         = [var.name]

  boot_disk {
    initialize_params {
      image = var.architecture == "arm64" ? "ubuntu-os-cloud/ubuntu-2404-lts-arm64" : "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
      size  = var.disk_gb
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.vigil.id
    access_config {
      nat_ip = google_compute_address.vigil.address
    }
  }

  service_account {
    email  = google_service_account.vigil.email
    scopes = ["cloud-platform"] # access is limited by IAM roles above, not by scopes
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    enable-oslogin = "TRUE"
    user-data = templatefile("${path.module}/../cloud-init.yaml.tftpl", {
      vigil_version     = var.vigil_version
      get_sh_sha256     = var.get_sh_sha256
      admin_email       = var.admin_email
      admin_name        = var.admin_name
      org_name          = var.org_name
      domain            = var.domain
      acme_email        = var.acme_email
      aws_principal_arn = ""
    })
  }

  lifecycle {
    ignore_changes = [metadata["user-data"], boot_disk[0].initialize_params[0].image]
  }

  depends_on = [google_project_iam_member.reader]
}

# ---------------------------------------------------------------- DNS (optional)
resource "google_dns_record_set" "vigil" {
  count        = var.domain != "" && var.dns_managed_zone != "" ? 1 : 0
  managed_zone = var.dns_managed_zone
  name         = "${var.domain}."
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_address.vigil.address]
}
