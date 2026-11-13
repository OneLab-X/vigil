output "public_ip" {
  value = google_compute_address.vigil.address
}

output "url" {
  value       = var.domain != "" ? "https://${var.domain}" : "gcloud compute ssh ${var.name} --zone ${var.zone} --tunnel-through-iap -- -L 3000:127.0.0.1:3000  → http://localhost:3000"
  description = "Where to open Vigil"
}

output "service_account_email" {
  value       = google_service_account.vigil.email
  description = "Identity Vigil's GCP connector uses (auth mode: Application Default Credentials). Grant it roles/logging.viewer on any further project."
}

output "initial_password_command" {
  value = "gcloud compute ssh ${var.name} --zone ${var.zone} --tunnel-through-iap -- sudo cat /opt/vigil/initial-owner-password"
}
