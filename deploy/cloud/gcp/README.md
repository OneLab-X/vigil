# Vigil on Google Compute Engine

## Terraform

```bash
cd deploy/cloud/gcp
cat > terraform.tfvars <<'EOF'
project_id            = "my-vigil-host-project"
vigil_version         = "0.1.0"
admin_email           = "you@example.com"
admin_name            = "Your Name"
org_name              = "Example Org"
monitored_project_ids = ["example-project"]   # default: project_id
domain                = "vigil.example.com"   # optional
acme_email            = "you@example.com"     # optional
dns_managed_zone      = "example-com"         # optional Cloud DNS zone
EOF
terraform init && terraform apply
```

Creates a VPC + subnet, firewall rules (80/443 from `web_cidrs`; 22 only from IAP's `35.235.240.0/20`), a static IP, a
Shielded VM (Ubuntu 24.04, `e2-standard-4`, 50 GiB pd-balanced) with OS Login, and the service account
`vigil-vm@…` with `roles/logging.viewer` on each monitored project (`read_data_access_logs = true` adds
`roles/logging.privateLogViewer`). Follow the install with
`gcloud compute ssh vigil --tunnel-through-iap -- sudo tail -f /var/log/cloud-init-output.log`.

## Identity (no key files)

Vigil's GCP connector with auth mode **Application Default Credentials** uses the VM's attached service account through
the metadata server — no key file, no `VIGIL_GCP_CREDENTIALS_FILE`. To monitor another project later:

```bash
gcloud projects add-iam-policy-binding OTHER_PROJECT --member serviceAccount:$(terraform output -raw service_account_email) --role roles/logging.viewer
```

**Connector test:** add a GCP connection (project id, auth mode ADC) and press *Test*.

## Without Terraform

Create an Ubuntu 24.04 VM (≥2 vCPU / 4 GiB) running as a dedicated service account with `roles/logging.viewer`, allow
80/443, and pass [`cloud-init.yaml`](cloud-init.yaml) (edited) as the `user-data` metadata value:
`gcloud compute instances create vigil … --metadata-from-file user-data=cloud-init.yaml`.
