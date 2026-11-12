# Vigil on an Azure VM

## Terraform

```bash
cd deploy/cloud/azure
cat > terraform.tfvars <<'EOF'
subscription_id = "00000000-0000-0000-0000-000000000000"
vigil_version   = "0.1.0"
admin_email     = "you@example.com"
admin_name      = "Your Name"
org_name        = "Example Org"
ssh_public_key  = "ssh-ed25519 AAAA… you@laptop"
domain          = "vigil.example.com"   # optional
acme_email      = "you@example.com"     # optional
dns_zone_name   = "example.com"         # optional Azure DNS zone (+ dns_zone_resource_group)
EOF
terraform init && terraform apply
```

Creates a resource group, VNet + subnet, NSG (80/443 from `web_cidrs`; SSH only from `ssh_cidrs`, empty by default —
use Azure Bastion), a static public IP, an Ubuntu 24.04 VM (`Standard_F4s_v2`, 64 GiB Premium SSD, password login
disabled) and a **user-assigned managed identity** with *Monitoring Reader* on each monitored subscription.

## Identity (no client secret)

Configure the Azure connector with:

- **Authentication:** Managed identity of this Azure VM
- **Application (client) ID:** `terraform output -raw managed_identity_client_id`
- **Tenant ID:** `terraform output -raw tenant_id`

Vigil requests tokens from the VM's Instance Metadata Service (`169.254.169.254`, `Metadata: true`), which is reachable
only from the VM. The identity can only read subscriptions in its own Entra ID tenant. To read Entra ID sign-in/audit
logs through Microsoft Graph, assign the identity's service principal the Graph app role `AuditLog.Read.All` (the
connector's onboarding page shows the call), or use a Log Analytics workspace with *Log Analytics Reader*.

**Connector test:** add an Azure connection with the values above and press *Test* — it reports
`managed_identity:app` and flags any role that can write.

Running Vigil outside Azure? Use workload identity federation (`VIGIL_AZURE_FEDERATED_TOKEN_FILE`) instead.

## Without Terraform

Create an Ubuntu 24.04 VM (≥2 vCPU / 4 GiB) with a managed identity that has *Monitoring Reader*, allow 80/443, and
paste [`cloud-init.yaml`](cloud-init.yaml) (edited) as *Custom data*.
