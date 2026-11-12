# Vigil on AWS EC2

## Terraform

```bash
cd deploy/cloud/aws
cat > terraform.tfvars <<'EOF'
region        = "us-east-1"
vigil_version = "0.1.0"
admin_email   = "you@example.com"
admin_name    = "Your Name"
org_name      = "Example Org"
domain        = "vigil.example.com"     # optional; empty = no HTTPS proxy, use SSM port forwarding
acme_email    = "you@example.com"       # optional
route53_zone_id = "Z0123456789ABC"      # optional; otherwise create the A record for output public_ip yourself
EOF
terraform init && terraform apply
```

Creates a VPC with one public subnet, a security group (80/443 from `web_cidrs`, 22 only from `ssh_cidrs` — empty by
default), an IMDSv2-only Ubuntu 24.04 instance with a 50 GiB encrypted gp3 disk and an Elastic IP, and the IAM role
`vigil-connector` (instance profile). Installation takes ~5 minutes after boot; follow it with
`aws ssm start-session --target <instance_id>` and `sudo tail -f /var/log/cloud-init-output.log`.

Then read the one-time password (`terraform output initial_password_command`) and sign in at `terraform output url`.

## Identity (no access keys)

The instance profile role may only `sts:AssumeRole` into roles named `vigil-reader*` (`reader_role_name_pattern`) in
`reader_account_ids`. `VIGIL_AWS_PRINCIPAL_ARN` is set to the role ARN, so the AWS connector's onboarding page shows
customers a trust policy for exactly this principal plus a per-connection ExternalId. The instance metadata hop limit is
2 so Vigil's containers can reach IMDSv2; the SDK default credential chain picks the role up automatically.

**Connector test:** in Vigil, add an AWS connection for an account where you created `vigil-reader` from the onboarding
policy, then press *Test* — it assumes the role with the instance profile and needs no stored keys.

## Without Terraform

Launch Ubuntu 24.04 (≥2 vCPU / 4 GiB, 50 GiB gp3), attach an instance profile as above, set *Metadata response hop
limit* to 2 with IMDSv2 required, allow inbound 80/443, and paste [`cloud-init.yaml`](cloud-init.yaml) (edited) as user
data. Or SSH in and run `get.sh` directly (see the main README).
