# Cloud quickstarts

Vigil does not ship per-cloud machine images. Every cloud uses the same path: a stock Ubuntu 24.04 VM, a
`cloud-init` user-data script that downloads `get.sh` for a **pinned release**, verifies it against that release's
`SHA256SUMS`, and runs it non-interactively. The VM's own cloud identity is what Vigil's connector for that cloud uses —
no access keys, service-account key files or client secrets are created or prompted for.

| Cloud | Folder | Identity Vigil uses | Connector setting |
|---|---|---|---|
| AWS EC2 | [aws/](aws/) | Instance profile role `<name>-connector` (IMDSv2, hop limit 2) that may only `sts:AssumeRole` into customer `vigil-reader*` roles | AWS connector (STS AssumeRole + ExternalId); `VIGIL_AWS_PRINCIPAL_ARN` is set to the role ARN |
| Google Compute Engine | [gcp/](gcp/) | Attached service account `<name>-vm@…` with `roles/logging.viewer` (+ `privateLogViewer` optional) on monitored projects | GCP connector, auth mode **Application Default Credentials** |
| Azure VM | [azure/](azure/) | User-assigned managed identity with **Monitoring Reader** on monitored subscriptions | Azure connector, auth mode **Managed identity**, client ID = Terraform output |

Each folder has:

- `cloud-init.yaml` — paste as user data / custom data in the console (edit the `CHANGE_ME` values);
- a Terraform example (`main.tf`, `variables.tf`, `outputs.tf`) that creates the network, firewall, VM, disk, static IP,
  identity and (optionally) the DNS record, and renders the same cloud-init from [`cloud-init.yaml.tftpl`](cloud-init.yaml.tftpl);
- a README with the steps.

## Sizing

| | Minimum | Recommended |
|---|---|---|
| vCPU | 2 | 4 |
| Memory | 4 GiB | 8 GiB |
| Disk | 30 GiB | 50 GiB+, sized for evidence retention |

Defaults: AWS `c6i.xlarge`, GCP `e2-standard-4`, Azure `Standard_F4s_v2`. `get.sh`'s preflight fails below 3 GiB of
memory available to Docker and warns below the recommended size.

## Network

Inbound: **80** and **443** only (80 is needed for Let's Encrypt HTTP validation and the HTTPS redirect). SSH is closed by
default — use AWS SSM Session Manager, GCP IAP TCP forwarding, or Azure Bastion — or open 22 to specific admin CIDRs.
Postgres, the API, the agents and the object store are never published; without a domain the UI listens on
`127.0.0.1:3000` only and you reach it through an SSH/SSM/IAP tunnel.

## First login

The first owner's one-time password is written to `/opt/vigil/initial-owner-password` (root-only) — not to the
cloud-init log. Read it over SSM/IAP/Bastion, sign in, change the password, then delete the file. Each Terraform module
has an `initial_password_command` (or equivalent) output.

## Managed database and object storage

- **Evidence storage on S3 / S3-compatible services:** supported today via `VIGIL_S3_ENDPOINT`, `VIGIL_S3_REGION`,
  `VIGIL_S3_BUCKET`, `VIGIL_S3_ACCESS_KEY` and `VIGIL_S3_SECRET_KEY` in `/opt/vigil/.env` (see
  [docs/SELF_HOSTING.md](../../docs/SELF_HOSTING.md)). On AWS, clearing the two key variables makes the SDK fall back to
  the instance profile — grant the role `s3:GetObject`, `s3:PutObject`, `s3:ListBucket` and `s3:GetBucketVersioning` /
  `s3:PutBucketVersioning` on the bucket. *This keyless S3 path has not been live-tested yet.* Google Cloud Storage works
  through its S3 interoperability API, but that requires HMAC keys (long-lived) — the bundled store is the keyless
  default on GCP. Azure Blob Storage has no native adapter yet; keep the bundled store on Azure.
- **Managed PostgreSQL (RDS, Cloud SQL, Azure Database for PostgreSQL):** not supported by the Compose install yet. Vigil
  needs PostgreSQL 17 with `pgvector` and `pgcrypto`, a migration role with `BYPASSRLS` and an application role with
  `NOBYPASSRLS` (row-level security is the tenant boundary), and the bundled compose file always runs its own Postgres.
  Use the bundled database with regular `vigil backup` (and disk snapshots) for now.
