# Vigil on AWS EC2 — example Terraform module.
# One Ubuntu 24.04 VM in a dedicated VPC, encrypted gp3 disk, Elastic IP, security group with 80/443 (+22 only from
# var.ssh_cidrs; SSM Session Manager is the default way in) and an instance profile whose role can only
# sts:AssumeRole into customer reader roles. Vigil's AWS connector uses that role through the SDK default chain
# (IMDSv2) — no access keys anywhere.

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_availability_zones" "available" { state = "available" }

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720108477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-${var.architecture == "arm64" ? "arm64" : "amd64"}-server-*"]
  }
}

locals {
  name = var.name
  tags = merge({ "app" = "vigil", "vigil:name" = var.name }, var.tags)
}

# ---------------------------------------------------------------- network
resource "aws_vpc" "this" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = local.name })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = local.tags
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.this.id
  cidr_block        = "10.42.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags              = merge(local.tags, { Name = "${local.name}-public" })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = local.tags
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "vigil" {
  name        = local.name
  description = "Vigil: HTTP/HTTPS from the internet, SSH only from admin CIDRs"
  vpc_id      = aws_vpc.this.id
  tags        = local.tags
}

resource "aws_vpc_security_group_ingress_rule" "http" {
  for_each          = toset(var.web_cidrs)
  security_group_id = aws_security_group.vigil.id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  description       = "HTTP (ACME challenge + redirect to HTTPS)"
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  for_each          = toset(var.web_cidrs)
  security_group_id = aws_security_group.vigil.id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "HTTPS"
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  for_each          = toset(var.ssh_cidrs)
  security_group_id = aws_security_group.vigil.id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  description       = "SSH from admin networks"
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.vigil.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "Cloud APIs, model provider, image registry, ACME"
}

# ---------------------------------------------------------------- identity (keyless)
data "aws_iam_policy_document" "ec2_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "vigil" {
  name               = "${local.name}-connector"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
  tags               = local.tags
}

# The only thing Vigil's own role may do: assume the read-only roles customers create from Vigil's onboarding
# trust policy (role name pattern + ExternalId enforced on their side).
data "aws_iam_policy_document" "assume_readers" {
  statement {
    actions   = ["sts:AssumeRole"]
    resources = [for a in var.reader_account_ids : "arn:${data.aws_partition.current.partition}:iam::${a}:role/${var.reader_role_name_pattern}"]
  }
}

resource "aws_iam_role_policy" "assume_readers" {
  name   = "assume-vigil-reader-roles"
  role   = aws_iam_role.vigil.id
  policy = data.aws_iam_policy_document.assume_readers.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  count      = var.enable_ssm ? 1 : 0
  role       = aws_iam_role.vigil.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "vigil" {
  name = "${local.name}-connector"
  role = aws_iam_role.vigil.name
}

# ---------------------------------------------------------------- VM
resource "aws_instance" "vigil" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.vigil.id]
  iam_instance_profile   = aws_iam_instance_profile.vigil.name
  key_name               = var.ssh_key_name

  metadata_options {
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 2          # containers sit one network hop behind the host
    http_endpoint               = "enabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.disk_gb
    encrypted             = true
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/../cloud-init.yaml.tftpl", {
    vigil_version     = var.vigil_version
    get_sh_sha256     = var.get_sh_sha256
    admin_email       = var.admin_email
    admin_name        = var.admin_name
    org_name          = var.org_name
    domain            = var.domain
    acme_email        = var.acme_email
    aws_principal_arn = aws_iam_role.vigil.arn
  })
  user_data_replace_on_change = false

  tags = merge(local.tags, { Name = local.name })

  lifecycle {
    ignore_changes = [ami, user_data] # upgrades happen in place with `vigil upgrade`, not by replacing the VM
  }
}

resource "aws_eip" "vigil" {
  instance = aws_instance.vigil.id
  domain   = "vpc"
  tags     = local.tags
}

# ---------------------------------------------------------------- DNS (optional)
resource "aws_route53_record" "vigil" {
  count   = var.domain != "" && var.route53_zone_id != "" ? 1 : 0
  zone_id = var.route53_zone_id
  name    = var.domain
  type    = "A"
  ttl     = 300
  records = [aws_eip.vigil.public_ip]
}
