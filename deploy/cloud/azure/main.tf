# Vigil on an Azure VM — example Terraform module.
# One Ubuntu 24.04 VM with a user-assigned managed identity. Vigil's Azure connector uses it with authMode
# "managed_identity" (tokens from the VM's Instance Metadata Service — no client secret, no key file). The identity gets
# "Monitoring Reader" on each monitored subscription (read-only). NSG: 80/443 from var.web_cidrs, 22 only from
# var.ssh_cidrs (empty by default; use Azure Bastion or `az ssh vm` with Entra ID login).

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

locals {
  monitored = length(var.monitored_subscription_ids) > 0 ? var.monitored_subscription_ids : [var.subscription_id]
  tags      = merge({ app = "vigil" }, var.tags)
}

resource "azurerm_resource_group" "vigil" {
  name     = "${var.name}-rg"
  location = var.location
  tags     = local.tags
}

# ---------------------------------------------------------------- identity (keyless)
resource "azurerm_user_assigned_identity" "vigil" {
  name                = var.name
  resource_group_name = azurerm_resource_group.vigil.name
  location            = azurerm_resource_group.vigil.location
  tags                = local.tags
}

resource "azurerm_role_assignment" "monitoring_reader" {
  for_each             = toset(local.monitored)
  scope                = "/subscriptions/${each.value}"
  role_definition_name = "Monitoring Reader"
  principal_id         = azurerm_user_assigned_identity.vigil.principal_id
  principal_type       = "ServicePrincipal"
}

# ---------------------------------------------------------------- network
resource "azurerm_virtual_network" "vigil" {
  name                = var.name
  address_space       = ["10.42.0.0/16"]
  location            = azurerm_resource_group.vigil.location
  resource_group_name = azurerm_resource_group.vigil.name
  tags                = local.tags
}

resource "azurerm_subnet" "vigil" {
  name                 = "vigil"
  resource_group_name  = azurerm_resource_group.vigil.name
  virtual_network_name = azurerm_virtual_network.vigil.name
  address_prefixes     = ["10.42.1.0/24"]
}

resource "azurerm_network_security_group" "vigil" {
  name                = var.name
  location            = azurerm_resource_group.vigil.location
  resource_group_name = azurerm_resource_group.vigil.name
  tags                = local.tags

  security_rule {
    name                       = "web"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["80", "443"]
    source_address_prefixes    = var.web_cidrs
    destination_address_prefix = "*"
  }

  dynamic "security_rule" {
    for_each = length(var.ssh_cidrs) > 0 ? [1] : []
    content {
      name                       = "ssh"
      priority                   = 110
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "22"
      source_address_prefixes    = var.ssh_cidrs
      destination_address_prefix = "*"
    }
  }
}

resource "azurerm_public_ip" "vigil" {
  name                = var.name
  location            = azurerm_resource_group.vigil.location
  resource_group_name = azurerm_resource_group.vigil.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_network_interface" "vigil" {
  name                = var.name
  location            = azurerm_resource_group.vigil.location
  resource_group_name = azurerm_resource_group.vigil.name
  tags                = local.tags
  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.vigil.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vigil.id
  }
}

resource "azurerm_network_interface_security_group_association" "vigil" {
  network_interface_id      = azurerm_network_interface.vigil.id
  network_security_group_id = azurerm_network_security_group.vigil.id
}

# ---------------------------------------------------------------- VM
resource "azurerm_linux_virtual_machine" "vigil" {
  name                            = var.name
  resource_group_name             = azurerm_resource_group.vigil.name
  location                        = azurerm_resource_group.vigil.location
  size                            = var.vm_size
  admin_username                  = var.admin_username
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.vigil.id]
  tags                            = local.tags

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.ssh_public_key
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.vigil.id]
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_size_gb         = var.disk_gb
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = var.architecture == "arm64" ? "server-arm64" : "server"
    version   = "latest" # the OS image only; Vigil itself is pinned by var.vigil_version
  }

  custom_data = base64encode(templatefile("${path.module}/../cloud-init.yaml.tftpl", {
    vigil_version     = var.vigil_version
    get_sh_sha256     = var.get_sh_sha256
    admin_email       = var.admin_email
    admin_name        = var.admin_name
    org_name          = var.org_name
    domain            = var.domain
    acme_email        = var.acme_email
    aws_principal_arn = ""
  }))

  lifecycle {
    ignore_changes = [custom_data]
  }

  depends_on = [azurerm_role_assignment.monitoring_reader]
}

# ---------------------------------------------------------------- DNS (optional)
resource "azurerm_dns_a_record" "vigil" {
  count               = var.domain != "" && var.dns_zone_name != "" ? 1 : 0
  name                = trimsuffix(var.domain, ".${var.dns_zone_name}")
  zone_name           = var.dns_zone_name
  resource_group_name = var.dns_zone_resource_group
  ttl                 = 300
  records             = [azurerm_public_ip.vigil.ip_address]
}
