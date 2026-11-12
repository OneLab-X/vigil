output "public_ip" {
  value = azurerm_public_ip.vigil.ip_address
}

output "url" {
  value = var.domain != "" ? "https://${var.domain}" : "ssh -L 3000:127.0.0.1:3000 ${var.admin_username}@${azurerm_public_ip.vigil.ip_address} (or Azure Bastion tunnel) → http://localhost:3000"
}

output "managed_identity_client_id" {
  value       = azurerm_user_assigned_identity.vigil.client_id
  description = "Azure connector: authMode managed_identity, clientId = this value"
}

output "managed_identity_principal_id" {
  value       = azurerm_user_assigned_identity.vigil.principal_id
  description = "Grant this principal Graph AuditLog.Read.All (app role) if you read Entra ID logs via Graph"
}

output "tenant_id" {
  value = azurerm_user_assigned_identity.vigil.tenant_id
}
