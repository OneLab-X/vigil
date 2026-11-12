output "public_ip" {
  value       = aws_eip.vigil.public_ip
  description = "Point var.domain's A record here if you did not set route53_zone_id"
}

output "url" {
  value       = var.domain != "" ? "https://${var.domain}" : "SSM port forward: aws ssm start-session --target ${aws_instance.vigil.id} --document-name AWS-StartPortForwardingSession --parameters portNumber=3000,localPortNumber=3000 → http://localhost:3000"
  description = "Where to open Vigil"
}

output "instance_id" {
  value = aws_instance.vigil.id
}

output "vigil_principal_arn" {
  value       = aws_iam_role.vigil.arn
  description = "VIGIL_AWS_PRINCIPAL_ARN — the principal customers trust in their vigil-reader role"
}

output "initial_password_command" {
  value       = "aws ssm start-session --target ${aws_instance.vigil.id}   then: sudo cat /opt/vigil/initial-owner-password && sudo rm /opt/vigil/initial-owner-password"
  description = "How to read the first owner's one-time password"
}
