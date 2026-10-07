# SA-AWS-09: Security group restricted to VPN CIDR (SAFE)
resource "aws_security_group_rule" "ssh_vpn" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/24"]
  security_group_id = aws_security_group.web.id
}
