# SA-AWS-09: Security group open to 0.0.0.0/0 (VULNERABLE)
resource "aws_security_group_rule" "ssh_open" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.web.id
}
