# SA-AWS-01: IAM policy with wildcard actions (VULNERABLE)
# CloudFormation-style JSON policy document
resource "aws_iam_policy" "admin" {
  name   = "full-admin"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
EOF
}
