# SA-AWS-05: S3 bucket with public ACL (VULNERABLE)
resource "aws_s3_bucket" "data" {
  bucket = "user-uploads"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}
