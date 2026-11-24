# Bucket names are global across all of AWS, so add a random suffix
resource "random_id" "bucket" {
  byte_length = 4
}

resource "aws_s3_bucket" "code" {
  bucket        = "${var.project}-code-${random_id.bucket.hex}"
  force_destroy = true # allow terraform destroy even if files are inside
}

# Make sure nobody can ever make this bucket public
resource "aws_s3_bucket_public_access_block" "code" {
  bucket                  = aws_s3_bucket.code.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Zip the app/ folder on your Mac
data "archive_file" "app" {
  type        = "zip"
  source_dir  = "${path.module}/../app"
  output_path = "${path.module}/build/app.zip"
  excludes = [
    "__pycache__",
    "detector/__pycache__",
    "detector/checks/__pycache__",
  ]
}

# Upload the zip. The name includes the content hash,
# so any code change = a new file name = servers get replaced later
resource "aws_s3_object" "app" {
  bucket = aws_s3_bucket.code.id
  key    = "app-${data.archive_file.app.output_md5}.zip"
  source = data.archive_file.app.output_path
}

resource "aws_s3_object" "requirements" {
  bucket = aws_s3_bucket.code.id
  key    = "requirements.txt"
  source = "${path.module}/../requirements.txt"
  etag   = filemd5("${path.module}/../requirements.txt")
}