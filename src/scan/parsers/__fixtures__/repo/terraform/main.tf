resource "aws_s3_bucket" "data" {
  bucket = "demo-data"
}

resource "aws_security_group" "open" {
  name = "open"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
