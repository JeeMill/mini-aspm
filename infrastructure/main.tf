terraform {
    required_providers {
        aws = {
            source = "hashicorp/aws"
            version = "~> 6.0"
        }
    }
}

prover "aws" {
    region = "us-east-1"
}

resource "aws_s3_bucket" "app_data" {
    bucket = "mini-aspm-demo-bucket"

    tags = {
        Name        = "mini-aspm-demo"
        Environment = "lab"
    }
}

