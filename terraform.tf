terraform {
    /*backend "s3" {
        bucket = "terraform-artifacts-bucket"
        key    = "cloudwatch-demo/terraform.tfstate"
        region = "${var.aws_region}"
    }*/
}

provider "aws" {
    region = "${var.aws_region}"
}