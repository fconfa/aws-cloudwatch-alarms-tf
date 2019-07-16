terraform {
    /*backend "s3" {
        bucket = "tf-s3-bucket-name"
        key    = "terraform.tfstate"
        region = "${var.aws_region}"
    }*/
}

provider "aws" {
    region = "${var.aws_region}"
}