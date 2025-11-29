terraform {
  backend "s3" {
    bucket         = "8386-bw3-terraform-state"
    key            = "lambda-api/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "bw3-terraform-locks"
  }
}
