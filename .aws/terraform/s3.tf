module "bw3_images_bucket" {
  source      = "./impl/s3"
  bucket_name = "bw3-images-dev"
  environment = "dev"
  enable_versioning = true
  enable_cors = true
  cors_allowed_origins = ["*"]
}