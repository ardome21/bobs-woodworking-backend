resource "aws_lambda_layer_version" "jwt_layer" {
  layer_name          = "bw3-jwt-layer"
  description         = "JWT library for password hashing"
  compatible_runtimes = ["python3.11"]
  filename            = "../../layers/output/jwt_layer.zip"
  source_code_hash = filebase64sha256("../../layers/output/jwt_layer.zip")
}

resource "aws_lambda_layer_version" "utils_layer" {
  layer_name          = "bw3-utils-layer"
  description         = "Utility functions for Lambda functions"
  compatible_runtimes = ["python3.11"]
  filename            = "../../layers/output/utils_layer.zip"
  source_code_hash = filebase64sha256("../../layers/output/utils_layer.zip")
}

resource "aws_lambda_layer_version" "multipart_layer" {
  layer_name          = "bw3-multipart-layer"
  description         = "Multipart form-data parser for Lambda functions"
  compatible_runtimes = ["python3.11"]
  filename            = "../../layers/output/multipart_layer.zip"
  source_code_hash    = filebase64sha256("../../layers/output/multipart_layer.zip")
}
