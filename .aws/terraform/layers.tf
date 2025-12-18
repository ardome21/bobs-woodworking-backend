resource "aws_lambda_layer_version" "utils_layer" {
  layer_name          = "bw3-utils-layer"
  description         = "Utility functions for Lambda functions"
  compatible_runtimes = ["python3.11"]
  filename            = "../../layers/output/utils_layer.zip"
  source_code_hash = filebase64sha256("../../layers/output/utils_layer.zip")
}

resource "aws_lambda_layer_version" "stripe_layer" {
  layer_name          = "bw3-stripe-layer"
  description         = "Stripe Python SDK for payment processing"
  compatible_runtimes = ["python3.11"]
  filename            = "../../layers/output/stripe_layer.zip"
  source_code_hash    = filebase64sha256("../../layers/output/stripe_layer.zip")
}
