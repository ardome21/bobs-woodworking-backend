variable "lambda_name" {}
variable "source_file" {}
variable "existing_iam_role_arn" {}
variable "lambda_layers" {
  type    = list(string)
  default = [aws_lambda_layer_version.utils_layer.arn]
}