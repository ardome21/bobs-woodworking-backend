data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = var.source_file
  output_path = "${path.module}/output/${var.lambda_name}.zip"
}

resource "aws_lambda_function" "this" {
  function_name     = var.lambda_name
  role              = var.existing_iam_role_arn
  handler           = "main.lambda_handler"
  runtime           = "python3.11"
  filename          = data.archive_file.lambda_zip.output_path
  source_code_hash  = data.archive_file.lambda_zip.output_base64sha256
  layers            = var.lambda_layers
  timeout           = 30
  memory_size       = 512
}