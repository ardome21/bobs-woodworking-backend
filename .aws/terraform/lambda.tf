  module "login_lambda" {
  source               = "./impl/lambda"
  lambda_name          = "bw3-login-dev"
  source_file          = "../../lambdas/auth/Login/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [aws_lambda_layer_version.jwt_layer.arn]
}

  module "logout_lambda" {
  source               = "./impl/lambda"
  lambda_name          = "bw3-logout-dev"
  source_file          = "../../lambdas/auth/Logout/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [aws_lambda_layer_version.jwt_layer.arn]
}

  module "verify_account_lambda" {
  source               = "./impl/lambda"
  lambda_name          = "bw3-verify-account-dev"
  source_file          = "../../lambdas/auth/VerifyAccount/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [aws_lambda_layer_version.jwt_layer.arn]
}

  module "create_account_lambda" {
  source               = "./impl/lambda"
  lambda_name          = "bw3-create-account-dev"
  source_file          = "../../lambdas/auth/CreateAccount/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [aws_lambda_layer_version.jwt_layer.arn]
}