module "login_lambda" {
  source               = "./impl/lambda"
  lambda_name          = "bw3-login-dev"
  source_file          = "../../lambdas/auth/Login/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [ aws_lambda_layer_version.utils_layer.arn ]
}

module "logout_lambda" {
  source               = "./impl/lambda"
  lambda_name          = "bw3-logout-dev"
  source_file          = "../../lambdas/auth/Logout/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [ aws_lambda_layer_version.utils_layer.arn ]
}

module "verify_account_lambda" {
  source               = "./impl/lambda"
  lambda_name          = "bw3-verify-account-dev"
  source_file          = "../../lambdas/auth/VerifyAccount/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [ aws_lambda_layer_version.utils_layer.arn ]
}

module "create_account_lambda" {
  source               = "./impl/lambda"
  lambda_name          = "bw3-create-account-dev"
  source_file          = "../../lambdas/auth/CreateAccount/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [ aws_lambda_layer_version.utils_layer.arn ]
}

module "auth_and_validate_lambda" {
  source               = "./impl/lambda"
  lambda_name          = "bw3-auth-and-validate-dev"
  source_file          = "../../lambdas/test/AuthAndValidate/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [ aws_lambda_layer_version.utils_layer.arn ]
}

module "add_product_lambda" {
  source               = "./impl/lambda"
  lambda_name          = "bw3-add-product-dev"
  source_file          = "../../lambdas/products/AddProduct/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [ aws_lambda_layer_version.utils_layer.arn ]
}

module "get_products_lambda" {
  source               = "./impl/lambda"
  lambda_name          = "bw3-get-products-dev"
  source_file          = "../../lambdas/products/GetProducts/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [ aws_lambda_layer_version.utils_layer.arn ]
}