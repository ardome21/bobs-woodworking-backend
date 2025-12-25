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

module "create_guest_token_lambda" {
  source               = "./impl/lambda"
  lambda_name          = "bw3-create-guest-token-dev"
  source_file          = "../../lambdas/auth/CreateGuestToken/main.py"
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

module "delete_products_lambda" {
  source               = "./impl/lambda"
  lambda_name          = "bw3-delete-products-dev"
  source_file          = "../../lambdas/products/DeleteProducts/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [ aws_lambda_layer_version.utils_layer.arn ]
}

module "update_product_lambda" {
  source               = "./impl/lambda"
  lambda_name          = "bw3-update-product-dev"
  source_file          = "../../lambdas/products/UpdateProduct/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [ aws_lambda_layer_version.utils_layer.arn ]
}

# Payment Lambdas
module "create_payment_intent_lambda" {
  source                = "./impl/lambda"
  lambda_name           = "bw3-create-payment-intent-dev"
  source_file           = "../../lambdas/payment/CreatePaymentIntent/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [
    aws_lambda_layer_version.stripe_layer.arn
  ]
}

module "payment_options_handler_lambda" {
  source                = "./impl/lambda"
  lambda_name           = "bw3-payment-options-handler-dev"
  source_file           = "../../lambdas/payment/OptionsHandler/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = []
}

# Cart Lambdas
module "validate_cart_lambda" {
  source                = "./impl/lambda"
  lambda_name           = "bw3-validate-cart-dev"
  source_file           = "../../lambdas/cart/ValidateCart/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [ aws_lambda_layer_version.utils_layer.arn ]
}

# Order Lambdas
module "create_order_lambda" {
  source                = "./impl/lambda"
  lambda_name           = "bw3-create-order-dev"
  source_file           = "../../lambdas/orders/CreateOrder/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [
    aws_lambda_layer_version.utils_layer.arn,
    aws_lambda_layer_version.stripe_layer.arn
  ]
}

module "get_user_orders_lambda" {
  source                = "./impl/lambda"
  lambda_name           = "bw3-get-user-orders-dev"
  source_file           = "../../lambdas/orders/GetUserOrders/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [ aws_lambda_layer_version.utils_layer.arn ]
}

module "get_order_by_id_lambda" {
  source                = "./impl/lambda"
  lambda_name           = "bw3-get-order-by-id-dev"
  source_file           = "../../lambdas/orders/GetOrderById/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = [ aws_lambda_layer_version.utils_layer.arn ]
}

module "orders_options_handler_lambda" {
  source                = "./impl/lambda"
  lambda_name           = "bw3-orders-options-handler-dev"
  source_file           = "../../lambdas/orders/OptionsHandler/main.py"
  existing_iam_role_arn = var.existing_iam_role_arn
  lambda_layers         = []
}