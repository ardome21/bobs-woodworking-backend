module "bw3_api" {
  source   = "./impl/apigateway"
  api_name = "bw3-api-dev"

  routes = [
    {
      method            = "POST"
      path              = "/login"
      lambda_name       = module.login_lambda.function_name
      lambda_invoke_arn = module.login_lambda.invoke_arn
    },
    {
      method            = "GET"
      path              = "/login"
      lambda_name       = module.login_lambda.function_name
      lambda_invoke_arn = module.login_lambda.invoke_arn
    },
    {
      method            = "OPTIONS"
      path              = "/login"
      lambda_name       = module.login_lambda.function_name
      lambda_invoke_arn = module.login_lambda.invoke_arn
    },
    {
      method            = "POST"
      path              = "/logout"
      lambda_name       = module.logout_lambda.function_name
      lambda_invoke_arn = module.logout_lambda.invoke_arn
    },
    {
      method            = "OPTIONS"
      path              = "/logout"
      lambda_name       = module.logout_lambda.function_name
      lambda_invoke_arn = module.logout_lambda.invoke_arn
    },
    {
      method            = "GET"
      path              = "/verify-account"
      lambda_name       = module.verify_account_lambda.function_name
      lambda_invoke_arn = module.verify_account_lambda.invoke_arn
    },
    {
      method            = "POST"
      path              = "/sign-up"
      lambda_name       = module.create_account_lambda.function_name
      lambda_invoke_arn = module.create_account_lambda.invoke_arn
    },
    {
      method            = "OPTIONS"
      path              = "/sign-up"
      lambda_name       = module.create_account_lambda.function_name
      lambda_invoke_arn = module.create_account_lambda.invoke_arn
    },
    {
      method            = "GET"
      path              = "/auth-and-validate"
      lambda_name       = module.auth_and_validate_lambda.function_name
      lambda_invoke_arn = module.auth_and_validate_lambda.invoke_arn
    },
    {
      method            = "POST"
      path              = "/product"
      lambda_name       = module.add_product_lambda.function_name
      lambda_invoke_arn = module.add_product_lambda.invoke_arn
    },
    {
      method            = "OPTIONS"
      path              = "/product"
      lambda_name       = module.add_product_lambda.function_name
      lambda_invoke_arn = module.add_product_lambda.invoke_arn
    },
    {
      method            = "GET"
      path              = "/products"
      lambda_name       = module.get_products_lambda.function_name
      lambda_invoke_arn = module.get_products_lambda.invoke_arn
    },
  ]
}

