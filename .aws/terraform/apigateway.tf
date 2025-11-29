module "bw3_api" {
  source   = "./impl/apigateway"
  api_name = "auth-api-dev"

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
      method            = "POST"
      path              = "/get-plaid-link"
      lambda_name       = module.plaid_create_link_lambda.function_name
      lambda_invoke_arn = module.plaid_create_link_lambda.invoke_arn
    },
    {
      method            = "OPTIONS"
      path              = "/get-plaid-link"
      lambda_name       = module.plaid_create_link_lambda.function_name
      lambda_invoke_arn = module.plaid_create_link_lambda.invoke_arn
    },
    {
      method            = "POST"
      path              = "/exchange-plaid-token"
      lambda_name       = module.plaid_exchange_token_lambda.function_name
      lambda_invoke_arn = module.plaid_exchange_token_lambda.invoke_arn
    },
    {
      method            = "OPTIONS"
      path              = "/exchange-plaid-token"
      lambda_name       = module.plaid_exchange_token_lambda.function_name
      lambda_invoke_arn = module.plaid_exchange_token_lambda.invoke_arn
    },
    {
      method            = "POST"
      path              = "/get-account-details"
      lambda_name       = module.plaid_get_account_details_lambda.function_name
      lambda_invoke_arn = module.plaid_get_account_details_lambda.invoke_arn
    },
    {
      method            = "OPTIONS"
      path              = "/get-account-details"
      lambda_name       = module.plaid_get_account_details_lambda.function_name
      lambda_invoke_arn = module.plaid_get_account_details_lambda.invoke_arn
    },
  ]
}

