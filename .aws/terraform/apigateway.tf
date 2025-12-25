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
      method            = "POST"
      path              = "/auth/guest-token"
      lambda_name       = module.create_guest_token_lambda.function_name
      lambda_invoke_arn = module.create_guest_token_lambda.invoke_arn
    },
    {
      method            = "OPTIONS"
      path              = "/auth/guest-token"
      lambda_name       = module.create_guest_token_lambda.function_name
      lambda_invoke_arn = module.create_guest_token_lambda.invoke_arn
    },
    {
      method            = "GET"
      path              = "/auth-and-validate"
      lambda_name       = module.auth_and_validate_lambda.function_name
      lambda_invoke_arn = module.auth_and_validate_lambda.invoke_arn
    },
    {
      method            = "POST"
      path              = "/products"
      lambda_name       = module.add_product_lambda.function_name
      lambda_invoke_arn = module.add_product_lambda.invoke_arn
    },
    {
      method            = "GET"
      path              = "/products"
      lambda_name       = module.get_products_lambda.function_name
      lambda_invoke_arn = module.get_products_lambda.invoke_arn
    },
    {
      method            = "OPTIONS"
      path              = "/products"
      lambda_name       = module.get_products_lambda.function_name
      lambda_invoke_arn = module.get_products_lambda.invoke_arn
    },
    {
      method            = "GET"
      path              = "/products/{id}"
      lambda_name       = module.get_products_lambda.function_name
      lambda_invoke_arn = module.get_products_lambda.invoke_arn
    },
    {
      method            = "PUT"
      path              = "/products/{id}"
      lambda_name       = module.update_product_lambda.function_name
      lambda_invoke_arn = module.update_product_lambda.invoke_arn
    },
    {
      method            = "DELETE"
      path              = "/products/{id}"
      lambda_name       = module.delete_products_lambda.function_name
      lambda_invoke_arn = module.delete_products_lambda.invoke_arn
    },
    {
      method            = "DELETE"
      path              = "/products"
      lambda_name       = module.delete_products_lambda.function_name
      lambda_invoke_arn = module.delete_products_lambda.invoke_arn
    },
    {
      method            = "OPTIONS"
      path              = "/products/{id}"
      lambda_name       = module.get_products_lambda.function_name
      lambda_invoke_arn = module.get_products_lambda.invoke_arn
    },
    # Payment routes
    {
      method            = "POST"
      path              = "/payment/create-intent"
      lambda_name       = module.create_payment_intent_lambda.function_name
      lambda_invoke_arn = module.create_payment_intent_lambda.invoke_arn
    },
    {
      method            = "OPTIONS"
      path              = "/payment/create-intent"
      lambda_name       = module.payment_options_handler_lambda.function_name
      lambda_invoke_arn = module.payment_options_handler_lambda.invoke_arn
    },
    # Cart routes
    {
      method            = "POST"
      path              = "/cart/validate"
      lambda_name       = module.validate_cart_lambda.function_name
      lambda_invoke_arn = module.validate_cart_lambda.invoke_arn
    },
    {
      method            = "OPTIONS"
      path              = "/cart/validate"
      lambda_name       = module.validate_cart_lambda.function_name
      lambda_invoke_arn = module.validate_cart_lambda.invoke_arn
    },
    # Order routes
    {
      method            = "POST"
      path              = "/orders"
      lambda_name       = module.create_order_lambda.function_name
      lambda_invoke_arn = module.create_order_lambda.invoke_arn
    },
    {
      method            = "OPTIONS"
      path              = "/orders"
      lambda_name       = module.orders_options_handler_lambda.function_name
      lambda_invoke_arn = module.orders_options_handler_lambda.invoke_arn
    },
    {
      method            = "GET"
      path              = "/orders"
      lambda_name       = module.get_user_orders_lambda.function_name
      lambda_invoke_arn = module.get_user_orders_lambda.invoke_arn
    },
    {
      method            = "GET"
      path              = "/orders/{order_id}"
      lambda_name       = module.get_order_by_id_lambda.function_name
      lambda_invoke_arn = module.get_order_by_id_lambda.invoke_arn
    },
    {
      method            = "OPTIONS"
      path              = "/orders/{order_id}"
      lambda_name       = module.orders_options_handler_lambda.function_name
      lambda_invoke_arn = module.orders_options_handler_lambda.invoke_arn
    },
    {
      method            = "POST"
      path              = "/request-admin-elevation"
      lambda_name       = module.request_admin_elevation_lambda.function_name
      lambda_invoke_arn = module.request_admin_elevation_lambda.invoke_arn
    },
    {
      method            = "POST"
      path              = "/promote-user-to-admin/{user_id}"
      lambda_name       = module.promote_user_to_admin_lambda.function_name
      lambda_invoke_arn = module.promote_user_to_admin_lambda.invoke_arn
    },
    {
      method            = "GET"
      path              = "/confirm-admin-elevation"
      lambda_name       = module.confirm_admin_elevation_lambda.function_name
      lambda_invoke_arn = module.confirm_admin_elevation_lambda.invoke_arn
    },
    {
      method            = "OPTIONS"
      path              = "/request-admin-elevation"
      lambda_name       = module.orders_options_handler_lambda.function_name
      lambda_invoke_arn = module.orders_options_handler_lambda.invoke_arn
    },
    {
      method            = "OPTIONS"
      path              = "/promote-user-to-admin/{user_id}"
      lambda_name       = module.orders_options_handler_lambda.function_name
      lambda_invoke_arn = module.orders_options_handler_lambda.invoke_arn
    },
  ]
}

