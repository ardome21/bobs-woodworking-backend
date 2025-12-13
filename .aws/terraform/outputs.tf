output "login_lambda_function_name" {
  description = "Name of the login Lambda function"
  value       = module.login_lambda.function_name
}

output "login_lambda_function_arn" {
  description = "ARN of the login Lambda function"
  value       = module.login_lambda.lambda_function_arn
}

output "api_gateway_url" {
  description = "API Gateway URL"
  value       = module.bw3_api.api_endpoint
}