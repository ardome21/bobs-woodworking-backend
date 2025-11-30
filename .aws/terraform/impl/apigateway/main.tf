resource "aws_apigatewayv2_api" "this" {
  name          = var.api_name
  protocol_type = "HTTP"
  description   = "Shared API Gateway"

  cors_configuration {
    allow_origins     = ["http://localhost:4200", "https://bobs-woodworking.com"]
    allow_credentials = true
    allow_methods     = ["POST", "GET", "OPTIONS"]
    allow_headers     = ["content-type", "authorization"]
    max_age           = 86400
  }

  tags = {
    Name        = var.api_name
    Environment = "dev"
  }
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.this.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_rate_limit  = 100
    throttling_burst_limit = 50
  }

  tags = {
    Name        = "${var.api_name}-default-stage"
    Environment = "dev"
  }
}

resource "aws_apigatewayv2_integration" "lambda_integration" {
  for_each = {
    for route in var.routes : "${route.method} ${route.path}" => route
  }

  api_id                  = aws_apigatewayv2_api.this.id
  integration_type        = "AWS_PROXY"
  integration_uri         = each.value.lambda_invoke_arn
  payload_format_version  = "2.0"
  timeout_milliseconds    = 30000
}

resource "aws_apigatewayv2_route" "routes" {
  for_each = {
    for route in var.routes : "${route.method} ${route.path}" => route
  }

  api_id    = aws_apigatewayv2_api.this.id
  route_key = each.key
  target    = "integrations/${aws_apigatewayv2_integration.lambda_integration[each.key].id}"
}

resource "aws_lambda_permission" "api_invoke" {
  for_each = {
    for route in var.routes : "${route.method} ${route.path}" => route
  }

  statement_id  = "AllowInvoke-${replace(replace(each.key, " ", "-"), "/", "-")}"
  action        = "lambda:InvokeFunction"
  function_name = each.value.lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.this.execution_arn}/*/*"
}
