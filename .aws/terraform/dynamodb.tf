module "bw3_user_table" {
  source        = "./impl/dynamodb"
  table_name    = "bw3-users-dev"
  partition_key = "user_id"
  secondary_index_key = "email"
  environment   = "dev"
}

module "bw3_auth_token_table" {
  source        = "./impl/dynamodb"
  table_name    = "bw3-auth-token-dev"
  partition_key = "user_id"
  environment   = "dev"
}

module "bw3_products_table" {
  source        = "./impl/dynamodb"
  table_name    = "bw3-products-dev"
  partition_key = "product_id"
  environment   = "dev"
}