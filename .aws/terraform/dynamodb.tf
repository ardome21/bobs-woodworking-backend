module "bw3_user_table" {
  source        = "./impl/dynamodb"
  table_name    = "bw3-users-dev"
  partition_key = "user_id"
  secondary_index_key = "email"
  environment   = "dev"
}

module "bw3_plaid_connections_table" {
  source        = "./impl/dynamodb"
  table_name    = "bw3-plaid-connections-dev"
  partition_key = "user_id"
  sort_key      = "item_id"
  secondary_index_key = "email"
  environment   = "dev"
}

module "bw3_auth_token_table" {
  source        = "./impl/dynamodb"
  table_name    = "bw3-auth-token-dev"
  partition_key = "user_id"
  environment   = "dev"
}