locals {
  index_name = var.secondary_index_key != null ? (
    "${var.secondary_index_key}-index"
    ):  null
}

resource "aws_dynamodb_table" "this" {
  name           = var.table_name
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = var.partition_key
  range_key      = var.sort_key

  attribute {
    name = var.partition_key
    type = "S"
  }

  dynamic "attribute" {
    for_each = var.sort_key != null ? [1] : []
    content {
      name = var.sort_key
      type = "S"
    }
  }

  dynamic "attribute" {
    for_each = var.secondary_index_key != null ? [1] : []
    content {
      name = var.secondary_index_key
      type = "S"
    }
  }

  dynamic "global_secondary_index" {
    for_each = var.secondary_index_key != null ? [1] : []
    content {
      name            = local.index_name
      hash_key        = var.secondary_index_key
      projection_type = "ALL"
    }
  }

  tags = {
    Environment = var.environment
  }
}