variable "table_name" {
  description = "Name of the DynamoDB table"
  type        = string
}

variable "partition_key" {
  description = "Partition Key"
  type        = string
}

variable "sort_key" {
  description = "Sort Key"
  type        = string
  default     = null
}


variable "secondary_index_key" {
  description = "Secondary index Key"
  type        = string
  default     = null
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
}