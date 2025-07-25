variable "location" {
  description = "The Azure region to deploy the resources"
  type        = string
  default     = "East US"
}

variable "resource_group_name" {
  description = "The name of the Azure Resource Group"
  type        = string
}

variable "storage_account_name" {
  description = "The name of the Azure Storage Account"
  type        = string
}
