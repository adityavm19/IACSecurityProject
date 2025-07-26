# Configure the Azure provider, you can have many
# if you use azurerm provider, it's source is hashicorp/azurerm
# short for registry.terraform.io/hashicorp/azurerm


terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
    }
  }

}
# configures the provider

provider "azurerm" {
  features {}
  
  subscription_id = var.subscription_id
}