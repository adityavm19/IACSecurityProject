terraform {
   backend "azurerm" {
        resource_group_name = "terraform-state"
        storage_account_name = "terraformpipelinebackend"
        container_name = "main-tfstate"
        key = "main.terraform.tfstate"
     
   }
}