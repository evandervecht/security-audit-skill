# SA-AZURE-03: Public blob access enabled (VULNERABLE)
resource "azurerm_storage_account" "main" {
  name                            = "storageaccount"
  resource_group_name             = azurerm_resource_group.rg.name
  location                        = "eastus"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
}
