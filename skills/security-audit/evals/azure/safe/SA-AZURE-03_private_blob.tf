# SA-AZURE-03: Private blob access (SAFE)
resource "azurerm_storage_account" "main" {
  name                            = "storageaccount"
  resource_group_name             = azurerm_resource_group.rg.name
  location                        = "eastus"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = false
  min_tls_version                 = "TLS1_2"
}
