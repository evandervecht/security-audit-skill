# SA-AZURE-01: Scoped role at resource group level (SAFE)
resource "azurerm_role_assignment" "reader" {
  scope                = azurerm_resource_group.app.id
  role_definition_name = "Reader"
  principal_id         = var.user_object_id
}
