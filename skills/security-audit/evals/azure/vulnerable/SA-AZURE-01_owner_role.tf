# SA-AZURE-01: Owner role at subscription scope (VULNERABLE)
resource "azurerm_role_assignment" "admin" {
  scope                = data.azurerm_subscription.primary.id
  role_definition_name = "Owner"
  principal_id         = var.user_object_id
}
