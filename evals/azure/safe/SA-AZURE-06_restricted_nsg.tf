# SA-AZURE-06: NSG rule restricted to VPN CIDR (SAFE)
resource "azurerm_network_security_rule" "ssh_vpn" {
  name                        = "allow-ssh-vpn"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  destination_port_range      = "22"
  source_address_prefix       = "10.0.0.0/24"
  destination_address_prefix  = "10.0.1.0/24"
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.nsg.name
}
