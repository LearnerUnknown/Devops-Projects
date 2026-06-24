provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "app-rg" {
  name     = "myapp-production-rg"
  location = "East US"
}

resource "azurerm_virtual_network" "appVnet" {
  name                = "myapp-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.app-rg.location
  resource_group_name = azurerm_resource_group.app-rg.name
}

resource "azurerm_subnet" "app_subnet" {
  name                 = "myapp-subnet"
  resource_group_name  = azurerm_resource_group.app-rg.name
  virtual_network_name = azurerm_virtual_network.appVnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_kubernetes_cluster" "aks" {
  name                = "myapp-aks-cluster"
  location            = azurerm_resource_group.app-rg.location
  resource_group_name = azurerm_resource_group.app-rg.name
  dns_prefix          = "myapp"

  default_node_pool {
    name       = "default"
    node_count = 2
    vm_size    = "Standard_DS2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_container_registry" "acr" {
  name                = "myappacr"
  resource_group_name = azurerm_resource_group.app-rg.name
  location            = azurerm_resource_group.app-rg.location
  sku                 = "Standard"
  admin_enabled       = true
}

resource "azurerm_mssql_server" "sql" {
  name                         = "myapp-sql-server"
  resource_group_name          = azurerm_resource_group.app-rg.name
  location                     = azurerm_resource_group.app-rg.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd!2024"
}
