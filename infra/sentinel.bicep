// Log Analytics workspace with Microsoft Sentinel enabled.
// Deploy: az deployment group create -g rg-secops -f infra/sentinel.bicep -p workspaceName=law-secops

@description('Name of the Log Analytics workspace that hosts Microsoft Sentinel')
param workspaceName string

@description('Azure region')
param location string = resourceGroup().location

@description('Interactive retention in days')
@minValue(30)
@maxValue(730)
param retentionInDays int = 90

@description('Daily ingestion cap in GB, -1 for no cap')
param dailyQuotaGb int = -1

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    workspaceCapping: {
      dailyQuotaGb: dailyQuotaGb
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = {
  scope: workspace
  name: 'default'
  properties: {}
}

output workspaceId string = workspace.id
output workspaceName string = workspace.name
