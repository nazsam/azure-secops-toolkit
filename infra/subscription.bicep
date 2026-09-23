// Subscription-level security baseline:
//  - Microsoft Defender for Cloud plans
//  - Azure Activity log streamed to the Sentinel workspace
// Deploy: az deployment sub create -l canadacentral -f infra/subscription.bicep -p workspaceId=<resource id>

targetScope = 'subscription'

@description('Resource ID of the Sentinel Log Analytics workspace')
param workspaceId string

@description('Defender for Cloud plans to enable on the Standard tier')
param defenderPlans array = [
  'VirtualMachines'
  'StorageAccounts'
  'KeyVaults'
  'Arm'
  'SqlServers'
  'Containers'
  'AppServices'
  'CloudPosture'
]

@batchSize(1)
resource plans 'Microsoft.Security/pricings@2024-01-01' = [for plan in defenderPlans: {
  name: plan
  properties: {
    pricingTier: 'Standard'
  }
}]

resource activityLog 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'activity-to-sentinel'
  properties: {
    workspaceId: workspaceId
    logs: [for category in [
      'Administrative'
      'Security'
      'ServiceHealth'
      'Alert'
      'Recommendation'
      'Policy'
      'Autoscale'
      'ResourceHealth'
    ]: {
      category: category
      enabled: true
    }]
  }
}
