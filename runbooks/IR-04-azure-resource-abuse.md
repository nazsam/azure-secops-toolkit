# IR-04: Azure resource abuse (exposed services, crypto mining, secret theft)

| | |
|---|---|
| **Triggers** | NSG opened to internet, Defender for Cloud alert cluster, Key Vault mass secret read, unexpected VM or GPU deployment |
| **Severity** | High |
| **MITRE** | T1562.007, T1496, T1555.006, T1578 |

## 1. Triage

- [ ] Identify the caller (user, service principal or managed identity) and source IP from the alert.
- [ ] List everything the caller changed in the last 7 days:

```kusto
AzureActivity
| where TimeGenerated > ago(7d)
| where Caller =~ "<caller>"
| where ActivityStatusValue in~ ("Success", "Succeeded")
| summarize Operations = make_set(OperationNameValue, 50), Resources = make_set(_ResourceId, 50) by ResourceGroup
```

## 2. Contain

- [ ] Revert the risky change (delete the NSG rule, stop or deallocate unexpected VMs).
- [ ] If the caller is a service principal, remove its new credentials and rotate the rest. If a user, follow [IR-01](IR-01-compromised-identity.md).
- [ ] If Key Vault secrets were read, rotate every secret, key and certificate in the affected vaults and review Key Vault firewall and RBAC.
- [ ] Apply a resource lock or Azure Policy deny assignment to stop the change recurring.

## 3. Recover and harden

- [ ] Check Defender for Cloud recommendations and secure score for the subscription.
- [ ] Confirm Activity log, Key Vault and NSG flow logs are all flowing to Sentinel.
- [ ] Add a policy (for example "Management ports should be closed on your virtual machines") in Deny or DeployIfNotExists mode.
