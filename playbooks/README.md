# SOAR playbooks (Logic Apps)

Each playbook starts from a **Microsoft Sentinel incident trigger**, acts on the incident's entities, and writes
what it did back to the incident as a comment. They authenticate with a **system-assigned managed identity**,
so there are no stored secrets (except the third-party AbuseIPDB key).

| Playbook | Entities | Action | Permissions for the managed identity |
|---|---|---|---|
| `Revoke-EntraUserSessions` | Account | Revoke sign-in sessions, optionally disable the account | Graph `User.RevokeSessions.All`, `User.EnableDisableAccount.All` (+ `User.ReadWrite.All` to disable) |
| `Isolate-MDEDevice` | Host | Isolate the device in Defender for Endpoint | WindowsDefenderATP `Machine.Isolate`, `Machine.Read.All` |
| `Enrich-IPAbuseIPDB` | IP | AbuseIPDB reputation added as an incident comment | none beyond the comment permission |

All three also need **Microsoft Sentinel Responder** on the workspace resource group (to add comments), and the
Sentinel service needs **Microsoft Sentinel Automation Contributor** on the playbook resource group to run them.

## Deploy

```bash
az deployment group create -g rg-secops -f playbooks/Revoke-EntraUserSessions.json -p PlaybookName=pb-revoke-sessions
az deployment group create -g rg-secops -f playbooks/Isolate-MDEDevice.json      -p PlaybookName=pb-isolate-device
az deployment group create -g rg-secops -f playbooks/Enrich-IPAbuseIPDB.json     -p PlaybookName=pb-enrich-ip AbuseIPDBKey=<key>
```

## Grant API permissions to a playbook's managed identity

```powershell
# Requires Microsoft.Graph PowerShell and a Privileged Role Administrator
Connect-MgGraph -Scopes AppRoleAssignment.ReadWrite.All, Application.Read.All
$mi   = Get-MgServicePrincipal -Filter "displayName eq 'pb-revoke-sessions'"
$api  = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"   # Microsoft Graph
foreach ($perm in 'User.RevokeSessions.All', 'User.EnableDisableAccount.All') {
    $role = $api.AppRoles | Where-Object Value -eq $perm
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $mi.Id -PrincipalId $mi.Id -ResourceId $api.Id -AppRoleId $role.Id
}
# Defender for Endpoint API (WindowsDefenderATP): appId fc780465-2017-40d4-a0c5-307022471b92, role Machine.Isolate
```

## Wire to analytics rules

Create an automation rule: *When incident is created* > *Analytics rule name contains* "Password spray" or
"Privileged Entra ID role" > *Run playbook* `pb-revoke-sessions`. Keep `DisableAccount = false` for automatic
runs and use `true` only for manual, analyst-approved runs.

Every playbook comments on the incident on success and on failure, so the SOC always sees the outcome.
