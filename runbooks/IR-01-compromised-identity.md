# IR-01: Compromised Entra ID identity

| | |
|---|---|
| **Triggers** | Password spray, multi-country sign-in, MFA removed, Entra ID Protection high risk user, token theft alerts in Defender XDR |
| **Severity** | High (Critical if the account holds a privileged role) |
| **Automation** | `Revoke-EntraUserSessions` playbook (revoke sessions, optional disable) |
| **MITRE** | T1078.004, T1110.003, T1556.006, T1098 |

## 1. Triage (first 15 minutes)

- [ ] Open the incident in Microsoft Sentinel / Defender XDR. Confirm the account, source IPs and apps involved.
- [ ] Check whether the account holds a privileged Entra ID role or PIM eligibility. If yes, raise to **Critical** and page the on-call lead.
- [ ] Run the hunting query below and confirm the sign-ins are not a known VPN, travel or service pattern.

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ "<upn>"
| project TimeGenerated, ResultType, IPAddress, Location = tostring(LocationDetails.countryOrRegion),
          AppDisplayName, ClientAppUsed, DeviceDetail, ConditionalAccessStatus, RiskLevelDuringSignIn
| order by TimeGenerated desc
```

## 2. Containment

- [ ] Run the **Revoke-EntraUserSessions** playbook from the incident (revokes refresh tokens and sessions).
- [ ] Reset the password and require MFA re-registration (delete attacker-added methods).
- [ ] If the attacker is still active or the account is privileged, disable the account (playbook with `DisableAccount = true`).
- [ ] Block attacker IPs with a Conditional Access named location or the firewall.

## 3. Scope (what did the attacker do?)

- [ ] Audit changes made by the account: `AuditLogs | where InitiatedBy.user.userPrincipalName =~ "<upn>"`.
- [ ] Mailbox rules and forwarding: `OfficeActivity | where Operation in ("New-InboxRule","Set-InboxRule","Set-Mailbox") and UserId =~ "<upn>"`.
- [ ] OAuth consents and app credentials added (see `hunting/oauth-consent-grants.kql`, `detections/entra-app-credential-added.yaml`).
- [ ] Files downloaded or shared (`OfficeActivity` FileDownloaded, SharingSet, AnonymousLinkCreated).
- [ ] Azure resource changes (`AzureActivity | where Caller =~ "<upn>"`).

## 4. Eradication and recovery

- [ ] Remove malicious inbox rules, app consents, credentials and role assignments found in scoping.
- [ ] Re-enable the account only after the owner re-registers MFA on a trusted device.
- [ ] Add confirmed attacker IPs and domains to the IOC watchlist (`secops ioc`).

## 5. Close

- [ ] Record timeline, root cause and actions in the incident. Complete the [post-incident review](post-incident-review-template.md) for High and Critical.
- [ ] Classify the incident in Sentinel (True Positive / Benign Positive / False Positive) so analytics can be tuned.
