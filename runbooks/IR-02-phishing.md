# IR-02: Phishing email and payload

| | |
|---|---|
| **Triggers** | User report, Defender for Office 365 alert, `hunting/rare-parent-child-process.kql`, encoded PowerShell detection |
| **Severity** | Medium (High if credentials were entered or a payload executed) |
| **Automation** | `Enrich-IPAbuseIPDB`, `Isolate-MDEDevice`, `secops ioc` |
| **MITRE** | T1566.001, T1566.002, T1204.002, T1059.001 |

## 1. Triage

- [ ] Get the message: sender, subject, NetworkMessageId, URLs and attachments.
- [ ] Extract indicators from the email or report: `secops ioc report.txt --source phishing > iocs.csv`.
- [ ] Find every recipient and who clicked:

```kusto
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress =~ "<sender>" or Subject has "<subject>"
| join kind=leftouter (UrlClickEvents | project NetworkMessageId, ClickedUrl = Url, ActionType, ClickUser = AccountUpn) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, DeliveryAction, ThreatTypes, ClickedUrl, ActionType, ClickUser
```

## 2. Containment

- [ ] Soft-delete the message from all mailboxes (Defender XDR: Email entity > Take action > Soft delete), or `New-ComplianceSearchAction -Purge`.
- [ ] Block the sender, domain and URLs in the Tenant Allow/Block List.
- [ ] For users who entered credentials, follow [IR-01](IR-01-compromised-identity.md).
- [ ] For devices where a payload ran, run `Isolate-MDEDevice` and follow [IR-03](IR-03-malware-ransomware.md).

## 3. Recovery and lessons

- [ ] Upload the IOC CSV as a Sentinel watchlist so future matches alert.
- [ ] Send a short awareness note to affected teams with the real example (redacted).
- [ ] Record the incident and tune mail flow rules if the message bypassed filtering.
