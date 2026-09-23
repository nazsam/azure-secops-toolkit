# Tabletop exercise: privileged identity takeover

**Duration:** 90 minutes. **Participants:** SecOps, identity team, cloud platform team, IT service desk, communications.
**Goal:** test [IR-01](IR-01-compromised-identity.md) and [IR-04](IR-04-azure-resource-abuse.md), decision rights and communication.

## Scenario

| Inject | Time | What the facilitator reveals |
|---|---|---|
| 1 | 0:00 | Sentinel raises "Entra ID password spray from a single IP" against 40 accounts. One sign-in succeeded for a cloud engineer. |
| 2 | 0:15 | The same account removed its MFA method and registered a new authenticator app from another country. |
| 3 | 0:30 | "Privileged Entra ID role assigned": the account added itself to Application Administrator, then added a secret to a production app registration. |
| 4 | 0:45 | Defender for Cloud: new NSG rule opened RDP to the internet; three GPU VMs are deploying. Key Vault mass secret read alert fires. |
| 5 | 1:00 | A journalist emails asking about "a breach at your organisation". |

## Discussion questions

1. Who can approve disabling a privileged engineer's account at 2 a.m.?
2. Which playbooks run automatically, and which need a human decision?
3. How do we confirm what the app registration's new secret was used for?
4. When do we notify the privacy office, the client and CCCS?
5. Which detections fired late or not at all? What would have caught inject 1 sooner?

## Scoring

For each inject record: time to decision, correct runbook step (yes/no), gaps found, owner for the fix.
