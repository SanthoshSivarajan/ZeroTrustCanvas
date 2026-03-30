# ZeroTrustCanvas

### Assess Your Zero Trust Security Posture

**Author:** Santhosh Sivarajan, Microsoft MVP
**GitHub:** [https://github.com/SanthoshSivarajan/ZeroTrustCanvas](https://github.com/SanthoshSivarajan/ZeroTrustCanvas)
**Reference:** [Microsoft Zero Trust Assessment Framework](https://learn.microsoft.com/en-us/security/zero-trust/assessment/overview)

---

## Overview

ZeroTrustCanvas is a cross-product security posture assessment tool that evaluates your Microsoft 365 environment against the **six Zero Trust pillars**. It pulls from Entra ID, Intune, Defender, and Purview via Microsoft Graph, scores each pillar, identifies gaps, and provides actionable recommendations.

This is not just documentation -- it's an **assessment with maturity scoring**.

## What Makes This Different

| Feature | ADCanvas / EntraIDCanvas / IntuneCanvas | ZeroTrustCanvas |
|---|---|---|
| Purpose | Document configuration | **Assess security posture** |
| Output | Inventory tables and charts | **Maturity scores, gap analysis, recommendations** |
| Scope | Single product | **Cross-product (Entra + Intune + Defender + Purview)** |
| Scoring | None | **Per-pillar % score with Traditional/Advanced/Optimal maturity** |

## The Six Zero Trust Pillars

### 1. Identity (Entra ID)
- MFA enforcement via Conditional Access or Security Defaults
- Global Admin count (recommended 2-5)
- Legacy authentication blocking
- Named locations for network-based policies
- Guest user ratio
- Risky users detection (Identity Protection)
- Authentication methods policy
- Directory synchronization status

### 2. Devices (Intune)
- Device compliance rate
- Device encryption rate (BitLocker/FileVault)
- Compliance policies deployed
- Configuration profiles deployed
- Endpoint security policies
- Windows Autopilot adoption
- Conditional Access requiring compliant devices

### 3. Applications (Entra ID + Intune)
- App protection policies (MAM) for iOS/Android
- Expired or expiring app credentials
- Conditional Access covering all cloud apps
- App registration governance

### 4. Data (Microsoft Purview)
- Sensitivity labels deployed
- DLP policies configured
- Mobile app-level data protection (MAM)

### 5. Infrastructure (Defender + M365)
- Microsoft Secure Score
- Endpoint security policy deployment
- Audit logging status

### 6. Network (Entra ID)
- Named/trusted locations defined
- Location-based Conditional Access policies

## Maturity Scoring

Each pillar receives a weighted score:

| Maturity Level | Score Range | Meaning |
|---|---|---|
| **Optimal** | 80-100% | Strong Zero Trust posture |
| **Advanced** | 50-79% | Good progress, gaps remain |
| **Traditional** | 0-49% | Significant gaps, immediate action needed |

Checks are weighted by importance (1-3):
- **Weight 3** -- Critical security controls (MFA, compliance, legacy auth blocking)
- **Weight 2** -- Important controls (encryption, app protection, Secure Score)
- **Weight 1** -- Recommended controls (named locations, Autopilot, app governance)

## Output Highlights

- **Overall Score** -- Single percentage with maturity level
- **Pillar Score Bars** -- Visual progress bar per pillar with pass/warning/fail counts
- **Critical Gaps** -- Failed checks with remediation recommendations
- **Per-Pillar Detail** -- Each pillar has its own section with all checks
- **All Checks Table** -- Complete list of every check evaluated
- **Charts** -- Pillar score comparison and check result distribution

## Requirements

- Windows PowerShell 5.1+ or PowerShell 7+
- **Microsoft.Graph PowerShell module**
- Global Reader role (minimum) for comprehensive results

### Required Graph Permissions (all read-only)

```
Directory.Read.All, User.Read.All, Group.Read.All, Application.Read.All,
Policy.Read.All, RoleManagement.Read.Directory, Device.Read.All,
Organization.Read.All, AuditLog.Read.All, Domain.Read.All,
Policy.Read.ConditionalAccess, DeviceManagementManagedDevices.Read.All,
DeviceManagementConfiguration.Read.All, DeviceManagementApps.Read.All,
DeviceManagementServiceConfig.Read.All, SecurityEvents.Read.All,
Reports.Read.All, IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All
```

**Note:** Some checks require specific licenses (Entra ID P2 for Identity Protection, E5 for Purview/Defender). Missing data gracefully degrades to "Warning" or "Not Available" instead of failing.

## Usage

```powershell
.\ZeroTrustCanvas.ps1
.\ZeroTrustCanvas.ps1 -OutputPath C:\Reports
```

## License

MIT -- Free to use, modify, and distribute.

## Related Projects

- [ADCanvas](https://github.com/SanthoshSivarajan/ADCanvas) -- Active Directory documentation
- [EntraIDCanvas](https://github.com/SanthoshSivarajan/EntraIDCanvas) -- Entra ID documentation
- [IntuneCanvas](https://github.com/SanthoshSivarajan/IntuneCanvas) -- Intune documentation

---

*Developed by Santhosh Sivarajan, Microsoft MVP*
