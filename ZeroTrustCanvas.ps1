<#
================================================================================
  ZeroTrustCanvas -- Assess Your Zero Trust Security Posture
  Version: 1.0
  Author : Santhosh Sivarajan, Microsoft MVP
  Purpose: Cross-product Zero Trust security posture assessment covering all
           six pillars: Identity, Devices, Applications, Data, Infrastructure,
           and Network. Pulls from Entra ID, Intune, Defender, and Purview
           via Microsoft Graph to evaluate, score, and recommend improvements.
  License: MIT -- Free to use, modify, and distribute.
  GitHub : https://github.com/SanthoshSivarajan/ZeroTrustCanvas
================================================================================
#>

#Requires -Modules Microsoft.Graph.Authentication

param([string]$OutputPath = $PSScriptRoot)

$ReportDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
$OutputFile = Join-Path $OutputPath "ZeroTrustCanvas_$ReportDate.html"

Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  |   ZeroTrustCanvas -- Zero Trust Posture Assessment v1.0    |" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  |   Author : Santhosh Sivarajan, Microsoft MVP              |" -ForegroundColor Cyan
Write-Host "  |   Web    : github.com/SanthoshSivarajan/ZeroTrustCanvas   |" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host ""

# --- Connect to Microsoft Graph -----------------------------------------------
$RequiredScopes = @(
    'Directory.Read.All','User.Read.All','Group.Read.All','Application.Read.All',
    'Policy.Read.All','RoleManagement.Read.Directory','Device.Read.All',
    'Organization.Read.All','AuditLog.Read.All','Domain.Read.All',
    'Policy.Read.ConditionalAccess','DeviceManagementManagedDevices.Read.All',
    'DeviceManagementConfiguration.Read.All','DeviceManagementApps.Read.All',
    'DeviceManagementServiceConfig.Read.All','SecurityEvents.Read.All',
    'Reports.Read.All','IdentityRiskyUser.Read.All','IdentityRiskEvent.Read.All'
)

$graphContext = Get-MgContext -ErrorAction SilentlyContinue
if (-not $graphContext) {
    Write-Host "  [*] Connecting to Microsoft Graph ..." -ForegroundColor Yellow
    try {
        Connect-MgGraph -Scopes $RequiredScopes -NoWelcome -ErrorAction Stop
        $graphContext = Get-MgContext
    } catch {
        Write-Host "  [!] Failed to connect: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  [*] Using existing Microsoft Graph session." -ForegroundColor Yellow
}

$Org = (Get-MgOrganization -ErrorAction SilentlyContinue)
$TenantName = $Org.DisplayName
$TenantId   = $Org.Id

Write-Host "  [*] Tenant    : $TenantName ($TenantId)" -ForegroundColor White
Write-Host "  [*] Account   : $($graphContext.Account)" -ForegroundColor White
Write-Host "  [*] Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host ""
Write-Host "  Running Zero Trust Assessment ..." -ForegroundColor Yellow
Write-Host ""

# --- Helpers ------------------------------------------------------------------
Add-Type -AssemblyName System.Web
function HtmlEncode($s) { if ($null -eq $s) { return "--" }; return [System.Web.HttpUtility]::HtmlEncode([string]$s) }
function Graph-Get {
    param([string]$Uri, [string]$Label)
    $all = @()
    try {
        $result = Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop
        if ($result.value) { $all += $result.value }
        while ($result.'@odata.nextLink') {
            $result = Invoke-MgGraphRequest -Method GET -Uri $result.'@odata.nextLink' -ErrorAction Stop
            if ($result.value) { $all += $result.value }
        }
        if ($Label) { Write-Host "  [+] $Label" -ForegroundColor Green }
    } catch {
        if ($Label) { Write-Host "  [i] $Label -- not available" -ForegroundColor Gray }
    }
    return $all
}

# Assessment check structure
$AllChecks = @()
function Add-Check {
    param([string]$Pillar, [string]$Category, [string]$Check, [string]$Status, [string]$Finding, [string]$Recommendation, [int]$Weight=1)
    $script:AllChecks += [PSCustomObject]@{
        Pillar=$Pillar; Category=$Category; Check=$Check; Status=$Status;
        Finding=$Finding; Recommendation=$Recommendation; Weight=$Weight
    }
}

# ==============================================================================
# DATA COLLECTION
# ==============================================================================

# --- Organization -------------------------------------------------------------
$VerifiedDomains = $Org.VerifiedDomains
$OnPremSync = $Org.OnPremisesSyncEnabled

# --- Users --------------------------------------------------------------------
$AllUsers = @()
try {
    $AllUsers = @(Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,AssignedLicenses,OnPremisesSyncEnabled,SignInActivity -ErrorAction Stop)
    Write-Host "  [+] Users collected ($($AllUsers.Count))" -ForegroundColor Green
} catch { Write-Host "  [i] Users -- limited data" -ForegroundColor Gray }
$TotalUsers   = $AllUsers.Count
$GuestUsers   = @($AllUsers | Where-Object { $_.UserType -eq 'Guest' }).Count
$EnabledUsers = @($AllUsers | Where-Object { $_.AccountEnabled -eq $true }).Count

# --- Conditional Access -------------------------------------------------------
$CAPolicies = @()
try {
    $CAPolicies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
    Write-Host "  [+] Conditional Access policies ($($CAPolicies.Count))" -ForegroundColor Green
} catch { Write-Host "  [i] Conditional Access -- not available" -ForegroundColor Gray }
$EnabledCA = @($CAPolicies | Where-Object { $_.State -eq 'enabled' }).Count

# --- Security Defaults --------------------------------------------------------
$SecurityDefaults = $null
try { $SecurityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop } catch { }

# --- Directory Roles ----------------------------------------------------------
$GlobalAdmins = @()
try {
    $gaRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" -ErrorAction Stop
    if ($gaRole) { $GlobalAdmins = @(Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -ErrorAction SilentlyContinue) }
    Write-Host "  [+] Directory roles collected" -ForegroundColor Green
} catch { }

# --- Auth Methods Policy ------------------------------------------------------
$AuthMethodsPolicy = $null
try { $AuthMethodsPolicy = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' -ErrorAction Stop } catch { }

# --- Named Locations ----------------------------------------------------------
$NamedLocations = @()
try { $NamedLocations = @(Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop) } catch { }

# --- Risky Users & Sign-Ins --------------------------------------------------
$RiskyUsers = Graph-Get -Uri 'https://graph.microsoft.com/v1.0/identityProtection/riskyUsers' -Label "Risky users"
$RiskySignIns = Graph-Get -Uri 'https://graph.microsoft.com/v1.0/identityProtection/riskDetections?$top=100' -Label "Risk detections"

# --- Managed Devices ----------------------------------------------------------
$ManagedDevices = Graph-Get -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' -Label "Managed devices"
$TotalDevices     = $ManagedDevices.Count
$CompliantDevices = @($ManagedDevices | Where-Object { $_.complianceState -eq 'compliant' }).Count
$EncryptedDevices = @($ManagedDevices | Where-Object { $_.isEncrypted -eq $true }).Count

# --- Compliance Policies ------------------------------------------------------
$CompliancePolicies = Graph-Get -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies' -Label "Compliance policies"

# --- Config Profiles ----------------------------------------------------------
$ConfigProfiles = Graph-Get -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations' -Label "Config profiles"

# --- App Protection -----------------------------------------------------------
$AppProtAndroid = Graph-Get -Uri 'https://graph.microsoft.com/v1.0/deviceAppManagement/androidManagedAppProtections' -Label "App protection (Android)"
$AppProtIOS     = Graph-Get -Uri 'https://graph.microsoft.com/v1.0/deviceAppManagement/iosManagedAppProtections' -Label "App protection (iOS)"
$TotalAppProt   = $AppProtAndroid.Count + $AppProtIOS.Count

# --- Applications -------------------------------------------------------------
$AppRegistrations = @()
try {
    $AppRegistrations = @(Get-MgApplication -All -Property Id,DisplayName,AppId,PasswordCredentials,KeyCredentials,RequiredResourceAccess -ErrorAction Stop)
    Write-Host "  [+] App registrations ($($AppRegistrations.Count))" -ForegroundColor Green
} catch { }

# Expiring creds
$now = Get-Date
$ExpiredCreds = 0; $ExpiringSoonCreds = 0
foreach ($app in $AppRegistrations) {
    foreach ($cred in $app.PasswordCredentials) {
        if ($cred.EndDateTime) {
            if ([datetime]$cred.EndDateTime -lt $now) { $ExpiredCreds++ }
            elseif ([datetime]$cred.EndDateTime -lt $now.AddDays(30)) { $ExpiringSoonCreds++ }
        }
    }
    foreach ($cred in $app.KeyCredentials) {
        if ($cred.EndDateTime) {
            if ([datetime]$cred.EndDateTime -lt $now) { $ExpiredCreds++ }
            elseif ([datetime]$cred.EndDateTime -lt $now.AddDays(30)) { $ExpiringSoonCreds++ }
        }
    }
}

# --- Secure Score -------------------------------------------------------------
$SecureScore = $null
try {
    $ssResult = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/security/secureScores?$top=1' -ErrorAction Stop
    if ($ssResult.value -and $ssResult.value.Count -gt 0) { $SecureScore = $ssResult.value[0] }
    Write-Host "  [+] Secure Score collected" -ForegroundColor Green
} catch { Write-Host "  [i] Secure Score -- not available" -ForegroundColor Gray }

# --- Sensitivity Labels -------------------------------------------------------
$SensitivityLabels = Graph-Get -Uri 'https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels' -Label "Sensitivity labels"

# --- DLP Policies (Purview) ---------------------------------------------------
$DLPPolicies = Graph-Get -Uri 'https://graph.microsoft.com/beta/security/informationProtection/policy/dlpPolicies' -Label "DLP policies"

# --- Endpoint Security --------------------------------------------------------
$EndpointSecPolicies = Graph-Get -Uri 'https://graph.microsoft.com/beta/deviceManagement/intents' -Label "Endpoint security policies"

# --- Autopilot ----------------------------------------------------------------
$AutopilotDevices = Graph-Get -Uri 'https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities' -Label "Autopilot devices"

Write-Host ""

# ==============================================================================
# PILLAR 1: IDENTITY
# ==============================================================================
Write-Host "  [*] Assessing Pillar 1: Identity ..." -ForegroundColor Yellow

# Check: Security Defaults or CA
$secDefEnabled = ($SecurityDefaults -and $SecurityDefaults.IsEnabled)
if ($EnabledCA -gt 0) {
    Add-Check 'Identity' 'Authentication' 'Conditional Access Policies' 'Pass' "$EnabledCA enabled CA policies" 'Conditional Access is active.' 3
} elseif ($secDefEnabled) {
    Add-Check 'Identity' 'Authentication' 'Security Defaults' 'Warning' 'Security Defaults enabled (basic protection)' 'Consider upgrading to Conditional Access for granular control.' 3
} else {
    Add-Check 'Identity' 'Authentication' 'MFA Enforcement' 'Fail' 'No CA policies and Security Defaults disabled' 'Enable Conditional Access policies or Security Defaults immediately.' 3
}

# Check: MFA in CA
$mfaCA = @($CAPolicies | Where-Object { $_.State -eq 'enabled' -and $_.GrantControls.BuiltInControls -contains 'mfa' })
if ($mfaCA.Count -gt 0) {
    Add-Check 'Identity' 'Authentication' 'MFA via Conditional Access' 'Pass' "$($mfaCA.Count) CA policies enforce MFA" '' 3
} elseif (-not $secDefEnabled) {
    Add-Check 'Identity' 'Authentication' 'MFA via Conditional Access' 'Fail' 'No CA policies enforce MFA' 'Create a CA policy requiring MFA for all users.' 3
}

# Check: Global Admin count
$gaCount = $GlobalAdmins.Count
if ($gaCount -le 5 -and $gaCount -ge 2) {
    Add-Check 'Identity' 'Privileged Access' 'Global Admin Count' 'Pass' "$gaCount Global Admins (recommended: 2-5)" '' 2
} elseif ($gaCount -eq 1) {
    Add-Check 'Identity' 'Privileged Access' 'Global Admin Count' 'Warning' "Only 1 Global Admin -- no break-glass" 'Create at least 2 Global Admin accounts including a break-glass account.' 2
} elseif ($gaCount -gt 5) {
    Add-Check 'Identity' 'Privileged Access' 'Global Admin Count' 'Fail' "$gaCount Global Admins (too many)" 'Reduce Global Admins to 2-5. Use least-privilege roles.' 2
} else {
    Add-Check 'Identity' 'Privileged Access' 'Global Admin Count' 'Fail' "Could not determine Global Admin count" 'Review Global Admin assignments.' 2
}

# Check: Guest access
if ($GuestUsers -gt 0) {
    $guestPct = [math]::Round(($GuestUsers / [math]::Max($TotalUsers,1)) * 100, 1)
    if ($guestPct -gt 20) {
        Add-Check 'Identity' 'External Identities' 'Guest User Ratio' 'Warning' "$GuestUsers guests ($guestPct% of users)" 'Review guest access. Consider access reviews for B2B guests.' 1
    } else {
        Add-Check 'Identity' 'External Identities' 'Guest User Ratio' 'Pass' "$GuestUsers guests ($guestPct%)" '' 1
    }
} else {
    Add-Check 'Identity' 'External Identities' 'Guest User Ratio' 'Pass' 'No guest users' '' 1
}

# Check: Legacy auth blocking
$legacyBlock = @($CAPolicies | Where-Object {
    $_.State -eq 'enabled' -and
    $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or
    $_.Conditions.ClientAppTypes -contains 'other'
})
if ($legacyBlock.Count -gt 0) {
    Add-Check 'Identity' 'Authentication' 'Block Legacy Authentication' 'Pass' 'Legacy auth blocked via CA policy' '' 3
} else {
    Add-Check 'Identity' 'Authentication' 'Block Legacy Authentication' 'Fail' 'No CA policy blocking legacy authentication' 'Create a CA policy to block legacy authentication protocols.' 3
}

# Check: Named Locations
if ($NamedLocations.Count -gt 0) {
    Add-Check 'Identity' 'Network Controls' 'Named Locations' 'Pass' "$($NamedLocations.Count) named locations configured" '' 1
} else {
    Add-Check 'Identity' 'Network Controls' 'Named Locations' 'Warning' 'No named locations configured' 'Define trusted network locations for location-based CA policies.' 1
}

# Check: Risky users
$activeRisky = @($RiskyUsers | Where-Object { $_.riskState -eq 'atRisk' })
if ($activeRisky.Count -gt 0) {
    Add-Check 'Identity' 'Identity Protection' 'Risky Users' 'Fail' "$($activeRisky.Count) users currently at risk" 'Investigate and remediate risky users in Entra ID Protection.' 3
} elseif ($RiskyUsers.Count -eq 0) {
    Add-Check 'Identity' 'Identity Protection' 'Risky Users' 'Pass' 'No users at risk (or Identity Protection not licensed)' '' 2
} else {
    Add-Check 'Identity' 'Identity Protection' 'Risky Users' 'Pass' 'No active risky users' '' 2
}

# Check: Password protection / SSPR
$passwordMethods = $null
if ($AuthMethodsPolicy -and $AuthMethodsPolicy.authenticationMethodConfigurations) {
    $passwordMethods = $AuthMethodsPolicy.authenticationMethodConfigurations
}
Add-Check 'Identity' 'Authentication' 'Authentication Methods Policy' $(if($AuthMethodsPolicy){'Pass'}else{'Warning'}) $(if($AuthMethodsPolicy){'Auth methods policy configured'}else{'Could not retrieve auth methods policy'}) 'Review authentication methods and enable passwordless options.' 1

# Check: Directory sync
if ($OnPremSync) {
    Add-Check 'Identity' 'Hybrid' 'Directory Synchronization' 'Pass' 'On-premises sync enabled (hybrid identity)' '' 1
}

# ==============================================================================
# PILLAR 2: DEVICES
# ==============================================================================
Write-Host "  [*] Assessing Pillar 2: Devices ..." -ForegroundColor Yellow

if ($TotalDevices -gt 0) {
    # Compliance rate
    $compRate = [math]::Round(($CompliantDevices / $TotalDevices) * 100, 1)
    if ($compRate -ge 90) {
        Add-Check 'Devices' 'Compliance' 'Device Compliance Rate' 'Pass' "$compRate% compliant ($CompliantDevices/$TotalDevices)" '' 3
    } elseif ($compRate -ge 70) {
        Add-Check 'Devices' 'Compliance' 'Device Compliance Rate' 'Warning' "$compRate% compliant" 'Improve compliance rate to 90%+ by reviewing non-compliant devices.' 3
    } else {
        Add-Check 'Devices' 'Compliance' 'Device Compliance Rate' 'Fail' "$compRate% compliant" 'Critically low compliance. Review and remediate non-compliant devices.' 3
    }

    # Encryption
    $encRate = [math]::Round(($EncryptedDevices / $TotalDevices) * 100, 1)
    if ($encRate -ge 90) {
        Add-Check 'Devices' 'Data Protection' 'Device Encryption' 'Pass' "$encRate% encrypted" '' 2
    } else {
        Add-Check 'Devices' 'Data Protection' 'Device Encryption' $(if($encRate -ge 50){'Warning'}else{'Fail'}) "$encRate% encrypted" 'Enforce BitLocker/FileVault via compliance or config policies.' 2
    }
} else {
    Add-Check 'Devices' 'Enrollment' 'Device Enrollment' 'Fail' 'No managed devices enrolled in Intune' 'Enroll devices into Intune for device compliance and management.' 3
}

# Compliance policies exist
if ($CompliancePolicies.Count -gt 0) {
    Add-Check 'Devices' 'Compliance' 'Compliance Policies Defined' 'Pass' "$($CompliancePolicies.Count) compliance policies" '' 2
} else {
    Add-Check 'Devices' 'Compliance' 'Compliance Policies Defined' 'Fail' 'No compliance policies defined' 'Create device compliance policies for each platform.' 2
}

# Config profiles
if ($ConfigProfiles.Count -gt 0) {
    Add-Check 'Devices' 'Configuration' 'Configuration Profiles' 'Pass' "$($ConfigProfiles.Count) configuration profiles" '' 1
} else {
    Add-Check 'Devices' 'Configuration' 'Configuration Profiles' 'Warning' 'No device configuration profiles' 'Deploy security baselines and configuration profiles.' 1
}

# Endpoint security
if ($EndpointSecPolicies.Count -gt 0) {
    Add-Check 'Devices' 'Endpoint Security' 'Security Policies' 'Pass' "$($EndpointSecPolicies.Count) endpoint security policies" '' 2
} else {
    Add-Check 'Devices' 'Endpoint Security' 'Security Policies' 'Warning' 'No endpoint security policies' 'Deploy antivirus, firewall, and disk encryption policies.' 2
}

# Autopilot
if ($AutopilotDevices.Count -gt 0) {
    Add-Check 'Devices' 'Provisioning' 'Windows Autopilot' 'Pass' "$($AutopilotDevices.Count) Autopilot devices registered" '' 1
} else {
    Add-Check 'Devices' 'Provisioning' 'Windows Autopilot' 'Warning' 'No Autopilot devices registered' 'Consider Windows Autopilot for secure device provisioning.' 1
}

# CA requiring compliant device
$compDeviceCA = @($CAPolicies | Where-Object { $_.State -eq 'enabled' -and $_.GrantControls.BuiltInControls -contains 'compliantDevice' })
if ($compDeviceCA.Count -gt 0) {
    Add-Check 'Devices' 'Access Control' 'Require Compliant Device' 'Pass' "$($compDeviceCA.Count) CA policies require compliant devices" '' 3
} else {
    Add-Check 'Devices' 'Access Control' 'Require Compliant Device' 'Fail' 'No CA policy requires device compliance' 'Create a CA policy requiring compliant or Entra joined devices.' 3
}

# ==============================================================================
# PILLAR 3: APPLICATIONS
# ==============================================================================
Write-Host "  [*] Assessing Pillar 3: Applications ..." -ForegroundColor Yellow

# App protection policies
if ($TotalAppProt -gt 0) {
    Add-Check 'Applications' 'Mobile Apps' 'App Protection Policies' 'Pass' "$TotalAppProt app protection policies (MAM)" '' 2
} else {
    Add-Check 'Applications' 'Mobile Apps' 'App Protection Policies' 'Fail' 'No app protection policies' 'Create MAM policies for iOS and Android to protect corporate data in apps.' 2
}

# Expiring credentials
if ($ExpiredCreds -gt 0) {
    Add-Check 'Applications' 'Credential Hygiene' 'Expired App Credentials' 'Fail' "$ExpiredCreds expired secrets/certificates" 'Rotate or remove expired app credentials immediately.' 3
} elseif ($ExpiringSoonCreds -gt 0) {
    Add-Check 'Applications' 'Credential Hygiene' 'Expiring App Credentials' 'Warning' "$ExpiringSoonCreds credentials expiring within 30 days" 'Plan credential rotation before expiry.' 2
} else {
    Add-Check 'Applications' 'Credential Hygiene' 'App Credentials' 'Pass' 'No expired or expiring credentials' '' 2
}

# CA covering all cloud apps
$allAppsCA = @($CAPolicies | Where-Object {
    $_.State -eq 'enabled' -and
    $_.Conditions.Applications.IncludeApplications -contains 'All'
})
if ($allAppsCA.Count -gt 0) {
    Add-Check 'Applications' 'Access Control' 'CA Covers All Apps' 'Pass' "$($allAppsCA.Count) CA policies cover all cloud apps" '' 2
} else {
    Add-Check 'Applications' 'Access Control' 'CA Covers All Apps' 'Warning' 'No CA policy targeting all cloud apps' 'Ensure CA policies cover all cloud applications.' 2
}

# OAuth consent
$appCount = $AppRegistrations.Count
Add-Check 'Applications' 'App Governance' 'App Registrations' $(if($appCount -lt 50){'Pass'}else{'Warning'}) "$appCount app registrations" $(if($appCount -ge 50){'Review and clean up unused app registrations.'}else{''}) 1

# ==============================================================================
# PILLAR 4: DATA
# ==============================================================================
Write-Host "  [*] Assessing Pillar 4: Data ..." -ForegroundColor Yellow

# Sensitivity labels
if ($SensitivityLabels.Count -gt 0) {
    Add-Check 'Data' 'Classification' 'Sensitivity Labels' 'Pass' "$($SensitivityLabels.Count) sensitivity labels defined" '' 2
} else {
    Add-Check 'Data' 'Classification' 'Sensitivity Labels' 'Warning' 'No sensitivity labels detected (Purview may not be licensed)' 'Deploy Microsoft Purview sensitivity labels for data classification.' 2
}

# DLP policies
if ($DLPPolicies.Count -gt 0) {
    Add-Check 'Data' 'Data Loss Prevention' 'DLP Policies' 'Pass' "$($DLPPolicies.Count) DLP policies" '' 2
} else {
    Add-Check 'Data' 'Data Loss Prevention' 'DLP Policies' 'Warning' 'No DLP policies detected (Purview may not be licensed)' 'Deploy DLP policies to prevent sensitive data leakage.' 2
}

# App protection (data perspective)
if ($TotalAppProt -gt 0) {
    Add-Check 'Data' 'Mobile Data Protection' 'App-Level Data Controls' 'Pass' "MAM policies protect data on mobile devices" '' 2
} else {
    Add-Check 'Data' 'Mobile Data Protection' 'App-Level Data Controls' 'Fail' 'No MAM policies to protect data on mobile' 'Deploy app protection policies to prevent copy/paste of corporate data.' 2
}

# ==============================================================================
# PILLAR 5: INFRASTRUCTURE
# ==============================================================================
Write-Host "  [*] Assessing Pillar 5: Infrastructure ..." -ForegroundColor Yellow

# Secure Score
if ($SecureScore) {
    $currentScore = [math]::Round($SecureScore.currentScore, 1)
    $maxScore     = [math]::Round($SecureScore.maxScore, 1)
    $pct = if ($maxScore -gt 0) { [math]::Round(($currentScore / $maxScore) * 100, 1) } else { 0 }
    $status = if ($pct -ge 70) { 'Pass' } elseif ($pct -ge 50) { 'Warning' } else { 'Fail' }
    Add-Check 'Infrastructure' 'Security Posture' 'Microsoft Secure Score' $status "$currentScore / $maxScore ($pct%)" $(if($pct -lt 70){'Improve Secure Score by addressing recommended actions.'}else{''}) 3
} else {
    Add-Check 'Infrastructure' 'Security Posture' 'Microsoft Secure Score' 'Warning' 'Secure Score not available' 'Review Microsoft Secure Score in the Security portal.' 2
}

# Audit logging
Add-Check 'Infrastructure' 'Monitoring' 'Unified Audit Logging' 'Pass' 'Microsoft 365 audit logging is enabled by default' 'Ensure audit log retention meets compliance requirements.' 1

# Endpoint security policies (infrastructure view)
if ($EndpointSecPolicies.Count -gt 0) {
    Add-Check 'Infrastructure' 'Endpoint Protection' 'Defender Policies' 'Pass' "$($EndpointSecPolicies.Count) endpoint security policies deployed" '' 2
} else {
    Add-Check 'Infrastructure' 'Endpoint Protection' 'Defender Policies' 'Warning' 'No endpoint security policies' 'Deploy Defender for Endpoint and security baselines.' 2
}

# ==============================================================================
# PILLAR 6: NETWORK
# ==============================================================================
Write-Host "  [*] Assessing Pillar 6: Network ..." -ForegroundColor Yellow

# Named locations for network segmentation
if ($NamedLocations.Count -gt 0) {
    Add-Check 'Network' 'Segmentation' 'Trusted Locations Defined' 'Pass' "$($NamedLocations.Count) named locations" '' 2
} else {
    Add-Check 'Network' 'Segmentation' 'Trusted Locations Defined' 'Warning' 'No named locations defined' 'Define trusted IP ranges and countries for location-based access control.' 2
}

# Location-based CA
$locationCA = @($CAPolicies | Where-Object {
    $_.State -eq 'enabled' -and
    ($_.Conditions.Locations.IncludeLocations -or $_.Conditions.Locations.ExcludeLocations)
})
if ($locationCA.Count -gt 0) {
    Add-Check 'Network' 'Access Control' 'Location-Based CA Policies' 'Pass' "$($locationCA.Count) CA policies use location conditions" '' 2
} else {
    Add-Check 'Network' 'Access Control' 'Location-Based CA Policies' 'Warning' 'No location-based CA policies' 'Use location conditions in CA policies to restrict access from untrusted networks.' 2
}

Write-Host ""
Write-Host "  [+] Assessment complete. $($AllChecks.Count) checks evaluated." -ForegroundColor Green

# ==============================================================================
# CALCULATE SCORES
# ==============================================================================
$Pillars = @('Identity','Devices','Applications','Data','Infrastructure','Network')
$PillarScores = @{}
foreach ($p in $Pillars) {
    $checks = @($AllChecks | Where-Object { $_.Pillar -eq $p })
    if ($checks.Count -eq 0) { $PillarScores[$p] = @{Score=0;Max=0;Pct=0;Pass=0;Warn=0;Fail=0;Total=0}; continue }
    $maxScore = ($checks | ForEach-Object { $_.Weight } | Measure-Object -Sum).Sum
    $earnedScore = 0
    $pass = 0; $warn = 0; $fail = 0
    foreach ($c in $checks) {
        switch ($c.Status) {
            'Pass'    { $earnedScore += $c.Weight; $pass++ }
            'Warning' { $earnedScore += [math]::Floor($c.Weight * 0.5); $warn++ }
            'Fail'    { $fail++ }
        }
    }
    $pct = if ($maxScore -gt 0) { [math]::Round(($earnedScore / $maxScore) * 100) } else { 0 }
    $PillarScores[$p] = @{Score=$earnedScore;Max=$maxScore;Pct=$pct;Pass=$pass;Warn=$warn;Fail=$fail;Total=$checks.Count}
}

# Overall score
$totalEarned = ($PillarScores.Values | ForEach-Object { $_.Score } | Measure-Object -Sum).Sum
$totalMax    = ($PillarScores.Values | ForEach-Object { $_.Max } | Measure-Object -Sum).Sum
$overallPct  = if ($totalMax -gt 0) { [math]::Round(($totalEarned / $totalMax) * 100) } else { 0 }
$totalPass   = ($PillarScores.Values | ForEach-Object { $_.Pass } | Measure-Object -Sum).Sum
$totalWarn   = ($PillarScores.Values | ForEach-Object { $_.Warn } | Measure-Object -Sum).Sum
$totalFail   = ($PillarScores.Values | ForEach-Object { $_.Fail } | Measure-Object -Sum).Sum

function Get-Maturity($pct) {
    if ($pct -ge 80) { return 'Optimal' }
    if ($pct -ge 50) { return 'Advanced' }
    return 'Traditional'
}
function Get-StatusColor($status) {
    switch ($status) { 'Pass' { '#34d399' } 'Warning' { '#fbbf24' } 'Fail' { '#f87171' } default { '#94a3b8' } }
}
function Get-ScoreColor($pct) {
    if ($pct -ge 80) { return '#34d399' }
    if ($pct -ge 50) { return '#fbbf24' }
    return '#f87171'
}

# Build check table HTML
$CheckTableHTML = [System.Text.StringBuilder]::new()
[void]$CheckTableHTML.Append('<div class="table-wrap"><table><thead><tr><th>Pillar</th><th>Category</th><th>Check</th><th>Status</th><th>Finding</th><th>Recommendation</th></tr></thead><tbody>')
foreach ($c in ($AllChecks | Sort-Object Pillar, Category)) {
    $statusColor = Get-StatusColor $c.Status
    $statusBadge = '<span style="color:' + $statusColor + ';font-weight:700">' + (HtmlEncode $c.Status) + '</span>'
    [void]$CheckTableHTML.Append("<tr><td>$(HtmlEncode $c.Pillar)</td><td>$(HtmlEncode $c.Category)</td><td>$(HtmlEncode $c.Check)</td><td>$statusBadge</td><td>$(HtmlEncode $c.Finding)</td><td>$(HtmlEncode $c.Recommendation)</td></tr>")
}
[void]$CheckTableHTML.Append('</tbody></table></div>')

# Failed checks only
$FailedChecks = @($AllChecks | Where-Object { $_.Status -eq 'Fail' })
$FailedTableHTML = '<p class="empty-note">No failed checks -- excellent!</p>'
if ($FailedChecks.Count -gt 0) {
    $ftb = [System.Text.StringBuilder]::new()
    [void]$ftb.Append('<div class="table-wrap"><table><thead><tr><th>Pillar</th><th>Check</th><th>Finding</th><th>Recommendation</th></tr></thead><tbody>')
    foreach ($c in $FailedChecks) {
        [void]$ftb.Append("<tr><td>$(HtmlEncode $c.Pillar)</td><td>$(HtmlEncode $c.Check)</td><td>$(HtmlEncode $c.Finding)</td><td style=`"color:#fbbf24`">$(HtmlEncode $c.Recommendation)</td></tr>")
    }
    [void]$ftb.Append('</tbody></table></div>')
    $FailedTableHTML = $ftb.ToString()
}

# Pillar score bars HTML
$PillarBarsHTML = [System.Text.StringBuilder]::new()
foreach ($p in $Pillars) {
    $s = $PillarScores[$p]
    $color = Get-ScoreColor $s.Pct
    $maturity = Get-Maturity $s.Pct
    [void]$PillarBarsHTML.Append(@"
<div style="margin-bottom:12px">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
    <span style="font-weight:700;font-size:.9rem;color:#e2e8f0">$p</span>
    <span style="font-size:.78rem;color:$color;font-weight:600">$($s.Pct)% -- $maturity</span>
  </div>
  <div style="height:24px;background:#273548;border-radius:6px;overflow:hidden;border:1px solid #334155">
    <div style="height:100%;width:$($s.Pct)%;background:$color;border-radius:5px;transition:width .6s ease;display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;color:#0f172a">$($s.Pct)%</div>
  </div>
  <div style="font-size:.7rem;color:#94a3b8;margin-top:2px">Pass: $($s.Pass) | Warning: $($s.Warn) | Fail: $($s.Fail) | Total: $($s.Total)</div>
</div>
"@)
}

# Chart data
$PillarChartJSON = '{' + (($Pillars | ForEach-Object { '"' + $_ + '":' + $PillarScores[$_].Pct }) -join ',') + '}'
$StatusChartJSON = '{"Pass":' + $totalPass + ',"Warning":' + $totalWarn + ',"Fail":' + $totalFail + '}'

# ==============================================================================
# HTML REPORT
# ==============================================================================
$HTML = @"
<!--
================================================================================
  ZeroTrustCanvas -- Zero Trust Security Posture Assessment
  Generated : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  Author    : Santhosh Sivarajan, Microsoft MVP
  GitHub    : https://github.com/SanthoshSivarajan/ZeroTrustCanvas
================================================================================
-->
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="author" content="Santhosh Sivarajan, Microsoft MVP"/>
<title>ZeroTrustCanvas -- $TenantName</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0f172a;--surface:#1e293b;--surface2:#273548;--border:#334155;--text:#e2e8f0;--text-dim:#94a3b8;--accent:#60a5fa;--accent2:#22d3ee;--green:#34d399;--red:#f87171;--amber:#fbbf24;--purple:#a78bfa;--pink:#f472b6;--orange:#fb923c;--radius:8px;--shadow:0 1px 3px rgba(0,0,0,.3);--font-body:'Segoe UI',system-ui,sans-serif}
html{scroll-behavior:smooth;font-size:15px}body{font-family:var(--font-body);background:var(--bg);color:var(--text);line-height:1.65;min-height:100vh}a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrapper{display:flex;min-height:100vh}.sidebar{position:fixed;top:0;left:0;width:260px;height:100vh;background:var(--surface);border-right:1px solid var(--border);overflow-y:auto;padding:20px 0;z-index:100;box-shadow:2px 0 12px rgba(0,0,0,.3)}.sidebar::-webkit-scrollbar{width:4px}.sidebar::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}.sidebar .logo{padding:0 18px 14px;border-bottom:1px solid var(--border);margin-bottom:8px}.sidebar .logo h2{font-size:1.05rem;color:var(--accent);font-weight:700}.sidebar .logo p{font-size:.68rem;color:var(--text-dim);margin-top:2px}.sidebar nav a{display:block;padding:5px 18px 5px 22px;font-size:.78rem;color:var(--text-dim);border-left:3px solid transparent;transition:all .15s}.sidebar nav a:hover,.sidebar nav a.active{color:var(--accent);background:rgba(96,165,250,.08);border-left-color:var(--accent);text-decoration:none}.sidebar nav .nav-group{font-size:.62rem;text-transform:uppercase;letter-spacing:.08em;color:var(--accent2);padding:10px 18px 2px;font-weight:700}
.main{margin-left:260px;flex:1;padding:24px 32px 50px;max-width:1200px}.section{margin-bottom:36px}.section-title{font-size:1.25rem;font-weight:700;color:var(--text);margin-bottom:4px;padding-bottom:8px;border-bottom:2px solid var(--border);display:flex;align-items:center;gap:8px}.section-title .icon{width:24px;height:24px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:.8rem;flex-shrink:0}.sub-header{font-size:.92rem;color:var(--text);margin:16px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--border)}.section-desc{color:var(--text-dim);font-size:.84rem;margin-bottom:14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:16px}.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;box-shadow:var(--shadow)}.card:hover{border-color:var(--accent)}.card .card-val{font-size:1.5rem;font-weight:800;line-height:1.1}.card .card-label{font-size:.68rem;color:var(--text-dim);margin-top:2px;text-transform:uppercase;letter-spacing:.05em}
.table-wrap{overflow-x:auto;margin-bottom:8px;border-radius:var(--radius);border:1px solid var(--border);box-shadow:var(--shadow)}table{width:100%;border-collapse:collapse;font-size:.78rem}thead{background:rgba(96,165,250,.1)}th{text-align:left;padding:8px 10px;font-weight:600;color:var(--accent);white-space:nowrap;border-bottom:2px solid var(--border)}td{padding:7px 10px;border-bottom:1px solid var(--border);color:var(--text-dim);max-width:360px;overflow:hidden;text-overflow:ellipsis}tbody tr:hover{background:rgba(96,165,250,.06)}tbody tr:nth-child(even){background:var(--surface2)}.empty-note{color:var(--text-dim);font-style:italic;padding:8px 0}
.score-card{background:linear-gradient(135deg,#1e293b 0%,#1e3a5f 100%);border:1px solid #334155;border-radius:var(--radius);padding:28px;margin-bottom:28px;text-align:center;box-shadow:var(--shadow)}
.score-big{font-size:3.5rem;font-weight:900;line-height:1}.score-label{font-size:.9rem;color:var(--text-dim);margin-top:4px}
.exec-kv{display:inline-block;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:2px 8px;margin:2px;font-size:.78rem;color:var(--text)}.exec-kv strong{color:var(--accent2)}
.footer{margin-top:36px;padding:18px 0;border-top:1px solid var(--border);text-align:center;color:var(--text-dim);font-size:.74rem}.footer a{color:var(--accent)}
@media print{.sidebar{display:none}.main{margin-left:0}body{background:#fff;color:#222}.card,.score-card{background:#f9f9f9;border-color:#ccc;color:#222}.card-val,.score-big,.section-title{color:#222}th{color:#333;background:#eee}td{color:#444}}
@media(max-width:900px){.sidebar{display:none}.main{margin-left:0;padding:14px}}
</style>
</head>
<body>
<div class="wrapper">
<aside class="sidebar">
  <div class="logo"><h2>ZeroTrustCanvas</h2><p>Developed by Santhosh Sivarajan</p><p style="margin-top:6px">Tenant: <strong style="color:#e2e8f0">$TenantName</strong></p></div>
  <nav>
    <div class="nav-group">Assessment</div>
    <a href="#overall-score">Overall Score</a>
    <a href="#pillar-scores">Pillar Scores</a>
    <a href="#critical-gaps">Critical Gaps</a>
    <div class="nav-group">Pillars</div>
    <a href="#identity">1. Identity</a>
    <a href="#devices">2. Devices</a>
    <a href="#applications">3. Applications</a>
    <a href="#data">4. Data</a>
    <a href="#infrastructure">5. Infrastructure</a>
    <a href="#network">6. Network</a>
    <div class="nav-group">Details</div>
    <a href="#all-checks">All Checks</a>
    <a href="#charts">Charts</a>
  </nav>
</aside>
<main class="main">

<!-- OVERALL SCORE -->
<div id="overall-score" class="section">
  <div class="score-card">
    <div class="score-big" style="color:$(Get-ScoreColor $overallPct)">$overallPct%</div>
    <div class="score-label">Zero Trust Maturity: <strong style="color:$(Get-ScoreColor $overallPct)">$(Get-Maturity $overallPct)</strong></div>
    <div style="margin-top:12px">
      <span class="exec-kv"><strong>Tenant:</strong> $TenantName</span>
      <span class="exec-kv"><strong>Checks:</strong> $($AllChecks.Count)</span>
      <span class="exec-kv" style="color:#34d399"><strong>Pass:</strong> $totalPass</span>
      <span class="exec-kv" style="color:#fbbf24"><strong>Warning:</strong> $totalWarn</span>
      <span class="exec-kv" style="color:#f87171"><strong>Fail:</strong> $totalFail</span>
      <span class="exec-kv"><strong>Assessed:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm")</span>
    </div>
  </div>
</div>

<!-- PILLAR SCORES -->
<div id="pillar-scores" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128202;</span> Zero Trust Pillar Scores</h2>
  <p class="section-desc">Each pillar is scored based on weighted checks. Maturity levels: Traditional (0-49%), Advanced (50-79%), Optimal (80-100%).</p>
  $($PillarBarsHTML.ToString())
</div>

<!-- CRITICAL GAPS -->
<div id="critical-gaps" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(248,113,113,.15);color:var(--red)">&#9888;</span> Critical Gaps ($($FailedChecks.Count) Failed Checks)</h2>
  <p class="section-desc">These items require immediate attention to improve your Zero Trust posture.</p>
  $FailedTableHTML
</div>

<!-- PILLAR DETAIL SECTIONS -->
$(foreach ($p in $Pillars) {
    $s = $PillarScores[$p]
    $color = Get-ScoreColor $s.Pct
    $icon = switch ($p) { 'Identity' {'&#128100;'} 'Devices' {'&#128187;'} 'Applications' {'&#128736;'} 'Data' {'&#128274;'} 'Infrastructure' {'&#9881;'} 'Network' {'&#127760;'} }
    $pillarChecks = @($AllChecks | Where-Object { $_.Pillar -eq $p })
    $checkRows = ($pillarChecks | ForEach-Object {
        $sc = Get-StatusColor $_.Status
        "<tr><td>$(HtmlEncode $_.Category)</td><td>$(HtmlEncode $_.Check)</td><td><span style=`"color:$sc;font-weight:700`">$($_.Status)</span></td><td>$(HtmlEncode $_.Finding)</td><td>$(HtmlEncode $_.Recommendation)</td></tr>"
    }) -join ''
@"
<div id="$($p.ToLower())" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">$icon</span> $p <span style="margin-left:auto;font-size:.85rem;color:$color">$($s.Pct)% -- $(Get-Maturity $s.Pct)</span></h2>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:$color">$($s.Pct)%</div><div class="card-label">Score</div></div>
    <div class="card"><div class="card-val" style="color:#34d399">$($s.Pass)</div><div class="card-label">Pass</div></div>
    <div class="card"><div class="card-val" style="color:#fbbf24">$($s.Warn)</div><div class="card-label">Warning</div></div>
    <div class="card"><div class="card-val" style="color:#f87171">$($s.Fail)</div><div class="card-label">Fail</div></div>
  </div>
  <div class="table-wrap"><table><thead><tr><th>Category</th><th>Check</th><th>Status</th><th>Finding</th><th>Recommendation</th></tr></thead><tbody>$checkRows</tbody></table></div>
</div>
"@
})

<!-- ALL CHECKS -->
<div id="all-checks" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(167,139,250,.15);color:var(--purple)">&#128220;</span> All Checks ($($AllChecks.Count))</h2>
  $($CheckTableHTML.ToString())
</div>

<!-- CHARTS -->
<div id="charts" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128202;</span> Assessment Charts</h2>
  <div id="chartsContainer" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px"></div>
</div>

<div class="footer">
  ZeroTrustCanvas v1.0 -- Zero Trust Security Posture Assessment -- $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
  Developed by <a href="https://github.com/SanthoshSivarajan">Santhosh Sivarajan</a>, Microsoft MVP --
  <a href="https://github.com/SanthoshSivarajan/ZeroTrustCanvas">github.com/SanthoshSivarajan/ZeroTrustCanvas</a>
</div>
</main>
</div>
<script>
var COLORS=['#60a5fa','#34d399','#f87171','#fbbf24','#a78bfa','#f472b6','#22d3ee','#fb923c','#a3e635','#e879f9'];
function buildBarChart(t,d,c){var b=document.createElement('div');b.style.cssText='background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;box-shadow:var(--shadow)';var h=document.createElement('h3');h.style.cssText='font-size:.86rem;margin-bottom:10px;color:#e2e8f0';h.textContent=t;b.appendChild(h);var tot=Object.values(d).reduce(function(a,b){return a+b},0);if(!tot){b.innerHTML+='<p style="color:#94a3b8">No data.</p>';c.appendChild(b);return}var g=document.createElement('div');g.style.cssText='display:flex;flex-direction:column;gap:6px';var e=Object.entries(d),ci=0;for(var i=0;i<e.length;i++){var p=((e[i][1]/tot)*100).toFixed(1);var r=document.createElement('div');r.style.cssText='display:flex;align-items:center;gap:8px';r.innerHTML='<span style="width:100px;font-size:.74rem;color:#94a3b8;text-align:right;flex-shrink:0">'+e[i][0]+'</span><div style="flex:1;height:20px;background:#273548;border-radius:4px;overflow:hidden;border:1px solid #334155"><div style="height:100%;border-radius:3px;width:'+p+'%;background:'+COLORS[ci%COLORS.length]+';display:flex;align-items:center;padding:0 6px;font-size:.66rem;font-weight:600;color:#fff;white-space:nowrap">'+p+'%</div></div><span style="width:44px;font-size:.74rem;color:#94a3b8;text-align:right">'+e[i][1]+'</span>';g.appendChild(r);ci++}b.appendChild(g);c.appendChild(b)}
function buildDonut(t,d,c){var b=document.createElement('div');b.style.cssText='background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;box-shadow:var(--shadow)';var h=document.createElement('h3');h.style.cssText='font-size:.86rem;margin-bottom:10px;color:#e2e8f0';h.textContent=t;b.appendChild(h);var tot=Object.values(d).reduce(function(a,b){return a+b},0);if(!tot){b.innerHTML+='<p style="color:#94a3b8">No data.</p>';c.appendChild(b);return}var dc=document.createElement('div');dc.style.cssText='display:flex;align-items:center;gap:18px;flex-wrap:wrap';var sz=130,cx=65,cy=65,r=48,cf=2*Math.PI*r;var s='<svg width="'+sz+'" height="'+sz+'" viewBox="0 0 '+sz+' '+sz+'">';var off=0,ci=0,e=Object.entries(d);for(var i=0;i<e.length;i++){var pc=e[i][1]/tot,da=pc*cf,ga=cf-da;s+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+COLORS[ci%COLORS.length]+'" stroke-width="14" stroke-dasharray="'+da.toFixed(2)+' '+ga.toFixed(2)+'" stroke-dashoffset="'+(-off).toFixed(2)+'" transform="rotate(-90 '+cx+' '+cy+')" />';off+=da;ci++}s+='<text x="'+cx+'" y="'+cy+'" text-anchor="middle" dominant-baseline="central" fill="#e2e8f0" font-size="18" font-weight="700">'+tot+'</text></svg>';dc.innerHTML=s;var lg=document.createElement('div');lg.style.cssText='display:flex;flex-direction:column;gap:3px';ci=0;for(var i=0;i<e.length;i++){var pc=((e[i][1]/tot)*100).toFixed(1);var it=document.createElement('div');it.style.cssText='display:flex;align-items:center;gap:6px;font-size:.74rem;color:#94a3b8';it.innerHTML='<span style="width:10px;height:10px;border-radius:2px;background:'+COLORS[ci%COLORS.length]+';flex-shrink:0"></span>'+e[i][0]+': '+e[i][1]+' ('+pc+'%)';lg.appendChild(it);ci++}dc.appendChild(lg);b.appendChild(dc);c.appendChild(b)}
(function(){var c=document.getElementById('chartsContainer');if(!c)return;
buildBarChart('Pillar Scores (%)',$PillarChartJSON,c);
buildDonut('Check Results',$StatusChartJSON,c);
})();
(function(){var lk=document.querySelectorAll('.sidebar nav a');var sc=[];for(var i=0;i<lk.length;i++){var id=lk[i].getAttribute('href');if(id&&id.charAt(0)==='#'){var el=document.querySelector(id);if(el)sc.push({el:el,link:lk[i]})}}window.addEventListener('scroll',function(){var cur=sc[0];for(var i=0;i<sc.length;i++){if(sc[i].el.getBoundingClientRect().top<=120)cur=sc[i]}for(var i=0;i<lk.length;i++)lk[i].classList.remove('active');if(cur)cur.link.classList.add('active')})})();
</script>
</body>
</html>
<!--
================================================================================
  ZeroTrustCanvas -- Zero Trust Security Posture Assessment
  Author : Santhosh Sivarajan, Microsoft MVP
  GitHub : https://github.com/SanthoshSivarajan/ZeroTrustCanvas
================================================================================
-->
"@

$HTML | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
$FileSize = [math]::Round((Get-Item $OutputFile).Length / 1KB, 1)

Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Green
Write-Host "  |   ZeroTrustCanvas -- Assessment Complete                   |" -ForegroundColor Green
Write-Host "  +============================================================+" -ForegroundColor Green
Write-Host ""
Write-Host "  ZERO TRUST MATURITY" -ForegroundColor White
Write-Host "  --------------------" -ForegroundColor Gray
Write-Host "    Overall Score     : $overallPct% ($(Get-Maturity $overallPct))" -ForegroundColor $(if($overallPct -ge 80){'Green'}elseif($overallPct -ge 50){'Yellow'}else{'Red'})
Write-Host ""
foreach ($p in $Pillars) {
    $s = $PillarScores[$p]
    $c = if($s.Pct -ge 80){'Green'}elseif($s.Pct -ge 50){'Yellow'}else{'Red'}
    Write-Host "    $($p.PadRight(18)) : $($s.Pct)% ($(Get-Maturity $s.Pct))" -ForegroundColor $c
}
Write-Host ""
Write-Host "    Total Checks   : $($AllChecks.Count) (Pass: $totalPass, Warning: $totalWarn, Fail: $totalFail)" -ForegroundColor White
Write-Host ""
Write-Host "  OUTPUT" -ForegroundColor White
Write-Host "  ------" -ForegroundColor Gray
Write-Host "    Report File : $OutputFile" -ForegroundColor White
Write-Host "    File Size   : $FileSize KB" -ForegroundColor White
Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host "  |  This report was generated using ZeroTrustCanvas v1.0      |" -ForegroundColor Cyan
Write-Host "  |  Developed by Santhosh Sivarajan, Microsoft MVP            |" -ForegroundColor Cyan
Write-Host "  |  https://github.com/SanthoshSivarajan/ZeroTrustCanvas      |" -ForegroundColor Cyan
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host ""

<#
================================================================================
  ZeroTrustCanvas v1.0 -- Zero Trust Security Posture Assessment
  Author : Santhosh Sivarajan, Microsoft MVP
  GitHub : https://github.com/SanthoshSivarajan/ZeroTrustCanvas
================================================================================
#>
