<#
.SYNOPSIS
    Read-Only Active Directory Identity Security Audit Script
.DESCRIPTION
    Audits Active Directory for AS-REP Roastable accounts, Kerberoastable SPNs,
    privileged Domain Admins exposure, and krbtgt password rotation hygiene.
.AUTHOR
    Juan Salas | Brazos Baseline Cybersecurity
#>

Import-Module ActiveDirectory
Write-Host "=== BRAZOS BASELINE CYBERSECURITY: AD IDENTITY HEALTH CHECK ===" -ForegroundColor Cyan

# 1. Check for AS-REP Roastable Accounts (Pre-Auth Disabled)
Write-Host "`n[1] Checking for AS-REP Roastable Accounts (Pre-Authentication Disabled)..." -ForegroundColor Yellow
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth, PasswordLastSet |
    Select-Object Name, SamAccountName, Enabled, PasswordLastSet | Format-Table -AutoSize

# 2. Check for Kerberoastable User Accounts (Non-Computer SPNs)
Write-Host "[2] Checking for Kerberoastable User Service Accounts (SPNs Registered)..." -ForegroundColor Yellow
Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires |
    Where-Object { $_.SamAccountName -ne "krbtgt" } |
    Select-Object Name, SamAccountName, PasswordLastSet, PasswordNeverExpires, @{N='SPNs';E={$_.ServicePrincipalName -join '; '}} | Format-Table -AutoSize

# 3. Check Privileged Group Memberships (DCSync / Domain Admin Exposure)
Write-Host "[3] Auditing Privileged Group Members (Domain Admins)..." -ForegroundColor Yellow
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName, objectClass | Format-Table -AutoSize

# 4. Check krbtgt Password Rotation Hygiene (Golden Ticket Exposure)
Write-Host "[4] Checking krbtgt Account Password Age..." -ForegroundColor Yellow
Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet |
    Select-Object Name, PasswordLastSet, @{N='DaysSinceRotation';E={(New-TimeSpan -Start $_.PasswordLastSet -End (Get-Date)).Days}} | Format-Table -AutoSize
