# PowerShell Script to Configure Sysmon and Security Events for Mimikatz Detection
# Based on MITRE ATT&CK Framework and Various Security References

# References:
# - SwiftOnSecurity Sysmon Config: https://github.com/SwiftOnSecurity/sysmon-config
# - Mimikatz detection techniques: https://attack.mitre.org/techniques/T1003/001/
# - Sysmon Event Filtering Guide: https://medium.com/@cyb3rops/sysmon-event-filtering-guide-1c9bcd4d4f27
# - ADSecurity Mimikatz Detection: https://adsecurity.org/?page_id=1821
# - scip AG - Detecting Attacks with MITRE ATT&CK: https://www.scip.ch/en/?labs.20190711
# - JPCERT/CC - Remote Login via Mimikatz: https://jpcertcc.github.io/ToolAnalysisResultSheet/details/RemoteLogin-Mimikatz.htm
# - Netwrix - Detecting Pass-the-Hash Attacks: https://blog.netwrix.com/2021/11/30/how-to-detect-pass-the-hash-attacks/
# - Additional Research: https://www.matteomalvica.com/blog/2020/01/20/mimikatz-lsass-dump-windg-pykd/

Write-Output "Enabling Windows Security Logging..."

# Step 1: Enable Auditing for Critical Security Events
# MITRE ATT&CK: T1003.001 (OS Credential Dumping: LSASS Memory)
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable

echo "Basic security logging enabled. Verify logs under Event Viewer > Windows Logs > Security."

# Step 2: Configure Additional Auditing for Credential Theft Detection
# MITRE ATT&CK: T1550.002 (Pass-the-Hash), T1078 (Valid Accounts)
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable  # Event 4776
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable  # Event 4768
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable  # Event 4769
auditpol /set /subcategory:"File System" /success:enable /failure:enable  # Event 5145 (Detect LSASS dump attempts)

echo "Enhanced security event monitoring enabled for credential access."

# Step 3: Configure Sysmon for LSASS Memory Access and Process Creation
Write-Output "Configuring Sysmon for LSASS access detection..."

# Ensure Sysmon is installed
if (-not (Get-Command sysmon64 -ErrorAction SilentlyContinue)) {
    Write-Output "Sysmon not found. Please install Sysmon from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon"
    exit
}

# Apply Sysmon configuration
sysmon -accepteula -i config-sysmon.xml
sc start sysmon

echo "Sysmon is now configured to detect Mimikatz activity. Check Event Viewer > Applications and Services Logs > Microsoft > Windows > Sysmon."
