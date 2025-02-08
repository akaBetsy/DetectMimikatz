# PowerShell Script to Configure Sysmon and Security Events for Mimikatz Detection
# Based on MITRE ATT&CK Framework and Various Security References

# References:
# - SwiftOnSecurity Sysmon Config: https://github.com/SwiftOnSecurity/sysmon-config
# - Mimikatz detection techniques: https://attack.mitre.org/techniques/T1003/
# - Sysmon Event Filtering Guide: https://medium.com/@cyb3rops/sysmon-event-filtering-guide-1c9bcd4d4f27
# - ADSecurity Mimikatz Detection: https://adsecurity.org/?page_id=1821
# - scip AG - Detecting Attacks with MITRE ATT&CK: https://www.scip.ch/en/?labs.20190711
# - JPCERT/CC - Remote Login via Mimikatz: https://jpcertcc.github.io/ToolAnalysisResultSheet/details/RemoteLogin-Mimikatz.htm
# - Netwrix - Detecting Pass-the-Hash Attacks: https://blog.netwrix.com/2021/11/30/how-to-detect-pass-the-hash-attacks/
# - Additional Research: https://www.matteomalvica.com/blog/2020/01/20/mimikatz-lsass-dump-windg-pykd/

Write-Output "Configuring Windows Security Logging for Mimikatz detection."

# Define RuleNames for detection categories
$RuleNames = @{
    "Privilege Escalation" = "Mimikatz Detected: Privilege Escalation TA0004";
    "Credential Access" = "Mimikatz Detected: Credential Access TA0006 / Defense Evasion TA0005";
    "Execution" = "Mimikatz Detected: Execution TA0002";
}

# Enable Auditing for Critical Security Events
auditpol /set /category:"Account Logon" /success:disable /failure:enable
Write-Output $RuleNames["Credential Access"]

auditpol /set /category:"Logon/Logoff" /success:disable /failure:enable
Write-Output $RuleNames["Credential Access"]

auditpol /set /category:"Privilege Use" /success:disable /failure:enable
Write-Output $RuleNames["Credential Access"]

auditpol /set /category:"Object Access" /success:disable /failure:enable
Write-Output $RuleNames["Credential Access"]

auditpol /set /category:"System" /success:disable /failure:enable
Write-Output $RuleNames["Execution"]


# Enable Auditing for Privilege Escalation Detection
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable  # Event 4672
Write-Output $RuleNames["Privilege Escalation"]

auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable  # Event 4673
Write-Output $RuleNames["Privilege Escalation"]

auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable  # Event 4688
Write-Output $RuleNames["Privilege Escalation"]

auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable  # Event 4697
Write-Output $RuleNames["Privilege Escalation"]


# Configure Additional Auditing for Credential Theft Detection
auditpol /set /subcategory:"Credential Validation" /success:disable /failure:enable  # Event 4776
Write-Output $RuleNames["Credential Access"]

auditpol /set /subcategory:"Kerberos Authentication Service" /success:disable /failure:enable  # Event 4768
Write-Output $RuleNames["Credential Access"]

auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:disable /failure:enable  # Event 4769
Write-Output $RuleNames["Credential Access"]

auditpol /set /subcategory:"File System" /success:disable /failure:enable  # Event 5145
Write-Output $RuleNames["Credential Access"]

echo "Security logging enabled. Find logs under Event Viewer > Windows Logs > Security."


# Configure Sysmon 
Write-Output "Configuring Sysmon for Mimikatz detection."

# Ensure Sysmon is installed
if (-not (Get-Command sysmon -ErrorAction SilentlyContinue)) {
    Write-Output "Sysmon not found. Please install Sysmon from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon"
    exit
}

# Apply Sysmon configuration
sysmon -accepteula -i config-sysmon.xml
sc start sysmon

echo "Sysmon is now configured to detect Mimikatz activity. Find logs in Event Viewer > Applications and Services Logs > Microsoft > Windows > Sysmon."
