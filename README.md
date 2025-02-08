1) Prerequistes win10 machine from module 5
   > Setup local admin
   > Install python3
   > Install sysmon
   > Install procmon
   > Place config files in C:\temp
   >> From github:
   >>> config-security-and-sysmon.ps1
   >>> config-sysmon.xml
   >>> mimikatz.exe
   >>> collector_security.py
   >>> collector_sysmon.py
   >>> extract_mimi_from_logs.py
   >> From sysinternals:
   >>> sysmon.exe
   >>> procmon.exe

3) Config win10 using PowerShell:
   > Set-ExecutionPolicy Unrestricted -Scope Process -Force
   > config-security-and-sysmon.ps1

4) Simulate Mimikatz Behavior & export logging using cmd (as administrator):
   > python test_mimikatz.py
   >> results in logs_security.json & logs_sysmon.json

5) Collect logs from sysmon and security
   > python extract_mimi_from_logs.py
   >> results in output_filtered_logs.json & output_mitre_stages_count.json

7) Read and interpret JSON output
   > output_filtered_logs.json
   > output_mitre_stages_count.json
   


