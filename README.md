1.	Prerequistes win10
-	For the VM: disable internet for lab setup
-	Setup local admin
-	Install python3
    o	python -m pip install --upgrade pip
    o	pip install wmi pywin32
    o	For Tristan’s scripts:
        	C:\python -m pip install psutil
        	C:\python -m pip install scapy
-	Install sysmon
-	Install procmon

2.	Security and Sysmon config 
-	Put the files on the target machine (in c:\temp)
    o	config-security-and-sysmon.ps1
    o	config-sysmon.xml
-	Runas administrator, Start powershell
    o	Set-ExecutionPolicy Unrestricted -Scope Process -Force
        	Select Yes to All (A)
    o	config-security-and-sysmon.ps1

3.	Simulating Mimikatz Behavior
-	test-sysmon-security.py
-	defense_evasion_test.py

4.	Export Logs to JSON 
-	export-logs-mitre.py
-	defense_evasion_export.py

