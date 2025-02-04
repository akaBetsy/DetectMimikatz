import os
import subprocess
import win32evtlog
import win32evtlogutil
import wmi

# Function to check if Sysmon service is running
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

    # Simulate Mimikatz-like commands
    subprocess.run(["cmd.exe", "/c", "echo sekurlsa::logonpasswords"], shell=True)
    subprocess.run(["cmd.exe", "/c", "echo lsadump::dcsync"], shell=True)

    # Simulate Registry modification
    print("[*] Testing registry modification detection...")
    reg_cmd = r'reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f'
    subprocess.run(["cmd.exe", "/c", reg_cmd], shell=True)

# Function to fetch Sysmon logs
def fetch_sysmon_logs():
    print("[*] Checking Sysmon event logs...")
    event_log = "Microsoft-Windows-Sysmon/Operational"
    return fetch_windows_logs(event_log, [1, 5, 10])

# Function to fetch Windows Security logs
def fetch_security_logs():
    print("[*] Checking Windows Security logs...")
    security_event_ids = [4624, 4672, 4688, 4719, 4776, 1102]
    return fetch_windows_logs("Security", security_event_ids)

# Generic function to fetch Windows Event Logs
def fetch_windows_logs(log_name, event_ids):
    logs_found = False
    try:
        hand = win32evtlog.OpenEventLog(None, log_name)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        total = win32evtlog.GetNumberOfEventLogRecords(hand)

        print(f"[*] Reading logs from {log_name}... (Total: {total} events)")

        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                break
            for event in events:
                if event.EventID in event_ids:
                    logs_found = True
                    print(f"[✔] Detected Event {event.EventID} at {event.TimeGenerated}")
        
        win32evtlog.CloseEventLog(hand)
    except Exception as e:
        print(f"[✖] Error reading {log_name}: {e}")

    if not logs_found:
        print(f"[✖] No relevant events found in {log_name}.")
    return logs_found

# Main function to orchestrate checks
def main():
    print("\n===== Sysmon & Security Log Validation Script =====")

    if not check_sysmon_service():
        return
    if not check_sysmon_config():
        return

    trigger_test_events()

    sysmon_detected = fetch_sysmon_logs()
    security_detected = fetch_security_logs()

    if sysmon_detected or security_detected:
        print("[✔] Security configuration validation complete! Events detected.")
    else:
        print("[✖] No security events detected. Check configurations!")

if __name__ == "__main__":
    main()
