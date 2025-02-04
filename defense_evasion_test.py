import subprocess
import time
import os

# Function to generate test data for Mimikatz attack simulation
# Each step corresponds to a stage in the MITRE ATT&CK framework

def generate_test_data():
    print("Generating test data for Mimikatz attack simulation...")

    # Defense Evasion - Create an exclusion directory in Windows Defender manually (MITRE ATT&CK: T1562.001)
    try:
        os.makedirs("C:\\ExcludedFolder", exist_ok=True)
        print("[SUCCESS] Exclusion directory created: C:\\ExcludedFolder")
    except Exception as e:
        print(f"[ERROR] Failed to create exclusion directory: {e}")

    time.sleep(2)
    print("Test data generation complete.")

if __name__ == "__main__":
    generate_test_data()

