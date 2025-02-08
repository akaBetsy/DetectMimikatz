import winreg
import json

# Function to check registry values and log results
def check_registry_value(hive, subkey, results):
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, i)
                    alert_message = f"[ALERT] Possible Defense Evasion detected: {subkey} -> {value_name} = {value_data}"
                    print(alert_message)
                    results.append({"subkey": subkey, "value_name": value_name, "value_data": value_data})
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        print(f"[OK] No exclusions found in {subkey}")
    except Exception as e:
        print(f"Error accessing registry: {e}")

# Define registry keys to check for exclusions
registry_keys = [
    r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
    r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
    r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"
]

# Store results in a list
results = []

# Check each registry key
for reg_key in registry_keys:
    check_registry_value(winreg.HKEY_LOCAL_MACHINE, reg_key, results)

# Export results to JSON
with open("defense_evasion_results.json", "w", encoding="utf-8") as json_file:
    json.dump(results, json_file, indent=4, ensure_ascii=False)

print("Results saved to defense_evasion_results.json")
