import sys
import os

# Add the current directory to sys.path so we can import from 'agent'
sys.path.append(os.getcwd())

from agent.tools.cve_lookup import cve_lookup
from agent.tools.mitre_lookup import mitre_lookup

print("--- Testing CVE Lookup ---")
try:
    cve_res = cve_lookup.invoke("CVE-2024-21762")
    print(cve_res)
except Exception as e:
    print(f"CVE Lookup Error: {e}")

print("\n--- Testing MITRE Lookup ---")
try:
    mitre_res = mitre_lookup.invoke("T1059.001")
    print(mitre_res)
except Exception as e:
    print(f"MITRE Lookup Error: {e}")

print("\n--- Testing MITRE Lookup by Name ---")
try:
    mitre_res_name = mitre_lookup.invoke("PowerShell")
    print(mitre_res_name)
except Exception as e:
    print(f"MITRE Lookup (Name) Error: {e}")
