import os
import requests
import json
from langchain.tools import tool

# Path to the enterprise-attack.json file
STIX_FILE = "enterprise-attack.json"
STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

def download_stix():
    """Download the MITRE ATT&CK STIX data if it doesn't exist."""
    if not os.path.exists(STIX_FILE):
        print(f"Downloading STIX data from {STIX_URL}...")
        response = requests.get(STIX_URL)
        response.raise_for_status()
        with open(STIX_FILE, "w", encoding="utf-8") as f:
            json.dump(response.json(), f)
        print("STIX data downloaded and cached.")

@tool
def mitre_lookup(query: str) -> str:
    """
    Search for MITRE ATT&CK technique details including name, description, tactic, and sub-techniques.
    Accepts a technique ID (e.g., T1059) or a technique name (e.g., PowerShell).
    """
    download_stix()
    
    try:
        with open(STIX_FILE, "r", encoding="utf-8") as f:
            stix_data = json.load(f)
        
        objects = stix_data.get("objects", [])
        
        # Search for the technique
        technique = None
        for obj in objects:
            if obj.get("type") == "attack-pattern":
                # Check for ID match
                external_ids = [ext.get("external_id") for ext in obj.get("external_references", []) if ext.get("source_name") == "mitre-attack"]
                if query.upper() in [eid.upper() for eid in external_ids]:
                    technique = obj
                    break
                # Check for Name match
                if query.lower() == obj.get("name", "").lower():
                    technique = obj
                    break
        
        if not technique:
            return f"No MITRE ATT&CK technique found for query: {query}"
        
        t_id = next((ext.get("external_id") for ext in technique.get("external_references", []) if ext.get("source_name") == "mitre-attack"), "N/A")
        name = technique.get("name", "N/A")
        description = technique.get("description", "No description available.")
        tactics = [phase.get("phase_name") for phase in technique.get("kill_chain_phases", []) if phase.get("kill_chain_name") == "mitre-attack"]
        
        # Find sub-techniques
        sub_techniques = []
        for obj in objects:
            if obj.get("type") == "attack-pattern":
                if obj.get("x_mitre_is_subtechnique"):
                    # Check if this sub-technique belongs to the current technique
                    # This is usually done via relationship objects, but for simplicity we can check the ID prefix
                    # e.g. T1059.001 belongs to T1059
                    parent_id = t_id
                    current_ext_id = next((ext.get("external_id") for ext in obj.get("external_references", []) if ext.get("source_name") == "mitre-attack"), "")
                    if current_ext_id.startswith(f"{parent_id}."):
                        sub_techniques.append(f"{current_ext_id}: {obj.get('name')}")

        result = (
            f"Technique ID: {t_id}\n"
            f"Technique Name: {name}\n"
            f"Tactics: {', '.join(tactics)}\n"
            f"Description: {description[:1000]}{'...' if len(description) > 1000 else ''}\n"
            f"Sub-techniques: {', '.join(sub_techniques) if sub_techniques else 'None'}"
        )
        return result

    except Exception as e:
        return f"Error querying MITRE ATT&CK data: {str(e)}"
