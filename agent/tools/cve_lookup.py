import requests
from langchain.tools import tool

@tool
def cve_lookup(cve_id: str) -> str:
    """
    Search for CVE details including description, CVSS score, severity, and published date using the NVD API.
    Input should be a CVE ID (e.g., CVE-2024-21762).
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return f"No information found for {cve_id}."
        
        cve_data = vulnerabilities[0].get("cve", {})
        descriptions = cve_data.get("descriptions", [])
        description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No description available.")
        
        metrics = cve_data.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [])
        cvss_v30 = metrics.get("cvssMetricV30", [])
        cvss_v2 = metrics.get("cvssMetricV2", [])
        
        cvss_score = "N/A"
        severity = "N/A"
        
        if cvss_v31:
            cvss_score = cvss_v31[0].get("cvssData", {}).get("baseScore", "N/A")
            severity = cvss_v31[0].get("cvssData", {}).get("baseSeverity", "N/A")
        elif cvss_v30:
            cvss_score = cvss_v30[0].get("cvssData", {}).get("baseScore", "N/A")
            severity = cvss_v30[0].get("cvssData", {}).get("baseSeverity", "N/A")
        elif cvss_v2:
            cvss_score = cvss_v2[0].get("cvssData", {}).get("baseScore", "N/A")
            severity = cvss_v2[0].get("baseSeverity", "N/A")
            
        published_date = cve_data.get("published", "N/A")
        
        result = (
            f"CVE ID: {cve_id}\n"
            f"Description: {description}\n"
            f"CVSS Score: {cvss_score}\n"
            f"Severity: {severity}\n"
            f"Published Date: {published_date}"
        )
        return result
        
    except requests.exceptions.RequestException as e:
        return f"Error fetching CVE data for {cve_id}: {str(e)}"
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}"
