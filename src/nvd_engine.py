import requests
import datetime
import json
import urllib.parse

class NVDEngine:
    def __init__(self, api_key=None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {"apiKey": api_key} if api_key else {}
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def get_cve_by_id(self, cve_id: str) -> dict:
        """
        Fetches information for a specific CVE ID.
        """
        print(f"[*] Fetching data for {cve_id}...")
        url = f"{self.base_url}?cveId={cve_id}"
        
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get('resultsPerPage', 0) > 0:
                print(f"[+] Successfully retrieved {cve_id}")
                return data['vulnerabilities'][0]['cve']
            else:
                print(f"[-] No data found for {cve_id}")
                return {}
                
        except requests.exceptions.RequestException as e:
            print(f"[!] Error fetching {cve_id}: {e}")
            return {}

    def get_daily_high_severity_cves(self, min_cvss_score: float = 8.0) -> list:
        """
        Fetches yesterday's published CVEs, filters for CVSS > 8.0, 
        and extracts CPE, CWE, and Remediation Links.
        """
        today = datetime.datetime.now(datetime.timezone.utc)
        yesterday = today - datetime.timedelta(days=1)
        
        start_date = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = yesterday.replace(hour=23, minute=59, second=59, microsecond=999000)
        
        pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.999")
        
        print(f"[*] Fetching CVEs published between {pub_start} and {pub_end}...")
        url = f"{self.base_url}?pubStartDate={pub_start}&pubEndDate={pub_end}"
        
        try:
            response = self.session.get(url, timeout=20)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as e:
            print(f"[!] API Request Failed: {e}")
            return []

        vulnerabilities = data.get('vulnerabilities', [])
        print(f"[*] Total CVEs published yesterday: {len(vulnerabilities)}")
        
        high_severity_cves = []

        for item in vulnerabilities:
            cve = item.get('cve', {})
            cve_id = cve.get('id', 'UNKNOWN')
            metrics = cve.get('metrics', {})
            
            # --- 1. Extract CVSS Score ---
            cvss_data = None
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
            elif 'cvssMetricV40' in metrics:
                cvss_data = metrics['cvssMetricV40'][0]['cvssData']

            if cvss_data:
                base_score = float(cvss_data.get('baseScore', 0.0))
                
                if base_score > min_cvss_score:
                    # --- 2. Extract CWEs (Root Cause) ---
                    cwes = []
                    for weakness in cve.get('weaknesses', []):
                        for desc in weakness.get('description', []):
                            if 'value' in desc and "CWE" in desc['value']:
                                cwes.append(desc['value'])
                    
                    # --- 3. Extract CPEs (Vulnerable Products) ---
                    cpes = []
                    for config in cve.get('configurations', []):
                        for node in config.get('nodes', []):
                            for cpe_match in node.get('cpeMatch', []):
                                if 'criteria' in cpe_match:
                                    cpes.append(cpe_match['criteria'])
                    
                    # --- 4. Extract References (Patch/Info Links) ---
                    references = []
                    for ref in cve.get('references', []):
                        if 'url' in ref:
                            references.append(ref['url'])

                    # Aggregate everything into our clean dictionary
                    high_severity_cves.append({
                        "CVE_ID": cve_id,
                        "Base_Score": base_score,
                        "Severity": cvss_data.get('baseSeverity', 'UNKNOWN'),
                        "CWE": list(set(cwes)), # Remove duplicates
                        "CPEs": list(set(cpes))[:5], # Limit to first 5 to prevent report bloat
                        "References": references[:4], # Limit to top 4 links
                        "Description": cve.get('descriptions', [{}])[0].get('value', 'No description')
                    })
        
        print(f"[+] Found {len(high_severity_cves)} CVEs with score > {min_cvss_score}")
        return high_severity_cves

# ==========================================
# TEST THE SCRIPT
# ==========================================
if __name__ == "__main__":
    engine = NVDEngine(api_key=None) 

    print("\n--- TEST: Daily High Severity CVEs (With CPE, CWE, Links) ---")
    daily_cves = engine.get_daily_high_severity_cves(min_cvss_score=8.0)
    
    # Print the first extracted CVE to see the new data structure
    if daily_cves:
        print(json.dumps(daily_cves[:2], indent=4))
    else:
        print("No high severity CVEs found for yesterday.")