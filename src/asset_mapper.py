import json
from db_manager import DatabaseManager

class AssetMapper:
    def __init__(self):
        self.db = DatabaseManager()

    def run_correlation(self):
        """Matches database CVEs against the PostgreSQL asset inventory."""
        
        # 1. Load Assets from Database
        self.db.cursor.execute("SELECT asset_id, hostname, ip_address, vendor, product, version FROM assets_inventory")
        assets = self.db.cursor.fetchall()
        
        if not assets:
            print("[-] No assets found in the database. Cannot run correlation.")
            return

        # 2. Load Recent CVEs
        self.db.cursor.execute("""
            SELECT cve_id, cpes 
            FROM daily_cves 
            WHERE discovered_at >= NOW() - INTERVAL '30 days'
        """)
        cves = self.db.cursor.fetchall()
        print(f"[*] Analyzing {len(cves)} recent CVEs against {len(assets)} internal assets...")

        matched_cves = 0

        # 3. Correlation Engine
        for cve_id, cve_cpes in cves:
            if isinstance(cve_cpes, str):
                try:
                    cve_cpes = json.loads(cve_cpes)
                except json.JSONDecodeError:
                    continue
                    
            if not cve_cpes or not isinstance(cve_cpes, list):
                continue

            affected_internal_assets = []

            for vul_cpe in cve_cpes:
                for asset_id, hostname, ip_address, vendor, product, version in assets:
                    # Safely clean strings
                    vendor_clean = str(vendor).strip().lower()
                    product_clean = str(product).strip().lower()
                    
                    match_string = f":{vendor_clean}:{product_clean}:"
                    
                    if match_string in vul_cpe.lower():
                        affected_internal_assets.append({
                            "Asset_ID": asset_id,
                            "Hostname": hostname,
                            "IP_Address": ip_address,
                            "Product": f"{vendor} {product}"
                        })

            if affected_internal_assets:
                unique_assets = list({a['Asset_ID']: a for a in affected_internal_assets}.values())
                print(f"[+] MATCH FOUND: {cve_id} affects {len(unique_assets)} asset(s)! (e.g., {unique_assets[0]['Hostname']})")
                
                update_query = """
                    UPDATE daily_cves 
                    SET is_matched = TRUE, affected_assets = %s
                    WHERE cve_id = %s
                """
                self.db.cursor.execute(update_query, (json.dumps(unique_assets), cve_id))
                matched_cves += 1

        print(f"[*] Correlation complete. {matched_cves} relevant CVEs found.")

if __name__ == "__main__":
    mapper = AssetMapper()
    mapper.run_correlation()
    mapper.db.close()