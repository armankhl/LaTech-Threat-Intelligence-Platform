from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os
import json

from db_manager import DatabaseManager
from nvd_engine import NVDEngine
from asset_mapper import AssetMapper
from report_gen import ReportGenerator

app = FastAPI(
    title="Nexus Threat Intelligence API",
    description="Enterprise API for Vulnerability Ingestion, Asset Correlation, and Reporting.",
    version="1.5.0"
)

# --- MODELS ---
class LatexPayload(BaseModel):
    latex_code: str
    filename: str = "Nexus_Threat_Intel"

class AssetPayload(BaseModel):
    asset_id: str
    hostname: str
    ip_address: str
    vendor: str
    product: str
    version: str
    cpe_string: str

# --- 1. VULNERABILITY ENDPOINTS ---

@app.get("/api/v1/cves/daily")
def fetch_daily_cves():
    """Microservice 1: Fetches the last 24h of high-severity CVEs from NVD."""
    try:
        nvd = NVDEngine()
        daily_threats = nvd.get_daily_high_severity_cves(min_cvss_score=8.0)
        
        if daily_threats:
            db = DatabaseManager()
            db.save_cves(daily_threats)
            db.close()
            return {"status": "success", "cves_ingested": len(daily_threats)}
        return {"status": "success", "message": "No new high-severity CVEs found today."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/cves/{cve_id}")
def get_single_cve(cve_id: str):
    """
    Microservice 2 (For Future AI Agent): 
    Searches the local database for a CVE. If not found, fetches it from NVD API.
    """
    db = DatabaseManager()
    db.cursor.execute("SELECT * FROM daily_cves WHERE cve_id = %s", (cve_id,))
    row = db.cursor.fetchone()
    db.close()

    if row:
        return {"source": "local_database", "data": row}
    
    # If not in DB, fallback to NVD API
    nvd = NVDEngine()
    cve_data = nvd.get_cve_by_id(cve_id)
    if cve_data:
        return {"source": "nvd_api", "data": cve_data}
    
    raise HTTPException(status_code=404, detail="CVE not found locally or on NVD.")

# --- 2. ASSET & CORRELATION ENDPOINTS ---

@app.post("/api/v1/assets/match")
def trigger_correlation():
    """Microservice 3: Correlates local DB assets against ingested CVEs."""
    try:
        mapper = AssetMapper()
        mapper.run_correlation()
        mapper.db.close()
        return {"status": "success", "message": "Correlation engine executed successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/assets")
def add_new_asset(asset: AssetPayload):
    """Microservice 4: Add a new asset to the inventory (Prepares for Tenable API)."""
    db = DatabaseManager()
    try:
        query = """
            INSERT INTO assets_inventory (asset_id, hostname, ip_address, vendor, product, version, cpe_string)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (asset_id) DO UPDATE SET
                ip_address = EXCLUDED.ip_address,
                version = EXCLUDED.version;
        """
        db.cursor.execute(query, (
            asset.asset_id, asset.hostname, asset.ip_address, 
            asset.vendor, asset.product, asset.version, asset.cpe_string
        ))
        db.close()
        return {"status": "success", "message": f"Asset {asset.hostname} added/updated."}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))

# --- 3. REPORTING ENDPOINTS ---

@app.post("/api/v1/reports/generate-pdf")
def compile_pdf(payload: LatexPayload):
    """Microservice 5: Compiles a raw LaTeX string into a Persian PDF."""
    generator = ReportGenerator()
    clean_latex = payload.latex_code.replace("```latex", "").replace("```", "").strip()
    
    success = generator.generate_pdf(clean_latex, payload.filename)
    
    if success:
        pdf_path = generator.pdf_dir / f"{payload.filename}.pdf"
        if pdf_path.exists():
            return FileResponse(path=pdf_path, media_type='application/pdf', filename=f"{payload.filename}.pdf")
            
    raise HTTPException(status_code=500, detail="Failed to compile XeLaTeX PDF.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)