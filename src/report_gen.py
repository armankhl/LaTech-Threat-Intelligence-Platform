import os
import subprocess
import shutil
import requests # <--- We will use this to call n8n
import json
from pathlib import Path

class ReportGenerator:
    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.tex_dir = self.base_dir / "reports" / "tex_output"
        self.pdf_dir = self.base_dir / "reports" / "pdf_output"
        
        # Add your n8n webhook URL here (Production or Test URL)
        self.n8n_webhook_url = "https://n8nlatech.lajvardtech.com:6789/webhook-test/generate-latex"

        self.tex_dir.mkdir(parents=True, exist_ok=True)
        self.pdf_dir.mkdir(parents=True, exist_ok=True)

    def ask_n8n_for_latex(self, vulnerability_data: list) -> str:
        """
        Sends the JSON vulnerability data to the n8n Webhook and retrieves the LaTeX string.
        """
        print("[*] Sending data to n8n AI Agent...")
        
        # We package the data nicely for the n8n webhook
        payload = {
            "cve_data": vulnerability_data
        }

        try:
            response = requests.post(self.n8n_webhook_url, json=payload, timeout=120)
            response.raise_for_status()
            
            # Assuming n8n responds with raw text, or adjust if you configured JSON response
            latex_code = response.text 
            
            # Clean up potential markdown formatting the LLM might stubbornly include
            latex_code = latex_code.replace("```latex\n", "").replace("```", "")
            
            print("[+] Successfully received LaTeX code from n8n!")
            return latex_code
            
        except requests.exceptions.RequestException as e:
            print(f"[!] Failed to communicate with n8n: {e}")
            return ""

    def generate_pdf(self, latex_content: str, filename: str = "daily_threat_report"):
        """
        Saves LaTeX content to a file and compiles it into a PDF using XeLaTeX.
        """
        if not latex_content:
            print("[!] No LaTeX content provided to compile.")
            return False

        tex_file_path = self.tex_dir / f"{filename}.tex"
        final_pdf_path = self.pdf_dir / f"{filename}.pdf"

        # 1. Write the LaTeX content
        print(f"[*] Saving LaTeX source to {tex_file_path}...")
        with open(tex_file_path, "w", encoding="utf-8") as f:
            f.write(latex_content)

        # 2. Compile with XeLaTeX
        print(f"[*] Compiling PDF using XeLaTeX...")
        process = subprocess.run(
            ["xelatex", "-interaction=nonstopmode", f"{filename}.tex"],
            cwd=self.tex_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if process.returncode != 0:
            print(f"[!] XeLaTeX Compilation Failed!")
            return False

        # 3. Move PDF and cleanup
        if (self.tex_dir / f"{filename}.pdf").exists():
            shutil.move(str(self.tex_dir / f"{filename}.pdf"), str(final_pdf_path))
            print(f"[+] Final PDF Ready: {final_pdf_path}")
            self._cleanup_aux_files(filename)
            return True
        return False

    def _cleanup_aux_files(self, filename: str):
        extensions_to_delete = ['.aux', '.log', '.nav', '.out', '.snm', '.toc']
        for ext in extensions_to_delete:
            file_to_delete = self.tex_dir / f"{filename}{ext}"
            if file_to_delete.exists():
                os.remove(file_to_delete)