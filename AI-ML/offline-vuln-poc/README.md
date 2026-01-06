# Autonomous Offline Vulnerability Intelligence & Actionable Risk Mitigation Platform (POC)
 
## Overview
 
This project is a **fully offline, cross-platform POC** for ingesting, analyzing, and remediating vulnerabilities from Windows and Linux systems. It provides:

- Offline ML (RandomForest) risk classification

- Local LLM-powered remediation and mapping (Ollama, phi/phi-4-mini)

- Professional dashboards & reporting (Streamlit)

- Robust data collection scripts (Linux Bash, Windows PowerShell)

- All data processed and stored locally
 
---
 
## Project Structure
 
```

offline-vuln-poc/

│

├── main_dashboard_app.py         # Main dashboard Streamlit app

├── generate_sample_data.py       # Utility for generating demo scan data

├── requirements.txt              # Python dependencies

├── scanLinuxOS.sh                # Linux scan script

├── scanWindows.ps1               # Windows scan script (optional)

├── sample_vulnerability_data/    # Folder created for generated data

│   ├── vulnerabilities.json

│   ├── vulnerabilities.csv

│   ├── nessus_scan.csv

│   ├── openvas_scan.csv

│   └── qualys_scan.csv

```
 
---
 
## Setup & Usage
 
### 1. Prerequisites
 
- Python 3.8+

- [Ollama](https://ollama.com/download) installed **with phi-4-mini or phi3 model pulled**

- No internet required after setup
 
---
 
### 2. Install Python Requirements
 
```bash

pip install -r requirements.txt

```
 
---
 
### 3. Generate Sample Data
 
```bash

python generate_sample_data.py

# This creates sample_vulnerability_data/ with various test scan files

```
 
---
 
### 4. (Optional) Run System Scan Scripts
 
- **Linux:**  

  ```bash

  sudo bash scanLinuxOS.sh

  # Upload the generated CSV in the dashboard

  ```

- **Windows:**  

  Run `scanWindows.ps1` in PowerShell as admin, or use the in-app scan option.
 
---
 
### 5. Start Ollama LLM (if not running)
 
```bash

ollama serve

# Ensure model is pulled: ollama pull phi-4-mini

```
 
---
 
### 6. Run the Dashboard
 
```bash

streamlit run main_dashboard_app.py

```
 
- Use the UI to upload any of the generated scan files from `sample_vulnerability_data/`

- Explore all dashboard and analysis features
 
---
 
## Security
 
- All data remains on your system—no cloud dependencies.

- All LLM/ML is performed locally.
 
---
 
## Notes
 
- For custom branding, add your logo to Streamlit’s sidebar/header.

- For PDF export, install `pdfkit` and `wkhtmltopdf` if desired.
 
---
 
## Support
 
For any issues or demo help, contact your POC developer.

 