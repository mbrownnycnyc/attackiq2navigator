#If you want to update the mitre_techniques_data_summary.json file from the latest CTI provided enterprise-attack.json, you can run generate-mitre_technique_data.ps1.

winget install Python.Python.3.13 # this might change
python -m venv venv
. .\venv\Scripts\activate
pip install -r requirements.txt