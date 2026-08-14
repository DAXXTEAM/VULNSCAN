# VULNSCAN
Automated Web Vulnerability Scanner - BTech Final Year Project

## Features
- HTTP Security Headers Analysis
- SSL/TLS Certificate Verification
- Technology Stack Detection
- Common Exposed Files Detection
- DNS Information Gathering
- Robots.txt Analysis
- Cookie Security Flags Check
- CORS Policy Analysis
- Server Version Disclosure Detection

## Run
```bash
pip install -r requirements.txt
python app.py
```

## Usage
Open http://localhost:5000
Enter any URL and click SCAN

## API
```bash
# Start a scan
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'

# Get report
curl http://localhost:5000/report/<scan_id>
```

## Author
Arpit Singh (DAXX)
BTech Final Year Project - Security & Software Domain

## Disclaimer
This tool performs PASSIVE reconnaissance only. No active exploitation is performed.
Only use on targets you have written authorization to test.
