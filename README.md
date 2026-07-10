# Context-Aware Web Fuzzer

A lightweight Python tool for fuzzing RESTful API endpoints using context-aware payload selection and feedback-driven analysis.

## Features

- Load target config from JSON
- Support Bearer Token / Cookie auth
- Collect baseline response
- Classify parameters by type and risk tag
- Generate light/deep payloads
- Analyze response anomalies
- Escalate suspicious cases
- Calculate confidence score
- Generate HTML/JSON reports

## Supported Checks

- SQL Injection
- XSS Reflection
- Path Traversal
- Command Injection
- IDOR Candidate

## Project Structure

```text
core/        Main fuzzing modules
payloads/    Payload JSON files
config/      Target and auth config
reports/     Generated reports
demo_lab.py  Local vulnerable demo lab
main.py      Entry point
```

## Installation

```bash
pip install -r requirements.txt
```

## Run Demo Lab

```bash
python demo_lab.py
```

Demo server:

```text
http://localhost:5000
```

## Run Fuzzer

```bash
python main.py
```

Optional:

```bash
python main.py --max-payloads-per-point 5 --max-deep-payloads 3
```

## Configuration

Edit target config:

```text
config/target.json
```

Example:

```json
{
  "target_url": "http://localhost:5000/api/users",
  "method": "GET",
  "params": {
    "id": "1"
  },
  "json_body": {},
  "timeout": 10,
  "verify_ssl": false
}
```

For no authentication:

```json
{
  "auth_enabled": false
}
```

## Reports

Reports are generated in:

```text
reports/report.json
reports/report.html
```

Open HTML report on Windows:

```bash
start reports/report.html
```

## Workflow

```text
Load Config
→ Collect Baseline
→ Classify Parameters
→ Generate Payloads
→ Fuzz Request
→ Analyze Response
→ Escalate if Suspicious
→ Score Confidence
→ Generate Report
```

## Demo Endpoints

```text
GET  /api/users?id=1          SQLi-like, IDOR
GET  /api/search?q=test       Reflected XSS
GET  /api/files?path=test     Path Traversal
POST /api/login               Bearer Token demo
```

## Safety Notice

This tool is for educational and authorized security testing only.  
Do not test systems without permission.

## Author

Đào Văn Chiến  
Hanoi University of Science and Technology
