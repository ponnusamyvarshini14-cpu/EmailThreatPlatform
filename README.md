# EmailThreatPlatform

Professional prototype for AI-assisted email threat detection, IP intelligence and digital-forensic case management.

## Run

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000`.

Demo login: `admin` / `sih2026`

## Main workflow

Login/Register -> Upload Email -> Combined Threat Analysis -> Dashboard -> Location Intelligence -> Case -> Activity Log.

The IP location is treated as an independent intelligence signal. A safe/known location never overrides malicious or suspicious email content. If no verified public sender IP is available, the platform clearly shows that location is unavailable instead of inventing a map location.


Location Intelligence is available from the left sidebar and shows approximate sender-IP location only when a verified public IP can be resolved. Forensic PDF Reports are not included in this version.


## Forensic Reports
Each analyzed email can generate a detailed PDF forensic report from the analysis result page. Reports are accessible from the Forensic Reports section. Dashboard does not display a map; Location Intelligence is a separate one-case-at-a-time page.
