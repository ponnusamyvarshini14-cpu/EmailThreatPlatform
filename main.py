import os
import secrets
import shutil
from datetime import datetime, timezone

from fastapi import FastAPI, Request, File, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from modules.mail_parser import parse_eml
from modules.geolocation import get_geolocation
from modules.threat_score import compute_threat_score
from modules.ml_classifier import classify_email_text
from modules.auth import check_credentials, register_user, is_logged_in
from modules.forensics import analyze_urls, sha256_file, detect_injection, create_case, evidence_chain, _load_json, _save_json
from modules.report_generator import generate_report

app = FastAPI(title="EmailThreatPlatform - Email Threat Detection & Forensic Intelligence")
SESSION_SECRET = os.environ.get("SESSION_SECRET") or secrets.token_hex(32)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("reports", exist_ok=True)
ANALYSIS_CACHE: dict[str, dict] = {}
HISTORY: list[dict] = _load_json("history.json", [])
LOGS: list[dict] = _load_json("activity_log.json", [])


def log_action(request, action, detail=""):
    username = request.session.get("username", "unknown")
    LOGS.append({"time": datetime.now(timezone.utc).isoformat(), "user": username, "action": action, "detail": detail})
    _save_json("activity_log.json", LOGS[-500:])


def _safe_upload_filename(filename: str) -> str:
    base = os.path.basename(filename)
    safe = "".join(c for c in base if c.isalnum() or c in "._-")
    return safe or "upload.eml"


def _load_cached(filename):
    if filename in ANALYSIS_CACHE:
        return ANALYSIS_CACHE[filename]
    # Rebuild the lightweight analysis context after an app restart so
    # Location Intelligence and the dashboard do not lose geo data merely
    # because the in-memory cache was cleared.
    path = os.path.join(UPLOAD_FOLDER, _safe_upload_filename(filename))
    if os.path.exists(path):
        try:
            parsed = parse_eml(path)
            geo = get_geolocation(parsed.get("sender_ip"), parsed.get("ip_confidence"), parsed.get("from_domain", ""))
            cached = {"parsed": parsed, "geo": geo}
            ANALYSIS_CACHE[filename] = cached
            return cached
        except Exception:
            return None
    return None

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html", {})

@app.post("/register", response_class=HTMLResponse)
async def register_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    success, message = register_user(username, password)
    if success:
        return templates.TemplateResponse(request, "login.html", {"success": message})
    return templates.TemplateResponse(request, "register.html", {"error": message})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {})

@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    if check_credentials(username, password):
        request.session["logged_in"] = True
        request.session["username"] = username
        log_action(request, "LOGIN", "Successful login")
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": "Invalid username or password"})

@app.get("/logout")
async def logout(request: Request):
    log_action(request, "LOGOUT", "User logged out")
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    if not is_logged_in(request): return RedirectResponse(url="/login", status_code=303)
    recent = list(reversed(HISTORY[-8:]))
    return templates.TemplateResponse(request, "index.html", {"recent": recent})

@app.post("/upload", response_class=HTMLResponse)
async def upload_email(request: Request, file: UploadFile = File(...)):
    if not is_logged_in(request): return RedirectResponse(url="/login", status_code=303)
    if not file.filename.lower().endswith(".eml"):
        return templates.TemplateResponse(request, "index.html", {"error": "Please upload a valid .eml file.", "recent": list(reversed(HISTORY[-8:]))})
    safe_filename = _safe_upload_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, safe_filename)
    with open(file_path, "wb") as buffer: shutil.copyfileobj(file.file, buffer)

    parsed = parse_eml(file_path)
    geo = get_geolocation(parsed["sender_ip"], parsed["ip_confidence"], parsed.get("from_domain", ""))
    ml_result = classify_email_text(parsed["subject"], parsed["body_preview"])
    ml_result["injection_indicators"] = detect_injection(f"{parsed.get('subject','')}\n{parsed.get('body_preview','')}")
    url_findings = analyze_urls(parsed.get("urls", []))
    source_hash = sha256_file(file_path)
    threat = compute_threat_score(parsed, geo, ml_result, url_findings)
    case = create_case(parsed, geo, threat, url_findings, [], safe_filename)
    chain = evidence_chain(case["case_id"], source_hash, {"filename": safe_filename, "verdict": threat["verdict"], "score": threat["score"]})

    ANALYSIS_CACHE[safe_filename] = {"parsed": parsed, "geo": geo, "ml_result": ml_result, "threat": threat, "url_findings": url_findings, "source_hash": source_hash, "case": case, "chain": chain}
    record = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "filename": safe_filename, "sender": parsed.get("from_email") or "unknown", "subject": parsed.get("subject") or "(No subject)", "score": threat["score"], "verdict": threat["verdict"], "case_id": case["case_id"]}
    HISTORY.append(record); _save_json("history.json", HISTORY[-200:])
    log_action(request, "UPLOAD_EMAIL", f"{safe_filename} -> {threat['verdict']} ({threat['score']}/100), case {case['case_id']}")
    return templates.TemplateResponse(request, "result.html", {**ANALYSIS_CACHE[safe_filename], "filename": safe_filename})

@app.get("/email/{filename}", response_class=HTMLResponse)
async def view_email(request: Request, filename: str):
    if not is_logged_in(request): return RedirectResponse(url="/login", status_code=303)
    cached = _load_cached(filename)
    if not cached: return HTMLResponse("Analysis not available. Upload the email again.", status_code=404)
    return templates.TemplateResponse(request, "result.html", {**cached, "filename": filename})

@app.post("/email/{filename}/delete")
async def delete_email(request: Request, filename: str, password: str = Form(...)):
    if not is_logged_in(request): return RedirectResponse(url="/login", status_code=303)
    username = request.session.get("username", "")
    if not check_credentials(username, password):
        log_action(request, "DELETE_FAILED", f"Incorrect password for {filename}")
        return RedirectResponse(url=f"/email/{filename}?delete_error=1", status_code=303)
    path = os.path.join(UPLOAD_FOLDER, _safe_upload_filename(filename))
    try:
        if os.path.exists(path): os.remove(path)
    except OSError: pass
    ANALYSIS_CACHE.pop(filename, None)
    global HISTORY
    HISTORY = [h for h in HISTORY if h.get("filename") != filename]
    _save_json("history.json", HISTORY[-200:])
    log_action(request, "DELETE_EMAIL", f"Deleted {filename}")
    return RedirectResponse(url="/", status_code=303)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not is_logged_in(request): return RedirectResponse(url="/login", status_code=303)
    counts = {"Safe": 0, "Suspicious": 0, "Malicious": 0}
    for r in HISTORY:
        counts[r.get("verdict", "Safe")] = counts.get(r.get("verdict", "Safe"), 0) + 1
    cases = _load_json("cases.json", [])
    case_counts = {"Open": 0, "Investigating": 0, "Closed": 0}
    for c in cases:
        case_counts[c.get("status", "Open")] = case_counts.get(c.get("status", "Open"), 0) + 1
    recent = list(reversed(HISTORY[-10:]))
    recent_scores = []
    n = len(recent)
    for i, r in enumerate(reversed(recent)):
        x = 20 if n <= 1 else 20 + (560 * i / (n - 1))
        y = 210 - (min(100, max(0, int(r.get("score", 0)))) * 1.9)
        recent_scores.append({"x": round(x,1), "y": round(y,1), "score": int(r.get("score",0)), "index": i+1})
    recent_scores = list(reversed(recent_scores))
    history_cache = {}
    for r in recent:
        history_cache[r.get("filename", "")] = _load_cached(r.get("filename", "")) or {}
    return templates.TemplateResponse(request, "dashboard.html", {
        "recent": recent, "recent_scores": recent_scores, "counts": counts, "total": len(HISTORY),
        "case_counts": case_counts, "case_total": len(cases), "history_cache": history_cache,
    })

@app.get("/locations", response_class=HTMLResponse)
async def locations_page(request: Request, case_id: str = ""):
    if not is_logged_in(request): return RedirectResponse(url="/login", status_code=303)
    # Location Intelligence is intentionally scoped to ONE case at a time.
    # If no case is supplied, open the most recently created case.
    cases = list(reversed(_load_json("cases.json", [])))
    selected_case = next((c for c in cases if c.get("case_id") == case_id), None) if case_id else (cases[0] if cases else None)
    selected_filename = (selected_case or {}).get("source_file") or (selected_case or {}).get("filename")
    if not selected_filename and selected_case:
        selected_filename = next((r.get("filename") for r in HISTORY if r.get("case_id") == selected_case.get("case_id")), None)
    record = next((r for r in HISTORY if r.get("filename") == selected_filename), None) if selected_filename else None
    if not record and selected_case:
        record = next((r for r in HISTORY if r.get("case_id") == selected_case.get("case_id")), None)
    rows = []
    if record:
        cached = _load_cached(record.get("filename", "")) or {}
        rows.append({**record, "geo": cached.get("geo", {}), "case_id": (selected_case or {}).get("case_id") or record.get("case_id")})
    map_locations = []
    for r in rows:
        geo = r.get("geo") or {}
        map_locations.append({
            "filename": r.get("filename"), "ip": geo.get("ip"), "city": geo.get("city"),
            "region": geo.get("region"), "country": geo.get("country"), "isp": geo.get("isp"),
            "asn": geo.get("asn"), "verdict": r.get("verdict"), "case_id": r.get("case_id"),
            "lat": geo.get("lat") if geo.get("ok") else None,
            "lon": geo.get("lon") if geo.get("ok") else None,
        })
    located_count = sum(1 for x in map_locations if x["lat"] is not None and x["lon"] is not None)
    return templates.TemplateResponse(request, "locations.html", {
        "locations": rows, "map_locations": map_locations, "located_count": located_count,
        "unavailable_count": len(map_locations) - located_count, "location_total": len(map_locations),
        "selected_case": selected_case
    })

@app.get("/cases", response_class=HTMLResponse)
async def cases_page(request: Request):
    if not is_logged_in(request): return RedirectResponse(url="/login", status_code=303)
    cases = list(reversed(_load_json("cases.json", [])))
    return templates.TemplateResponse(request, "cases.html", {"cases": cases})

@app.get("/activity-log", response_class=HTMLResponse)
async def activity_log(request: Request):
    if not is_logged_in(request): return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request, "logs.html", {"logs": list(reversed(LOGS[-200:]))})

@app.get("/forensic-reports", response_class=HTMLResponse)
async def forensic_reports(request: Request):
    if not is_logged_in(request): return RedirectResponse(url="/login", status_code=303)
    os.makedirs("reports", exist_ok=True)
    reports = []
    for name in sorted(os.listdir("reports"), reverse=True):
        if name.lower().endswith(".pdf"):
            reports.append({"name": name, "url": f"/reports/{name}"})
    return templates.TemplateResponse(request, "forensic_reports.html", {"reports": reports, "recent": list(reversed(HISTORY[-8:]))})

@app.get("/report/{filename}")
async def download_report(request: Request, filename: str):
    if not is_logged_in(request): return RedirectResponse(url="/login", status_code=303)
    cached = _load_cached(filename)
    if not cached or not cached.get("threat"):
        return JSONResponse({"error": "No analysis found for this file. Upload it again."}, status_code=404)
    pdf_path = generate_report(cached["parsed"], cached["geo"], cached["threat"], filename)
    log_action(request, "REPORT_GENERATED", f"Generated forensic report for {filename}")
    return FileResponse(pdf_path, media_type="application/pdf", filename=os.path.basename(pdf_path))

@app.get("/reports/{report_name}")
async def serve_report(request: Request, report_name: str):
    if not is_logged_in(request): return RedirectResponse(url="/login", status_code=303)
    safe = os.path.basename(report_name)
    path = os.path.join("reports", safe)
    if not os.path.isfile(path): return HTMLResponse("Report not found", status_code=404)
    return FileResponse(path, media_type="application/pdf", filename=safe)

@app.get("/api/history")
async def api_history(request: Request):
    if not is_logged_in(request): return JSONResponse({"error":"Unauthorized"}, status_code=401)
    counts = {"Safe":0,"Suspicious":0,"Malicious":0}
    for r in HISTORY: counts[r["verdict"]] = counts.get(r["verdict"],0)+1
    return JSONResponse({"history":HISTORY,"verdict_counts":counts,"total_scanned":len(HISTORY)})

@app.get("/api/cases")
async def api_cases(request: Request):
    if not is_logged_in(request): return JSONResponse({"error":"Unauthorized"}, status_code=401)
    return JSONResponse({"cases":_load_json("cases.json",[])})

@app.get("/case/{case_id}", response_class=HTMLResponse)
async def case_page(request: Request, case_id: str):
    if not is_logged_in(request): return RedirectResponse(url="/login", status_code=303)
    cases = _load_json("cases.json", [])
    case = next((c for c in cases if c.get("case_id")==case_id), None)
    if not case: return HTMLResponse("Case not found", status_code=404)
    return templates.TemplateResponse(request, "case.html", {"case":case})

@app.post("/case/{case_id}/status")
async def update_case_status(request: Request, case_id: str, status: str = Form(...)):
    if not is_logged_in(request): return JSONResponse({"error":"Unauthorized"}, status_code=401)
    if status not in {"Open","Investigating","Closed"}: return JSONResponse({"error":"Invalid status"}, status_code=400)
    cases = _load_json("cases.json", [])
    for case in cases:
        if case.get("case_id")==case_id:
            case["status"]=status; _save_json("cases.json",cases); log_action(request,"CASE_STATUS",f"{case_id} -> {status}")
            return RedirectResponse(url=f"/case/{case_id}",status_code=303)
    return JSONResponse({"error":"Case not found"},status_code=404)

