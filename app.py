import os
import pyotp
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, session, redirect, url_for

from scenarios import PHISHING_SCENARIO, WIFI_SCENARIO, PII_FIELDS, HYGIENE_CHECKLIST
import validators
import llm_agent

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev")

TOTAL_MODULES = 7

def init_session():
    if "current_module" not in session:
        session["current_module"] = 1
    if "completed_modules" not in session:
        session["completed_modules"] = []
    if "attempts" not in session:
        session["attempts"] = {str(i): 0 for i in range(1, TOTAL_MODULES + 1)}
    if "hints_used" not in session:
        session["hints_used"] = 0
    if "totp_secret" not in session:
        session["totp_secret"] = pyotp.random_base32()

def calculate_score():
    total_extra_attempts = sum(max(0, count - 1) for count in session.get("attempts", {}).values())
    hints = session.get("hints_used", 0)
    score = 100 - (hints * 4) - (total_extra_attempts * 3)
    return max(0, score)

@app.route("/")
def landing():
    init_session()
    return render_template("landing.html")

@app.route("/reset")
def reset():
    session.clear()
    init_session()
    return redirect(url_for("landing"))

@app.route("/module/<int:mod_id>")
def show_module(mod_id: int):
    init_session()
    if mod_id < 1 or mod_id > TOTAL_MODULES:
        return redirect(url_for("landing"))
    
    if mod_id > 1 and (mod_id - 1) not in session["completed_modules"]:
        return redirect(url_for("show_module", mod_id=max(1, session["current_module"])))

    session["current_module"] = mod_id
    totp_code = pyotp.TOTP(session["totp_secret"]).now() if mod_id == 3 else None

    return render_template(
        "module.html",
        mod_id=mod_id,
        total_modules=TOTAL_MODULES,
        phishing=PHISHING_SCENARIO,
        wifi=WIFI_SCENARIO,
        pii=PII_FIELDS,
        hygiene=HYGIENE_CHECKLIST,
        totp_secret=session.get("totp_secret"),
        totp_code=totp_code,
        completed=mod_id in session["completed_modules"]
    )

@app.route("/api/validate/<int:mod_id>", methods=["POST"])
def validate_api(mod_id: int):
    init_session()
    data = request.get_json() or {}
    
    attempts = session.get("attempts", {})
    attempts[str(mod_id)] = attempts.get(str(mod_id), 0) + 1
    session["attempts"] = attempts

    passed = False
    issues = []
    extra_meta = {}

    if mod_id == 1:
        password = data.get("password", "")
        passed, issues, entropy = validators.validate_password(password)
        extra_meta["entropy"] = entropy
    elif mod_id == 2:
        selected_ids = [int(x) for x in data.get("selected_flags", [])]
        passed, issues = validators.validate_phishing(selected_ids)
    elif mod_id == 3:
        code = data.get("totp_code", "").strip()
        passed, issues = validators.validate_2fa(code, session["totp_secret"])
    elif mod_id == 4:
        passed, issues = validators.validate_privacy(data.get("privacy_settings", {}))
    elif mod_id == 5:
        passed, issues = validators.validate_wifi(data.get("wifi_option", ""))
    elif mod_id == 6:
        passed, issues = validators.validate_pii(data.get("pii_choices", {}))
    elif mod_id == 7:
        passed, issues = validators.validate_hygiene(data.get("hygiene_checklist", {}))

    hint = ""
    if passed:
        if mod_id not in session["completed_modules"]:
            session["completed_modules"].append(mod_id)
            session.modified = True
        cipher_msg = "Verification Successful! Security policy validated. Proceed to the next module."
    else:
        session["hints_used"] = session.get("hints_used", 0) + 1
        hint = llm_agent.get_character_hint(f"Module {mod_id}", issues)
        cipher_msg = hint

    return jsonify({
        "passed": passed,
        "issues": issues,
        "cipher_message": cipher_msg,
        "extra": extra_meta,
        "next_module": mod_id + 1 if mod_id < TOTAL_MODULES else None
    })

@app.route("/report")
def report():
    init_session()
    if len(session.get("completed_modules", [])) < TOTAL_MODULES:
        return redirect(url_for("show_module", mod_id=session.get("current_module", 1)))

    score = calculate_score()
    session["score"] = score
    
    summary_text = llm_agent.generate_report_card(session)

    return render_template("report.html", score=score, summary=summary_text)

if __name__ == "__main__":
    app.run(debug=True, port=5000)