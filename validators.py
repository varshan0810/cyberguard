import re
import math
import pyotp
from scenarios import PHISHING_SCENARIO, WIFI_SCENARIO, PII_FIELDS, HYGIENE_CHECKLIST

def calculate_entropy(password: str) -> float:
    """Calculates password entropy in bits: E = L * log2(R)"""
    if not password:
        return 0.0
    
    charset_size = 0
    if re.search(r"[a-z]", password): charset_size += 26
    if re.search(r"[A-Z]", password): charset_size += 26
    if re.search(r"[0-9]", password): charset_size += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): charset_size += 32
    
    if charset_size == 0:
        return 0.0
    
    return len(password) * math.log2(charset_size)

def validate_password(pw: str) -> tuple[bool, list[str], float]:
    issues = []
    if len(pw) < 10:
        issues.append("Password must be at least 10 characters long.")
    if not re.search(r"[A-Z]", pw):
        issues.append("Include at least one uppercase letter.")
    if not re.search(r"[a-z]", pw):
        issues.append("Include at least one lowercase letter.")
    if not re.search(r"[0-9]", pw):
        issues.append("Include at least one numerical digit.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", pw):
        issues.append("Include at least one special character.")
    
    common = {"password", "123456", "qwerty", "letmein", "iloveyou", "admin123", "password123"}
    if pw.lower() in common:
        issues.append("Password is too common and easily crackable.")
        
    entropy = round(calculate_entropy(pw), 2)
    if entropy < 50.0 and len(issues) == 0:
        issues.append("Password lacks structural variety (low entropy).")

    return (len(issues) == 0, issues, entropy)

def validate_phishing(selected_ids: list[int]) -> tuple[bool, list[str]]:
    required_ids = [item["id"] for item in PHISHING_SCENARIO["body_parts"] if item["is_flag"]]
    
    selected_set = set(selected_ids)
    required_set = set(required_ids)
    
    if selected_set == required_set:
        return True, []
    
    issues = []
    missing = required_set - selected_set
    extra = selected_set - required_set
    
    if missing:
        issues.append("You missed one or more critical phishing red flags (e.g., suspicious URL or urgent threat).")
    if extra:
        issues.append("You incorrectly flagged legitimate parts of the email as suspicious.")
        
    return False, issues

def validate_2fa(entered_code: str, secret: str) -> tuple[bool, list[str]]:
    totp = pyotp.TOTP(secret)
    
    # valid_window=1 accepts the current 30-second code AND the previous 30-second code (60 seconds total tolerance)
    if totp.verify(entered_code, valid_window=1):
        return True, []
        
    return False, ["Invalid 6-digit TOTP code or code has expired. Please try again."]

def validate_privacy(settings: dict) -> tuple[bool, list[str]]:
    is_private = settings.get("is_private", False)
    location = settings.get("location_visible", False)
    phone = settings.get("phone_visible", False)
    dob = settings.get("dob_visible", False)

    if is_private and not (location or phone or dob):
        return True, []
    if not is_private and not location and not phone and not dob:
        return True, []
    
    issues = []
    if phone:
        issues.append("Your phone number is publicly visible.")
    if dob:
        issues.append("Your date of birth is publicly visible.")
    if location:
        issues.append("Live location tagging is enabled.")
    
    return False, issues

def validate_wifi(selected_option: str) -> tuple[bool, list[str]]:
    correct_option = next(opt["id"] for opt in WIFI_SCENARIO["options"] if opt["correct"])
    if selected_option == correct_option:
        return True, []
    return False, ["Incorrect choice. Connecting directly to open Wi-Fi without encryption leaves your traffic vulnerable to sniffing."]

def validate_pii(user_classifications: dict) -> tuple[bool, list[str]]:
    issues = []
    for field in PII_FIELDS:
        f_id = field["id"]
        expected = field["category"]
        actual = user_classifications.get(f_id, "unknown")
        
        if expected == "unsafe" and actual != "unsafe":
            issues.append(f"Field '{field['label']}' contains sensitive PII and should never be shared publicly.")
            
    return (len(issues) == 0, issues)

def validate_hygiene(checklist: dict) -> tuple[bool, list[str]]:
    missing = []
    for item in HYGIENE_CHECKLIST:
        if item["required"] and not checklist.get(item["id"], False):
            missing.append(item["label"])
            
    if not missing:
        return True, []
    return False, [f"Unmet security requirements: {', '.join(missing)}"]