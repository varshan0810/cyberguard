"""
Static data scenarios, ground truth definitions, and mock inputs for CyberGuard modules.
"""

# Module 2: Phishing Ground Truth
PHISHING_SCENARIO = {
    "sender": "support@sec-bank-verify-alert.com",
    "subject": "URGENT: Your Account Has Been Suspended!",
    "body_parts": [
        {"id": 1, "text": "Dear Valued Customer,", "is_flag": False},
        {"id": 2, "text": " We detected unauthorized login attempts from an unknown IP.", "is_flag": False},
        {"id": 3, "text": " Your account will be permanently terminated within 2 hours.", "is_flag": True, "reason": "Artificial Urgency / Threat"},
        {"id": 4, "text": " Please verify your identity immediately by clicking here: ", "is_flag": False},
        {"id": 5, "text": "http://sec-bank-verify-alert.com/login-reset", "is_flag": True, "reason": "Suspicious / Fake Domain URL"},
        {"id": 6, "text": " Sincerely, Security Team.", "is_flag": False}
    ]
}

# Module 5: Public Wi-Fi Options
WIFI_SCENARIO = {
    "title": "Café Wi-Fi Dilemma",
    "prompt": "You are at a local coffee shop connected to an open network named 'Free_Coffee_WiFi'. You need to log into your primary bank account to transfer money.",
    "options": [
        {"id": "a", "text": "Proceed immediately since the Wi-Fi requires a password printed on the café receipt.", "correct": False},
        {"id": "b", "text": "Enable a trusted Virtual Private Network (VPN) or switch to mobile cellular data before logging in.", "correct": True},
        {"id": "c", "text": "Use Incognito/Private mode in your browser to encrypt your connection.", "correct": False},
        {"id": "d", "text": "Check if the banking URL starts with 'http://' instead of 'https://'.", "correct": False}
    ]
}

# Module 6: PII Field Classifications
PII_FIELDS = [
    {"id": "name", "label": "Full Name", "category": "safe"},
    {"id": "username", "label": "Desired Username", "category": "safe"},
    {"id": "ssn", "label": "Aadhaar / SSN / National ID", "category": "unsafe"},
    {"id": "mother_maiden", "label": "Mother's Maiden Name", "category": "unsafe"},
    {"id": "address", "label": "Home Physical Address", "category": "unsafe"},
    {"id": "pet_name", "label": "First Pet's Name (Common Security Q)", "category": "unsafe"},
    {"id": "avatar", "label": "Public Profile Picture", "category": "safe"}
]

# Module 7: Device Hygiene Items
HYGIENE_CHECKLIST = [
    {"id": "os_update", "label": "Automatic OS and Security Updates Enabled", "required": True},
    {"id": "app_perm", "label": "App Permissions Reviewed (e.g., Flashlight app location access revoked)", "required": True},
    {"id": "unused_apps", "label": "Unused Apps Uninstalled", "required": True},
    {"id": "screen_lock", "label": "PIN / Biometric Screen Lock Configured", "required": True}
]