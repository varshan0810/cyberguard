import os
from groq import Groq

def get_groq_client():
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key or api_key == "your_groq_api_key_here":
        return None
    return Groq(api_key=api_key)

SYSTEM_PROMPT = (
    "You are Cipher, an expert cybersecurity mentor in an interactive educational web app. "
    "Keep responses under 35 words, encouraging, direct, and free of vague analogies. "
    "Focus purely on concrete technical feedback."
)

def get_character_hint(module_name: str, issues: list[str]) -> str:
    client = get_groq_client()
    if not client:
        return f"Cipher Alert: {issues[0] if issues else 'Security check failed. Please review your settings.'}"

    prompt = f"Module: {module_name}. Validation failed with issues: {'; '.join(issues)}. Provide a single concise tip to fix this."
    
    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            max_tokens=60,
            temperature=0.6,
        )
        return response.choices[0].message.content
    except Exception:
        return f"Cipher Note: {issues[0] if issues else 'Adjust your configuration to meet the security requirements.'}"

def generate_report_card(session_data: dict) -> str:
    client = get_groq_client()
    attempts = session_data.get("attempts", {})
    score = session_data.get("score", 100)
    
    if not client:
        return f"Your final security score is {score}/100. Excellent job completing all 7 defensive modules! Keep practicing key security habits like using robust passwords and checking email headers."

    prompt = (
        f"Generate a personalized 3-sentence digital security evaluation card for a student.\n"
        f"Final Score: {score}/100.\n"
        f"Module Attempt History: {attempts}.\n"
        f"Acknowledge their strongest areas and provide 2 specific actionable recommendations."
    )
    
    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            max_tokens=150,
            temperature=0.7,
        )
        return response.choices[0].message.content
    except Exception:
        return f"Assessment Completed! Final Score: {score}/100. Excellent effort across all 7 digital security modules."