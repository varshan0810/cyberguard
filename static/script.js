function typeWriter(elementId, text, speed = 20) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.innerHTML = "";
    let i = 0;
    function type() {
        if (i < text.length) {
            el.innerHTML += text.charAt(i);
            i++;
            setTimeout(type, speed);
        }
    }
    type();
}

function calculateLiveEntropy(pw) {
    if (!pw) return 0;
    let charset = 0;
    if (/[a-z]/.test(pw)) charset += 26;
    if (/[A-Z]/.test(pw)) charset += 26;
    if (/[0-9]/.test(pw)) charset += 10;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(pw)) charset += 32;
    if (charset === 0) return 0;
    return Math.round(pw.length * Math.log2(charset) * 100) / 100;
}

document.addEventListener("DOMContentLoaded", () => {
    const pwInput = document.getElementById("password_input");
    if (pwInput) {
        pwInput.addEventListener("input", (e) => {
            const ent = calculateLiveEntropy(e.target.value);
            const display = document.getElementById("entropy_display");
            if (display) display.innerText = `Entropy: ${ent} bits`;
        });
    }

    const flags = document.querySelectorAll(".phishing-span");
    flags.forEach(span => {
        span.addEventListener("click", () => {
            span.classList.toggle("selected");
        });
    });
});

async function submitModule(modId) {
    let payload = {};

    if (modId === 1) {
        payload.password = document.getElementById("password_input").value;
    } else if (modId === 2) {
        const selected = Array.from(document.querySelectorAll(".phishing-span.selected"))
                             .map(el => el.getAttribute("data-id"));
        payload.selected_flags = selected;
    } else if (modId === 3) {
        payload.totp_code = document.getElementById("totp_input").value;
    } else if (modId === 4) {
        payload.privacy_settings = {
            is_private: document.getElementById("priv_private").checked,
            location_visible: document.getElementById("priv_location").checked,
            phone_visible: document.getElementById("priv_phone").checked,
            dob_visible: document.getElementById("priv_dob").checked,
        };
    } else if (modId === 5) {
        const checked = document.querySelector('input[name="wifi_opt"]:checked');
        payload.wifi_option = checked ? checked.value : "";
    } else if (modId === 6) {
        const choices = {};
        document.querySelectorAll(".pii-select").forEach(sel => {
            choices[sel.getAttribute("data-id")] = sel.value;
        });
        payload.pii_choices = choices;
    } else if (modId === 7) {
        const checklist = {};
        document.querySelectorAll(".hygiene-chk").forEach(chk => {
            checklist[chk.getAttribute("data-id")] = chk.checked;
        });
        payload.hygiene_checklist = checklist;
    }

    const response = await fetch(`/api/validate/${modId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });

    const result = await response.json();
    typeWriter("cipher_dialogue", result.cipher_message);

    const issueContainer = document.getElementById("issues_div");
    if (issueContainer) {
        if (result.issues.length > 0) {
            issueContainer.innerHTML = "<ul>" + result.issues.map(i => `<li>${i}</li>`).join("") + "</ul>";
        } else {
            issueContainer.innerHTML = "";
        }
    }

    if (result.passed) {
        const nextBtn = document.getElementById("next_btn");
        if (nextBtn) nextBtn.disabled = false;
    }
}