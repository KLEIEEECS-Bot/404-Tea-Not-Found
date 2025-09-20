import re
import streamlit as st
import torch
from transformers import pipeline
from urllib.parse import urlparse
import tldextract
import validators

# ---------------------- Existing AI Classifier ----------------------
classifier = pipeline(
    "zero-shot-classification",
    model="valhalla/distilbart-mnli-12-1",
    device=-1
)

RED_FLAGS = [
    "guaranteed returns",
    "double your money",
    "limited time",
    "no risk",
    "exclusive offer",
    "get rich quick",
    "fast profits",
    "zero loss"
]


def detect_red_flags(text):
    """Detect scammy keywords in text."""
    flags = []
    for phrase in RED_FLAGS:
        if re.search(rf"\b{phrase}\b", text.lower()):
            flags.append(phrase)
    return flags


def ai_risk_analysis(text):
    """Classify the text with AI model."""
    labels = ["safe investment", "potential scam", "high risk"]
    result = classifier(text, candidate_labels=labels)
    return result


# ---------------------- URL Detection Heuristics ----------------------
SUSPICIOUS_KEYWORDS = {
    "login", "secure", "account", "verify", "update", "bank", "confirm",
    "password", "signin", "click", "free", "urgent", "verification", "ssn"
}

IP_ADDRESS_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
LONG_URL_THRESHOLD = 120
URL_RE = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)


def extract_urls(text):
    found = URL_RE.findall(text or "")
    normalized = []
    for u in found:
        u = u.rstrip('.,;:)|>\n')
        if not u.startswith(('http://', 'https://')):
            u = 'http://' + u
        normalized.append(u)
    return normalized


def extract_domain(url):
    try:
        p = urlparse(url)
        return p.netloc.lower()
    except Exception:
        return ""


def has_punycode(domain):
    return "xn--" in domain


def looks_like_ip(domain):
    host = domain.split(":")[0]
    return bool(IP_ADDRESS_RE.match(host))


def suspicious_keywords_in_path(url):
    path = urlparse(url).path.lower()
    query = urlparse(url).query.lower()
    combined = path + " " + query
    return [k for k in SUSPICIOUS_KEYWORDS if k in combined]


def flag_url(url):
    reasons = []
    domain = extract_domain(url)

    if not domain or not validators.domain(domain.split(":")[0]):
        reasons.append("malformed_or_invalid_domain")

    if looks_like_ip(domain):
        reasons.append("uses_ip_address")

    if has_punycode(domain):
        reasons.append("punycode_in_domain")

    if len(url) > LONG_URL_THRESHOLD:
        reasons.append("very_long_url")

    if "@" in url:
        reasons.append("contains_at_symbol")

    if "//" in urlparse(url).path:
        reasons.append("double_slash_in_path")

    kws = suspicious_keywords_in_path(url)
    if kws:
        reasons.append("suspicious_keywords:" + ",".join(kws))

    if ".." in domain:
        reasons.append("double_dot_in_domain")

    td = tldextract.extract(domain)
    for kw in ["bank", "secure", "login", "verify", "paypal", "amazon", "apple", "google"]:
        if kw in td.subdomain and kw not in td.domain:
            reasons.append(f"deceptive_subdomain_contains_{kw}")

    flagged = len(reasons) > 0
    return flagged, reasons


def analyze_urls(text):
    urls = extract_urls(text)
    results = []
    for u in urls:
        flagged, reasons = flag_url(u)
        results.append({
            "url": u,
            "flagged": flagged,
            "reasons": reasons
        })
    return results


# ---------------------- Streamlit UI ----------------------
st.title("💸 Scam Investment Detector")
st.write("AI tool to analyze investment offers and pitches for potential scam red flags.")

user_input = st.text_area("📥 Paste pitch or offer text here:")

if st.button("🔎 Analyze"):
    if user_input.strip():
        flags = detect_red_flags(user_input)
        result = ai_risk_analysis(user_input)
        top_label = result["labels"][0]
        score = round(result["scores"][0] * 100, 2)

        st.subheader("📊 Analysis Results")

        if "scam" in top_label.lower() or "high" in top_label.lower():
            st.error(f"🔴 AI Risk Prediction: {top_label} ({score}%)")
        elif "safe" in top_label.lower():
            st.success(f"🟢 AI Risk Prediction: {top_label} ({score}%)")
        else:
            st.warning(f"🟡 AI Risk Prediction: {top_label} ({score}%)")

        if flags:
            st.warning("⚠️ Red Flags Detected:")
            for f in flags:
                st.write(f"- {f}")
        else:
            st.success("✅ No obvious red flags detected.")

        # URL analysis results
        url_analysis = analyze_urls(user_input)
        if url_analysis:
            st.subheader("🔗 URL Analysis")
            for u in url_analysis:
                if u["flagged"]:
                    st.error(f"{u['url']} — Suspicious ({', '.join(u['reasons'])})")
                else:
                    st.success(f"{u['url']} — Looks OK")
        else:
            st.info("No URLs detected in the text.")

        st.info("Disclaimer: Demo tool only. Build By Basavanagoud & Manoj (404:Team not found - Thanks !!).")
