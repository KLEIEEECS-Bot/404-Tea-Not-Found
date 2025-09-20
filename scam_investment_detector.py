import re
import streamlit as st
import torch
from transformers import pipeline

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

        st.info("Disclaimer: Demo tool only. Build By Basavanagoud & Manoj (404:Team not found - Thanks !!).")
