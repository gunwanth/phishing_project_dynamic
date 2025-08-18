import streamlit as st
import os
import json

# ✅ Relative imports for package execution
from .gmail_client import GmailClient
from .phishing_detector import PhishingDetector
from .auth import login_block
from .notifier import send_notification

# ----------------- Page Setup -----------------
st.set_page_config(page_title="Phishing Email Detector", layout="wide")
st.title("📬 Gmail Inbox - Phishing Detection")

# ----------------- Login -----------------
user_email = login_block()
if not user_email:
    st.stop()

# ----------------- Sidebar -----------------
with st.sidebar:
    st.title("Session")
    st.markdown(f"**Logged in as:** {user_email}")
    if st.button("🔓 Logout"):
        token_file = f"token_{user_email}.pkl"
        if os.path.exists(token_file):
            os.remove(token_file)
        st.session_state.clear()
        st.rerun()

# ----------------- Initialize Gmail and Detector -----------------
if 'gmail_client' not in st.session_state:
    st.session_state.gmail_client = GmailClient(user_email)
gmail = st.session_state.gmail_client

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = gmail.authenticate()

if not st.session_state.authenticated or not gmail.service:
    st.error("❌ Authentication failed. Cannot access Gmail API.")
    st.stop()

detector = PhishingDetector()

# ----------------- Fetch Emails -----------------
try:
    emails = gmail.get_recent_emails(limit=20)
except Exception as e:
    st.error(f"Failed to fetch emails: {e}")
    st.stop()

st.subheader("📥 Recent Emails")
phishing_count = 0

for email in emails:
    score = detector.calculate_risk_score(email)
    level = detector.get_risk_level(score)
    threats = detector.detect_threats(email)

    if level == "High":
        phishing_count += 1
        send_notification(
            title="🚨 Phishing Alert",
            message=f"High-risk email detected from: {email['sender']}\nSubject: {email['subject']}"
        )
    elif threats:
        send_notification(
            title="⚠️ Suspicious Email Detected",
            message=f"Email from: {email['sender']}\nThreats: {', '.join(threats)}"
        )

    with st.expander(f"📧 {email['subject']}"):
        st.markdown(f"**From:** {email['sender']}")
        st.markdown(f"**Date:** {email['date']}")
        st.markdown(f"**Labels:** {', '.join(email.get('labels', []))}")
        st.markdown("---")
        st.write(email['content'])
        st.markdown("---")
        st.metric("Phishing Risk Score", f"{score:.2f}", level)

        if threats:
            st.warning("⚠️ Threat Indicators:")
            for t in threats:
                st.write(f"- {t}")
        else:
            st.success("✅ No significant phishing indicators detected.")

        if level == "High" and st.button(f"🚫 Mark email `{email['id']}` as spam", key=email['id']):
            success = gmail.mark_as_spam(email['id'])
            if success:
                st.success("Marked as spam.")
            else:
                st.error("Failed to mark as spam.")

# ----------------- Summary -----------------
st.markdown("---")
st.metric("🚨 Total Phishing Emails Detected", f"{phishing_count} of {len(emails)}")
