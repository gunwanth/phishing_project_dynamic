import streamlit as st
import json
import os

USER_FILE = "users.json"

def login_block():
    if 'user' in st.session_state:
        return st.session_state['user']

    tab1, tab2 = st.tabs(["🔐 Login", "🆕 Sign Up"])

    with tab1:
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login"):
            if not os.path.exists(USER_FILE):
                st.error("No users found. Please sign up.")
            else:
                with open(USER_FILE, "r") as f:
                    users = json.load(f)
                if email in users and users[email]["password"] == password:
                    st.session_state['user'] = email  
                    st.rerun()
                else:
                    st.error("Invalid email or password.")

    with tab2:
        new_email = st.text_input("New Email", key="signup_email")
        new_password = st.text_input("New Password", type="password", key="signup_password")
        if st.button("Sign Up"):
            if not new_email or not new_password:
                st.warning("Please provide both email and password.")
            else:
                users = {}
                if os.path.exists(USER_FILE):
                    with open(USER_FILE, "r") as f:
                        users = json.load(f)
                if new_email in users:
                    st.warning("User already exists.")
                else:
                    users[new_email] = {"password": new_password}
                    with open(USER_FILE, "w") as f:
                        json.dump(users, f)
                    st.success("Account created! Please login now.")

    return None