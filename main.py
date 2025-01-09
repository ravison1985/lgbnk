import streamlit as st
import bcrypt
import json
import os

# File to store user data
USER_DATA_FILE = "user_data.json"

# Load user data from JSON file
def load_user_data():
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "r") as file:
            return json.load(file)
    return {}

# Save user data to JSON file
def save_user_data(data):
    with open(USER_DATA_FILE, "w") as file:
        json.dump(data, file, indent=4)

# Initialize session state
if "logged_in_user" not in st.session_state:
    st.session_state["logged_in_user"] = None

if "user_data" not in st.session_state:
    st.session_state["user_data"] = load_user_data()

if "current_applicant" not in st.session_state:
    st.session_state["current_applicant"] = None

# Hash a password
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# Verify a password
def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

# Login function
def login(username, password):
    user_data = st.session_state["user_data"]
    if username in user_data:
        stored_password = user_data[username]["password"]
        if verify_password(password, stored_password):
            st.session_state["logged_in_user"] = username
            return True
    return False

# Register a new user
def register(username, password):
    user_data = st.session_state["user_data"]
    if username in user_data:
        return False
    user_data[username] = {"password": hash_password(password), "applications": {}}
    save_user_data(user_data)
    return True

# Logout function
def logout():
    st.session_state["logged_in_user"] = None
    st.session_state["current_applicant"] = None

# Add a new applicant
def add_new_applicant():
    username = st.session_state["logged_in_user"]
    if username:
        user_apps = st.session_state["user_data"][username]["applications"]
        new_applicant_key = f"applicant_{len(user_apps) + 1}"
        user_apps[new_applicant_key] = {"name": "", "age": 0}
        st.session_state["current_applicant"] = new_applicant_key
        save_user_data(st.session_state["user_data"])
        st.success(f"New application created: {new_applicant_key}")

# Edit existing applicant
def edit_applicant(applicant_key):
    st.session_state["current_applicant"] = applicant_key

# App UI
st.title("Applicant Management System")

if not st.session_state["logged_in_user"]:
    # Login or Register
    st.header("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if login(username, password):
            st.success(f"Welcome, {username}!")
            st.experimental_rerun()
        else:
            st.error("Invalid username or password.")

    st.markdown("---")
    st.header("Register")
    new_username = st.text_input("New Username")
    new_password = st.text_input("New Password", type="password")
    if st.button("Register"):
        if new_username.strip() and new_password.strip():
            if register(new_username, new_password):
                st.success("Registration successful! You can now log in.")
            else:
                st.error("Username already exists.")
        else:
            st.error("Username and password cannot be empty.")
else:
    # Main app
    st.sidebar.header(f"Logged in as: {st.session_state['logged_in_user']}")
    if st.sidebar.button("Logout"):
        logout()
        st.experimental_rerun()

    username = st.session_state["logged_in_user"]
    user_apps = st.session_state["user_data"][username]["applications"]

    # Sidebar for actions
    with st.sidebar:
        st.header("Actions")
        if st.button("Create New Application"):
            add_new_applicant()

        applicant_keys = list(user_apps.keys())
        if applicant_keys:
            selected_applicant = st.selectbox(
                "Select an applicant to edit", 
                applicant_keys, 
                index=0
            )
            if st.button("Edit Selected Applicant"):
                edit_applicant(selected_applicant)

    # Display current applicant details
    if st.session_state["current_applicant"]:
        current_applicant = st.session_state["current_applicant"]
        st.subheader(f"Editing: {current_applicant}")
        
        applicant_data = user_apps[current_applicant]
        name = st.text_input("Name", value=applicant_data["name"])
        age = st.number_input("Age", value=applicant_data["age"], min_value=0)
        
        if st.button("Save Changes"):
            user_apps[current_applicant]["name"] = name
            user_apps[current_applicant]["age"] = age
            save_user_data(st.session_state["user_data"])
            st.success("Changes saved!")
    else:
        st.info("No application selected. Use the sidebar to create or edit an application.")
