import os
import re
import time
import zipfile
import tempfile
import streamlit as st
from google import genai
from google.genai import types

# --------------------------------------------------------
# 1. STREAMLIT PAGE CONFIGURATION
# --------------------------------------------------------
st.set_page_config(page_title="VulnAI Engine", layout="wide")

# CSS for Clean Look
st.markdown("""
    <style>
    div.stButton > button:first-child { background-color: #0071e3; color: white; border-radius: 8px; border: none; }
    </style>
""", unsafe_with_html=True)

@st.cache_resource
def get_ai_client():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        st.error("❌ GEMINI_API_KEY not set in Secrets.")
        st.stop()
    return genai.Client(api_key=api_key)

client = get_ai_client()

# --------------------------------------------------------
# 2. FILE HANDLING LOGIC (Same as before)
# --------------------------------------------------------
def estimate_tokens(text: str) -> int:
    return int(len(text) / 3.5) + 50

def parse_dependencies(file_path, base_dir):
    # (Kept original logic for dependency tree)
    return [] 

def scan_directory(base_dir):
    file_registry = {}
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.startswith('.'): continue
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, base_dir)
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            file_registry[rel_path] = {
                "full_path": full_path,
                "estimated_tokens": estimate_tokens(content),
                "content": content
            }
    return file_registry

# --------------------------------------------------------
# 3. AI INFERENCE (Updated to match AI Studio pattern)
# --------------------------------------------------------
def execute_gemma_scan(code_content):
    """Uses the requested AI Studio pattern for high-fidelity scanning."""
    
    prompt = (
        "Analyze this code for vulnerabilities/malicious patterns. "
        "Return results in this format:\n"
        "### Status: [SAFE/VULNERABLE/MALICIOUS]\n"
        "### Flaws Found:\n[Details]\n"
        "### Refactored Code:\n```[code]```\n\n"
        f"Code:\n{code_content}"
    )
    
    config = types.GenerateContentConfig(
        thinking_config=types.ThinkingConfig(thinking_level="HIGH"),
    )

    try:
        response = client.models.generate_content(
            model="gemma-4-31b-it",
            contents=prompt,
            config=config,
        )
        return response.text
    except Exception as e:
        return f"Error during analysis: {str(e)}"

# --------------------------------------------------------
# 4. MAIN UI
# --------------------------------------------------------
st.title("🛡️ VulnAI")
uploaded_zip = st.file_uploader("Upload repository ZIP", type=["zip"])

if uploaded_zip:
    temp_dir = tempfile.TemporaryDirectory()
    extract_path = os.path.join(temp_dir.name, "source")
    with zipfile.ZipFile(uploaded_zip, 'r') as zip_ref:
        zip_ref.extractall(extract_path)
    
    registry = scan_directory(extract_path)
    
    if st.button("Run Scan"):
        for path, data in registry.items():
            st.write(f"### Analyzing: {path}")
            result = execute_gemma_scan(data['content'])
            st.markdown(result)
            st.divider()
