import os
import re
import time
import zipfile
import tempfile
import streamlit as st
from google import genai
from google.genai import types

# --------------------------------------------------------
# 1. STREAMLIT SETTING
# --------------------------------------------------------
st.set_page_config(page_title="VulnAI: Security Auditor", layout="wide")

@st.cache_resource
def get_ai_client():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        st.error("❌ GEMINI_API_KEY is missing from Streamlit Secrets.")
        st.stop()
    return genai.Client(api_key=api_key)

client = get_ai_client()

# --------------------------------------------------------
# 2. LIGHTWEIGHT REPOSITORY PARSER
# --------------------------------------------------------
def scan_directory(base_dir: str):
    file_registry = {}
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.startswith('.'): continue
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, base_dir)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                file_registry[rel_path] = {
                    "content": content,
                    "size": os.path.getsize(full_path)
                }
            except:
                continue
    return file_registry

# --------------------------------------------------------
# 3. INTERACTIVE TREE SIDEBAR
# --------------------------------------------------------
def render_sidebar_tree(base_dir: str, current_dir: str, level=0):
    try:
        items = os.listdir(current_dir)
    except: return
    items = sorted(items, key=lambda x: (not os.path.isdir(os.path.join(current_dir, x)), x.lower()))
    for item in items:
        if item.startswith('.'): continue
        full_path = os.path.join(current_dir, item)
        indent = "  " * level
        if os.path.isdir(full_path):
            with st.sidebar.expander(f"{indent}📁 {item}", expanded=False):
                render_sidebar_tree(base_dir, full_path, level + 1)
        else:
            st.sidebar.text(f"{indent}📄 {item}")

# --------------------------------------------------------
# 4. MAIN UI INTERFACE & ROUTER
# --------------------------------------------------------
st.title("🛡️ VulnAI: Live Streaming Auditor")
st.caption("Bachelor Project Portal • Powered by Gemma 4 31B Streaming Architecture")

uploaded_zip = st.file_uploader("Upload repository package ZIP file", type=["zip"])

if uploaded_zip:
    temp_dir = tempfile.TemporaryDirectory()
    zip_path = os.path.join(temp_dir.name, "repo.zip")
    extract_path = os.path.join(temp_dir.name, "extracted")
    
    with open(zip_path, "wb") as f:
        f.write(uploaded_zip.getbuffer())
        
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_path)
        
    file_registry = scan_directory(extract_path)
    
    st.sidebar.markdown("### 📂 Folder Workspace")
    render_sidebar_tree(extract_path, extract_path)
    
    st.subheader("📊 Workspace Details")
    st.write(f"Total Discovered Files: **{len(file_registry)}**")
    
    if st.button("🚀 Start Live-Streamed Analysis", use_container_width=True):
        st.write("### 📜 Real-time Generation Feed")
        
        # We loop and hit Gemma 4 31B individually per file with a 4-second safety gap
        # This fixes hanging issues, respects rate limits, and displays immediate output
        for current_idx, (file_path, file_meta) in enumerate(file_registry.items()):
            st.markdown(f"---")
            st.markdown(f"#### 🔍 Auditing Target File ({current_idx+1}/{len(file_registry)}): `{file_path}`")
            
            # 4 Second Cooldown Gate to respect 15 RPM
            time.sleep(4.0)
            
            prompt = (
                "You are an advanced software security expert auditing code repositories.\n"
                "Analyze this file completely. Do NOT stop searching if you find a defect; "
                "continue scanning everything to provide a full report.\n\n"
                "Return your analysis matching this exact structure:\n"
                "### Status: [SAFE or VULNERABLE or MALICIOUS]\n\n"
                "### Flaws Found:\n"
                "[List details of flaws or write 'None.']\n\n"
                "### Refactored Code:\n"
                "```\n"
                "[Full working replacement code]\n"
                "```\n\n"
                f"Target File Path: {file_path}\n"
                f"Target Code:\n{file_meta['content']}"
            )
            
            config = types.GenerateContentConfig(
                thinking_config=types.ThinkingConfig(thinking_level="HIGH"),
            )
            
            # Define an empty dynamic text element block to stream content into
            stream_output_box = st.empty()
            full_streamed_text = ""
            
            try:
                response_stream = client.models.generate_content_stream(
                    model="gemma-4-31b-it",
                    contents=prompt,
                    config=config,
                )
                
                for chunk in response_stream:
                    if chunk.text:
                        full_streamed_text += chunk.text
                        # Update the UI live as characters drop in
                        stream_output_box.markdown(full_streamed_text)
                        
            except Exception as e:
                st.error(f"⚠️ API Pipeline exception on `{file_path}`: {str(e)}")
