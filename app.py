import os
import re
import time
import zipfile
import tempfile
import streamlit as st
from google import genai
from google.genai import types

# --------------------------------------------------------
# 1. STREAMLIT WORKSPACE CONFIGURATION
# --------------------------------------------------------
st.set_page_config(
    page_title="VulnAI: Security Engine",
    layout="wide",
    initial_sidebar_state="expanded"
)

@st.cache_resource
def get_ai_client():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        st.error("❌ GEMINI_API_KEY is missing from Streamlit Secrets.")
        st.stop()
    return genai.Client(api_key=api_key)

client = get_ai_client()

# --------------------------------------------------------
# 2. FILE SCANNING & RESOURCE CALCULATOR
# --------------------------------------------------------
def estimate_tokens(text: str) -> int:
    """Estimates code block context footprint safely."""
    return int(len(text) / 3.5) + 50

def parse_dependencies(file_path: str) -> list:
    """Scans code components to look up structural import declarations."""
    deps = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        patterns = [
            r'(?:import|from)\s+([a-zA-Z0-9_\.]+)',
            r'require\([\'"](.+)[\'"]\)',
            r'#include\s+[\'"](.+)[\'"]'
        ]
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                deps.append(match.split('.')[0])
    except Exception:
        pass
    return deps

def scan_directory(base_dir: str):
    """Maps entire workspace archive compiling files and computing weights."""
    file_registry = {}
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.startswith('.'):
                continue
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, base_dir)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                file_registry[rel_path] = {
                    "full_path": full_path,
                    "size_bytes": os.path.getsize(full_path),
                    "estimated_tokens": estimate_tokens(content),
                    "dependencies": parse_dependencies(full_path),
                    "content": content
                }
            except Exception:
                continue
    return file_registry

# --------------------------------------------------------
# 3. INTERACTIVE SIDEBAR TREE COMPONENT
# --------------------------------------------------------
def render_sidebar_tree(base_dir: str, current_dir: str, level=0):
    """Recursively draws the folder structure map in the left sidebar."""
    try:
        items = os.listdir(current_dir)
    except Exception:
        return
    items = sorted(items, key=lambda x: (not os.path.isdir(os.path.join(current_dir, x)), x.lower()))
    for item in items:
        if item.startswith('.'):
            continue
        full_path = os.path.join(current_dir, item)
        indent = "  " * level
        if os.path.isdir(full_path):
            with st.sidebar.expander(f"{indent}📁 {item}", expanded=False):
                render_sidebar_tree(base_dir, full_path, level + 1)
        else:
            st.sidebar.text(f"{indent}📄 {item}")

# --------------------------------------------------------
# 4. LIVE ROUTER & RENDERING INTERFACE
# --------------------------------------------------------
st.title("🛡️ VulnAI: Advanced Repository Security Engine")
st.caption("Bachelor Project Portal Engine • Optimized via Gemini 3.1 flash lite")
st.write("")

uploaded_zip = st.file_uploader("Upload repository package ZIP file", type=["zip"])

if uploaded_zip:
    temp_dir = tempfile.TemporaryDirectory()
    zip_path = os.path.join(temp_dir.name, "repo.zip")
    extract_path = os.path.join(temp_dir.name, "extracted")
    
    with open(zip_path, "wb") as f:
        f.write(uploaded_zip.getbuffer())
        
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_path)
        
    # Process project telemetry immediately
    file_registry = scan_directory(extract_path)
    
    # Sidebar tree generation
    st.sidebar.markdown("### 📂 Folder Workspace")
    render_sidebar_tree(extract_path, extract_path)
    
    # Dashboard Telemetry Cards
    st.subheader("📊 Workspace Telemetry Snapshot")
    m_col1, m_col2, m_col3 = st.columns(3)
    m_col1.metric("Total File Assets", len(file_registry))
    m_col2.metric("Workspace Size", f"{sum(f['size_bytes'] for f in file_registry.values()) / 1024:.2f} KB")
    m_col3.metric("Estimated Tokens", f"~{sum(f['estimated_tokens'] for f in file_registry.values())}")
    st.write("")
    
    if st.button("🚀 Execute Comprehensive Analysis Scan", use_container_width=True):
        st.write("### 📜 Real-time Generation Feed")
        
        # Loop through files sequentially to support streaming logs and exact execution times
        for current_idx, (file_path, file_meta) in enumerate(file_registry.items()):
            st.markdown(f"---")
            st.markdown(f"#### 🔍 Auditing Target File ({current_idx+1}/{len(file_registry)}): `{file_path}`")
            
            # 4-Second safety interval gate
            time.sleep(4.0)
            
            # Unbiased prompt structure preventing forced hallucinations
            prompt = (
                "You are an objective, hyper-accurate software security auditor. Your goal is to analyze code "
                "for security vulnerabilities, malware patterns, and fatal structural code injection gaps.\n\n"
                "CRITICAL: Do NOT invent, assume, or force false flaws if the code is safe. "
                "Be a completely unbiased analyzer. If the code follows safe patterns, explicitly rate it as SAFE "
                "and state that no flaws were found.\n\n"
                "Provide your response matching this exact layout format:\n"
                "### Status: [SAFE or VULNERABLE or MALICIOUS]\n\n"
                "### Flaws Found:\n"
                "[List genuine issues itemized here. If no security issues exist, write 'None.']\n\n"
                "### Refactored Code:\n"
                "```\n"
                "[Only provide replacement code if vulnerabilities were present. Otherwise, state 'No refactoring required.']\n"
                "```\n\n"
                f"File Target Name: {file_path}\n"
                f"Code Component Content:\n{file_meta['content']}"
            )
            
            config = types.GenerateContentConfig(
                thinking_config=types.ThinkingConfig(thinking_level="HIGH"),
            )
            
            stream_box = st.empty()
            full_text = ""
            
            # Start timer calculation
            start_time = time.time()
            
            try:
                # Switched cleanly to the faster MoE model
                response_stream = client.models.generate_content_stream(
                    model="gemini-3.1-flash-lite",
                    contents=prompt,
                    config=config,
                )
                
                for chunk in response_stream:
                    if chunk.text:
                        full_text += chunk.text
                        stream_box.markdown(full_text)
                        
                # Conclude timing tracking metrics
                elapsed_time = time.time() - start_time
                st.info(f"⏱️ **Analysis Duration:** {elapsed_time:.2f} seconds")
                
            except Exception as e:
                st.error(f"⚠️ API pipeline failure on `{file_path}`: {str(e)}")
