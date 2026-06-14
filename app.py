import sys
import subprocess

# --------------------------------------------------------
# 0. AUTOMATED DEPENDENCY BOOTSTRAP (Fixes the ImportError)
# --------------------------------------------------------
try:
    from google import genai
    from google.genai import types
except ImportError:
    # Programmatically force-installs the correct package if Streamlit skips it
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "google-genai"])
    from google import genai
    from google.genai import types

import os
import re
import time
import zipfile
import tempfile
import streamlit as st

# --------------------------------------------------------
# 1. STREAMLIT PAGE CONFIGURATION & UI THEME
# --------------------------------------------------------
st.set_page_config(
    page_title="AI Vulnerability & Malware Detector",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Minimalist CSS for a clean look
st.markdown("""
    <style>
    .reportview-container { background: #fdfdfd; }
    .sidebar .sidebar-content { background: #f5f5f7; }
    div.stButton > button:first-child {
        background-color: #0071e3;
        color: white;
        border-radius: 8px;
        border: none;
        padding: 0.5rem 2rem;
    }
    div.stButton > button:first-child:hover {
        background-color: #0077ed;
        color: white;
    }
    </style>
""", unsafe_with_html=True)

# Initialize GenAI Client
@st.cache_resource
def get_ai_client():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        st.error("❌ GEMINI_API_KEY variable not detected in environment variables.")
        st.stop()
    return genai.Client(api_key=api_key)

client = get_ai_client()

# --------------------------------------------------------
# 2. FILE HANDLING & DEPENDENCY CORE LOGIC
# --------------------------------------------------------
def estimate_tokens(text: str) -> int:
    """Estimates code token footprint based on character distributions."""
    return int(len(text) / 3.5) + 50  # Adding a constant padding value

def parse_dependencies(file_path: str, base_dir: str) -> list:
    """Extracts internal code dependencies to structure execution chains."""
    deps = []
    ext = os.path.splitext(file_path)[1].lower()
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
        # Target common import statements across languages (Python, JS, C++, etc.)
        patterns = [
            r'(?:import|from)\s+([a-zA-Z0-9_\.]+)',
            r'require\([\'"](.+)[\'"]\)',
            r'#include\s+[\'"](.+)[\'"]'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                clean_dep = match.split('.')[0] if ext == '.py' else match
                deps.append(clean_dep)
    except Exception:
        pass
    return deps

def scan_directory(base_dir: str):
    """Walks directory to build metadata registry and dependency mappings."""
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
                    "dependencies": parse_dependencies(full_path, base_dir),
                    "content": content
                }
            except Exception:
                continue
                
    return file_registry

# --------------------------------------------------------
# 3. INTERACTIVE MAC-LIKE SIDEBAR COMPONENT
# --------------------------------------------------------
def render_sidebar_tree(base_dir: str, current_dir: str, level=0):
    """Recursively draws folder maps using minimalist native components."""
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
            st.sidebar.markdown(f"{indent}📄 {item}")

# --------------------------------------------------------
# 4. CHUNKING & STRATEGY GENERATOR
# --------------------------------------------------------
def generate_analysis_batches(registry: dict, max_tokens=100000):
    """Groups code files down dependent paths without overflowing token boundaries."""
    batches = []
    current_batch = []
    current_tokens = 0
    
    sorted_files = sorted(registry.keys(), key=lambda x: len(registry[x]['dependencies']), reverse=True)
    
    for file_path in sorted_files:
        file_tokens = registry[file_path]['estimated_tokens']
        
        if file_tokens > max_tokens:
            batches.append([file_path])
            continue
            
        if current_tokens + file_tokens > max_tokens:
            batches.append(current_batch)
            current_batch = [file_path]
            current_tokens = file_tokens
        else:
            current_batch.append(file_path)
            current_tokens += file_tokens
            
    if current_batch:
        batches.append(current_batch)
        
    return batches

# --------------------------------------------------------
# 5. AI INFERENCE PIPELINE
# --------------------------------------------------------
def execute_gemma_scan(batch_files: list, registry: dict):
    """Packages code blocks and communicates securely with Gemma 4 31B."""
    prompt_payload = (
        "You are an advanced, hyper-detailed secure code auditor. Analyze the following file(s) "
        "comprehensively for architectural vulnerabilities, security flaws, weaknesses, and malicious payloads.\n"
        "CRITICAL INSTRUCTION: Do NOT halt evaluation upon locating a single flaw. Continue scanning the "
        "entirety of every file to catch all hidden issues. You must evaluate the code fully.\n\n"
        "Provide your analysis back strictly matching this exact markdown structure for EVERY single file:\n\n"
        "=== START FILE: [File Path] ===\n"
        "### Status: [SAFE or VULNERABLE or MALICIOUS]\n\n"
        "### Flaws Found:\n"
        "[Enumerate line-by-line structural descriptions of any issues found. If safe, state 'None.']\n\n"
        "### Refactored Code:\n"
        "```[language]\n"
        "[Provide the absolute full, fully-functional, copy-paste ready safe file code replacement here. "
        "Do not truncate or summarize the code.]\n"
        "```\n"
        "=== END FILE: [File Path] ===\n\n"
        "Here is the code to audit:\n"
    )
    
    for file_path in batch_files:
        prompt_payload += f"\n--- FILE: {file_path} ---\n{registry[file_path]['content']}\n"
        
    try:
        response = client.models.generate_content(
            model="gemma-4-31b-it",
            contents=prompt_payload,
            config=types.GenerateContentConfig(
                thinking_config=types.ThinkingConfig(thinking_level="high")
            )
        )
        return response.text
    except Exception as e:
        return f"⚠️ Execution Error during API payload transmission: {str(e)}"

# --------------------------------------------------------
# 6. MAIN USER UI & APPLICATION ROUTER
# --------------------------------------------------------
st.title("🛡️ VulnAI: Source Code Vulnerability & Malware Auditor")
st.caption("Bachelor Project Engine • Powered by Google Gemma 4 31B Core API")
st.write("---")

uploaded_zip = st.file_uploader("Drop your target source repository ZIP archive here", type=["zip"])

if uploaded_zip:
    temp_dir = tempfile.TemporaryDirectory()
    zip_path = os.path.join(temp_dir.name, "repo.zip")
    extract_path = os.path.join(temp_dir.name, "extracted_source")
    
    with open(zip_path, "wb") as f:
        f.write(uploaded_zip.getbuffer())
        
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_path)
        
    file_registry = scan_directory(extract_path)
    
    st.sidebar.markdown("### 📂 Repository File Tree")
    render_sidebar_tree(extract_path, extract_path)
    
    st.subheader("📊 Target Package Snapshot")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total File Assets", len(file_registry))
    col2.metric("Total Code Size", f"{sum(f['size_bytes'] for f in file_registry.values()) / 1024:.2f} KB")
    col3.metric("Aggregated Context Weight", f"~{sum(f['estimated_tokens'] for f in file_registry.values())} Tokens")
    
    st.write("---")
    
    if st.button("🚀 Run Vulnerability & Malware Scan"):
        batches = generate_analysis_batches(file_registry)
        st.info(f"📦 Grouped workspace into **{len(batches)} optimal context delivery batches**.")
        
        progress_bar = st.progress(0.0)
        all_raw_responses = ""
        
        for idx, batch in enumerate(batches):
            with st.spinner(f"Auditing Group Batch {idx + 1}/{len(batches)}..."):
                time.sleep(4.0)
                batch_response = execute_gemma_scan(batch, file_registry)
                all_raw_responses += batch_response + "\n"
                
            progress_bar.progress((idx + 1) / len(batches))
            
        progress_bar.empty()
        st.success("✅ Audit cycle complete! See individual breakdown records below:")
        
        for file_path, details in file_registry.items():
            st.write(f"---")
            st.markdown(f"### 📄 Target Artifact: `{file_path}`")
            
            try:
                segment_pattern = rf"=== START FILE: {re.escape(file_path)} ===(.*?)=== END FILE: {re.escape(file_path)} ==="
                segment_match = re.search(segment_pattern, all_raw_responses, re.DOTALL)
                
                if segment_match:
                    file_analysis = segment_match.group(1)
                    
                    status_match = re.search(r"### Status:\s*(\w+)", file_analysis)
                    status = status_match.group(1) if status_match else "UNKNOWN"
                    
                    if "SAFE" in status.upper():
                        st.success("🟢 Code Status Assessment: Clean / Safe")
                    elif "VULNERABLE" in status.upper():
                        st.warning("⚠️ Code Status Assessment: Security Vulnerability Detected")
                    else:
                        st.error("🚨 Code Status Assessment: Malicious Payload Signatures Flagged")
                        
                    flaws_segment = re.search(r"### Flaws Found:(.*?)(?=### Refactored Code:|$)", file_analysis, re.DOTALL)
                    if flaws_segment:
                        st.markdown("#### 🔍 Discovered Deficiencies:")
                        st.markdown(flaws_segment.group(1).strip())
                        
                    code_segment = re.search(r"### Refactored Code:\s*\n```[a-zA-Z0-9]*\n(.*?)```", file_analysis, re.DOTALL)
                    if code_segment:
                        st.markdown("#### 💡 Remediated, Clean Code Implementations:")
                        st.caption("Use the copy button on the top right of the code window below for deployment:")
                        st.code(code_segment.group(1).strip())
                else:
                    st.info("📊 Generic Scan Insights Compiled:")
                    st.write(all_raw_responses)
            except Exception as parse_error:
                st.error(f"Could not render custom code UI split accurately: {str(parse_error)}")
