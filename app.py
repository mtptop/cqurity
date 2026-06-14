import os
import re
import time
import zipfile
import tempfile
import streamlit as st
from google import genai
from google.genai import types

# --------------------------------------------------------
# 1. STREAMLIT CONFIGURATION (Python 3.14 Safe)
# --------------------------------------------------------
st.set_page_config(
    page_title="VulnAI: Security Auditor",
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
# 2. CORE WORKSPACE FILTRATION & TREE COMPILING
# --------------------------------------------------------
def estimate_tokens(text: str) -> int:
    """Calculates code footprint base using character distribution tokens."""
    return int(len(text) / 3.5) + 50

def parse_dependencies(file_path: str, base_dir: str) -> list:
    """Scans code files to extract structural import connections."""
    deps = []
    ext = os.path.splitext(file_path)[1].lower()
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
                clean_dep = match.split('.')[0] if ext == '.py' else match
                deps.append(clean_dep)
    except Exception:
        pass
    return deps

def scan_directory(base_dir: str):
    """Catalogues directory file assets, computing token metrics instantly."""
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
# 3. INTERACTIVE SIDEBAR DIRECTORY TREE
# --------------------------------------------------------
def render_sidebar_tree(base_dir: str, current_dir: str, level=0):
    """Recursively draws folder maps using expandable UI blocks."""
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
# 4. CHUNKING ENGINE (CONTEXT BUFFER WATCHDOG)
# --------------------------------------------------------
def generate_analysis_batches(registry: dict, max_tokens=100000):
    """Assembles optimized scanning groups under the token limit ceiling."""
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
# 5. AI EXECUTION STRATEGY (AI STUDIO SPECIFICATION)
# --------------------------------------------------------
def execute_gemma_scan(batch_files: list, registry: dict):
    """Dispatches full script files cleanly using the Gemma thinking pipeline."""
    prompt_payload = (
        "You are an advanced software security expert auditing code repositories.\n"
        "Analyze these files completely. Do NOT stop searching if you find a defect; "
        "continue scanning everything to provide a full report.\n\n"
        "Return your analysis matching this structure for EVERY file:\n\n"
        "=== START FILE: [File Path] ===\n"
        "### Status: [SAFE or VULNERABLE or MALICIOUS]\n\n"
        "### Flaws Found:\n"
        "[List every flaw found or write 'None.']\n\n"
        "### Refactored Code:\n"
        "```\n"
        "[Full working, replacement code file with no missing pieces or placeholders]\n"
        "```\n"
        "=== END FILE: [File Path] ===\n\n"
        "Target Source Code:\n"
    )
    for file_path in batch_files:
        prompt_payload += f"\n--- FILE: {file_path} ---\n{registry[file_path]['content']}\n"
    
    config = types.GenerateContentConfig(
        thinking_config=types.ThinkingConfig(thinking_level="HIGH"),
    )
    try:
        response = client.models.generate_content(
            model="gemma-4-31b-it",
            contents=prompt_payload,
            config=config,
        )
        return response.text
    except Exception as e:
        return f"⚠️ API Error Encountered: {str(e)}"

# --------------------------------------------------------
# 6. MINIMALIST DASHBOARD & ROUTER UI
# --------------------------------------------------------
st.title("🛡️ VulnAI: Source Code Auditor")
st.caption("Bachelor Project Portal Engine • Powered by Gemma 4 31B")
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
        
    # File analysis mapping triggers instantly
    file_registry = scan_directory(extract_path)
    
    # Left Sidebar Rendering
    st.sidebar.markdown("### 📂 Folder Workspace")
    render_sidebar_tree(extract_path, extract_path)
    
    # Project Core Summary Dashboard
    st.subheader("📊 Workspace Analysis Metrics")
    m_col1, m_col2, m_col3 = st.columns(3)
    m_col1.metric("Discovered Files", len(file_registry))
    m_col2.metric("Total File Size", f"{sum(f['size_bytes'] for f in file_registry.values()) / 1024:.2f} KB")
    m_col3.metric("Project Token Load", f"~{sum(f['estimated_tokens'] for f in file_registry.values())}")
    
    st.write("")
    
    # Execution Button Trigger
    if st.button("🚀 Execute Repository Deep Scan", use_container_width=True):
        batches = generate_analysis_batches(file_registry)
        st.info(f"📦 Workspace mapped into {len(batches)} context transmission blocks.")
        
        progress_bar = st.progress(0.0)
        all_raw_responses = ""
        
        for idx, batch in enumerate(batches):
            with st.spinner(f"Auditing Batch {idx + 1}/{len(batches)}..."):
                # 4-Second Interval Protective Threshold Check
                time.sleep(4.0)
                batch_response = execute_gemma_scan(batch, file_registry)
                all_raw_responses += batch_response + "\n"
            progress_bar.progress((idx + 1) / len(batches))
            
        progress_bar.empty()
        st.success("🎉 Repository Scan Completed.")
        
        # Present individual structural outputs per file asset
        for file_path, details in file_registry.items():
            st.markdown("---")
            st.markdown(f"### 📄 Source Target: `{file_path}`")
            
            try:
                segment_pattern = rf"=== START FILE: {re.escape(file_path)} ===(.*?)=== END FILE: {re.escape(file_path)} ==="
                segment_match = re.search(segment_pattern, all_raw_responses, re.DOTALL)
                
                if segment_match:
                    file_analysis = segment_match.group(1)
                    
                    status_match = re.search(r"### Status:\s*(\w+)", file_analysis)
                    status = status_match.group(1).upper() if status_match else "UNKNOWN"
                    
                    if "SAFE" in status:
                        st.success("🟢 Security Status: Verified Safe Code")
                    elif "VULNERABLE" in status:
                        st.warning("⚠️ Security Status: Vulnerability Identified")
                    else:
                        st.error("🚨 Security Status: Malicious Script Component Detected")
                        
                    flaws_segment = re.search(r"### Flaws Found:(.*?)(?=### Refactored Code:|$)", file_analysis, re.DOTALL)
                    if flaws_segment:
                        st.info("🔎 Discovered Architectural Flaws:")
                        st.markdown(flaws_segment.group(1).strip())
                        
                    code_segment = re.search(r"### Refactored Code:\s*\n```[a-zA-Z0-9]*\n(.*?)```", file_analysis, re.DOTALL)
                    if code_segment:
                        st.markdown("#### 💡 Remediated Code Block:")
                        st.code(code_segment.group(1).strip())
                else:
                    st.info("📝 Raw Analysis Data Block Compiled:")
                    st.text(all_raw_responses)
            except Exception as parse_error:
                st.error(f"Render engine parse variation: {str(parse_error)}")
