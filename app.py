import os
import re
import time
import zipfile
import tempfile
import streamlit as st
from groq import Groq

# --------------------------------------------------------
# 1. STREAMLIT SYSTEM INITIALIZATION
# --------------------------------------------------------
st.set_page_config(
    page_title="VulnAI: Groq Advanced Engine",
    layout="wide",
    initial_sidebar_state="expanded"
)

@st.cache_resource
def get_groq_client():
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        st.error("❌ GROQ_API_KEY is missing from Streamlit Secrets.")
        st.stop()
    return Groq(api_key=api_key)

client = get_groq_client()

# --------------------------------------------------------
# 2. FILE SCANNING & DEPENDENCY CORE LOGIC
# --------------------------------------------------------
def estimate_tokens(text: str) -> int:
    """Estimates code token footprint based on character distributions."""
    return int(len(text) / 3.5) + 50

def parse_dependencies(file_path: str, base_dir: str) -> list:
    """Extracts internal code dependencies to structure execution chains."""
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
# 3. INTERACTIVE SIDEBAR TREE COMPONENT
# --------------------------------------------------------
def render_sidebar_tree(base_dir: str, current_dir: str, level=0):
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
# 4. DEPENDENCY-BASED BATCHING STRATEGY
# --------------------------------------------------------
def generate_analysis_batches(registry: dict, max_tokens=100000):
    """Groups interconnected code files together under strict context limits."""
    batches = []
    current_batch = []
    current_tokens = 0
    # Sorting components based on their structural dependencies down the execution wire
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
# 5. GROQ LIVE INFERENCE PIPELINE (Genuine Analyzer Prompt)
# --------------------------------------------------------
def execute_groq_scan(batch_files: list, registry: dict):
    """Assembles context data payloads and opens an instantaneous Groq stream."""
    prompt_payload = (
        "You are an objective, hyper-accurate software security auditor. Analyze the following file(s) "
        "comprehensively for architectural vulnerabilities, security flaws, weaknesses, and malicious payloads.\n"
        "CRITICAL INSTRUCTION: Do NOT invent, assume, or force false flaws if the code is safe. "
        "Be a completely unbiased analyzer. If the code follows safe patterns, explicitly rate it as SAFE "
        "and state that no flaws were found.\n\n"
        "Provide your analysis back strictly matching this exact layout structure for EVERY single file:\n\n"
        "=== START FILE: [File Path] ===\n"
        "### Status: [SAFE or VULNERABLE or MALICIOUS]\n\n"
        "### Flaws Found:\n"
        "[List genuine issues itemized here. If no security issues exist, write 'None.']\n\n"
        "### Refactored Code:\n"
        "```\n"
        "[Only provide replacement code if vulnerabilities were present. Otherwise, state 'No refactoring required.']\n"
        "```\n"
        "=== END FILE: [File Path] ===\n\n"
        "Here is the code to audit:\n"
    )
    
    for file_path in batch_files:
        prompt_payload += f"\n--- FILE: {file_path} ---\n{registry[file_path]['content']}\n"
        
    try:
        completion = client.chat.completions.create(
            model="meta-llama/llama-4-scout-17b-16e-instruct",
            messages=[{"role": "user", "content": prompt_payload}],
            stream=True
        )
        return completion
    except Exception as e:
        st.error(f"⚠️ Groq API connection failure: {str(e)}")
        return None

# --------------------------------------------------------
# 6. MAIN APPLICATION GRAPHICAL ROUTER
# --------------------------------------------------------
st.title("🛡️ VulnAI: Advanced Groq Security Engine")
st.caption("Bachelor Project Portal Engine • Hosted on Meta Llama 4 Scout (17B Active MoE)")
st.write("")

uploaded_zip = st.file_uploader("Drop your target source repository ZIP archive here", type=["zip"])

if uploaded_zip:
    temp_dir = tempfile.TemporaryDirectory()
    zip_path = os.path.join(temp_dir.name, "repo.zip")
    extract_path = os.path.join(temp_dir.name, "extracted")
    
    with open(zip_path, "wb") as f:
        f.write(uploaded_zip.getbuffer())
        
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_path)
        
    file_registry = scan_directory(extract_path)
    
    # Render left sidebar structure
    st.sidebar.markdown("### 📂 Repository File Tree")
    render_sidebar_tree(extract_path, extract_path)
    
    # Project Snapshot Telemetry Metrics
    st.subheader("📊 Target Package Snapshot")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total File Assets", len(file_registry))
    col2.metric("Total Code Size", f"{sum(f['size_bytes'] for f in file_registry.values()) / 1024:.2f} KB")
    col3.metric("Aggregated Context Weight", f"~{sum(f['estimated_tokens'] for f in file_registry.values())} Tokens")
    st.write("")
    
    if st.button("🚀 Run Cloud-Speed Dependency-Batched Scan", use_container_width=True):
        batches = generate_analysis_batches(file_registry)
        st.info(f"📦 Workspace organized into **{len(batches)} multi-file dependency batches**.")
        
        for idx, batch in enumerate(batches):
            st.markdown(f"### 📦 Processing Context Batch {idx + 1}/{len(batches)}")
            st.caption(f"Batch files included: {', '.join([f'`{b}`' for b in batch])}")
            
            start_time = time.time()
            response_stream = execute_groq_scan(batch, file_registry)
            
            if response_stream:
                stream_box = st.empty()
                batch_text = ""
                
                for chunk in response_stream:
                    if chunk.choices and chunk.choices[0].delta.content:
                        batch_text += chunk.choices[0].delta.content
                        stream_box.markdown(batch_text)
                
                elapsed_time = time.time() - start_time
                st.success(f"⏱️ **Batch {idx + 1} processing duration:** {elapsed_time:.2f} seconds")
        
        st.write("---")
        st.success("🎉 Comprehensive repository audit finished. You can review the streamed logs above.")
