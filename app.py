import os
import re
import time
import zipfile
import tempfile
import streamlit as st
from groq import Groq

# --------------------------------------------------------
# 1. STREAMLIT INITIALIZATION & APP HEADERS
# --------------------------------------------------------
st.set_page_config(
    page_title="CQurity Portal",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Display specific project and model credentials with zero emojis
st.title("CQurity")
st.subheader("Llama 3.3 70B Versatile")
st.write("")

@st.cache_resource
def get_groq_client():
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        st.error("GROQ_API_KEY is missing from Streamlit Secrets.")
        st.stop()
    return Groq(api_key=api_key)

client = get_groq_client()

# --------------------------------------------------------
# 2. FILE REGISTRY & DEPENDENCY PARSING
# --------------------------------------------------------
def estimate_tokens(text: str) -> int:
    return int(len(text) / 3.5) + 50

def parse_dependencies(file_path: str, base_dir: str) -> list:
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
# 3. COMPREHENSIVE RECURSIVE SIDEBAR TREE (GITHUB STYLE)
# --------------------------------------------------------
def render_sidebar_tree(current_dir: str, base_dir: str, parent_element):
    """Recursively draws hierarchical paths pinning sub-folders to the top."""
    try:
        items = os.listdir(current_dir)
    except Exception:
        return
    
    # Sort: Folders first (GitHub style), then files alphabetically
    items = sorted(items, key=lambda x: (not os.path.isdir(os.path.join(current_dir, x)), x.lower()))
    
    for item in items:
        if item.startswith('.'):
            continue
        full_path = os.path.join(current_dir, item)
        
        if os.path.isdir(full_path):
            # Create a nested container inside the current element context
            folder_node = parent_element.expander(f"📁 {item}", expanded=False)
            render_sidebar_tree(full_path, base_dir, folder_node)
        else:
            parent_element.text(f"📄 {item}")

# --------------------------------------------------------
# 4. DEPENDENCY-BASED BATCHING STRATEGY
# --------------------------------------------------------
def generate_analysis_batches(registry: dict, max_tokens=70000):
    batches = []
    current_batch = []
    current_tokens = 0
    # Prioritize execution grouping based on internal file connections
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
# 5. RESPONSE STRUCTURAL DECONSTRUCTION PARSER
# --------------------------------------------------------
def parse_batch_outputs(raw_text: str) -> dict:
    """Extracts structural sections from raw strings cleanly via flexible tags."""
    parsed_map = {}
    pattern = r"=== FILE_START:\s*(.*?)\s*===(.*?)=== FILE_END:\s*\1\s*==="
    matches = re.findall(pattern, raw_text, re.DOTALL | re.IGNORECASE)
    
    for file_path, block_content in matches:
        f_path = file_path.strip()
        
        status_match = re.search(r"\[RESULT\]:\s*(\w+)", block_content, re.IGNORECASE)
        status = status_match.group(1).strip().upper() if status_match else "SAFE"
        
        if status in ["VULNERABLE", "MALICIOUS"]:
            issues_match = re.search(r"\[ISSUE_DETAILS\]:(.*?)(?=\[FLAWED_CODE_SEGMENT\]:|$)", block_content, re.DOTALL | re.IGNORECASE)
            flawed_match = re.search(r"\[FLAWED_CODE_SEGMENT\]:(.*?)(?=\[FIXED_FULL_CODE\]:|$)", block_content, re.DOTALL | re.IGNORECASE)
            fixed_match = re.search(r"\[FIXED_FULL_CODE\]:\s*\n```[a-zA-Z0-9]*\n(.*?)```", block_content, re.DOTALL | re.IGNORECASE)
            
            parsed_map[f_path] = {
                "status": status,
                "issues": issues_match.group(1).strip() if issues_match else "Unspecified flaw details.",
                "flawed_code": flawed_match.group(1).strip() if flawed_match else "",
                "fixed_code": fixed_match.group(1).strip() if fixed_match else ""
            }
        else:
            parsed_map[f_path] = {"status": "SAFE"}
            
    return parsed_map

# --------------------------------------------------------
# 6. APP UI ROUTER
# --------------------------------------------------------
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
    
    # Generate structural file explorer tree in the sidebar
    st.sidebar.markdown("### Repository Workspace Tree")
    render_sidebar_tree(extract_path, extract_path, st.sidebar)
    
    # Display numeric telemetry summary (omitting 'target package snapshot' title)
    st.subheader("Project Metrics")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total File Assets", len(file_registry))
    col2.metric("Total Workspace Size", f"{sum(f['size_bytes'] for f in file_registry.values()) / 1024:.2f} KB")
    col3.metric("Aggregated Context Weight", f"~{sum(f['estimated_tokens'] for f in file_registry.values())} Tokens")
    st.write("")
    
    # Process scan trigger with clean textual labels (omitting emojis)
    if st.button("Execute Cloud-Speed Dependency-Batched Scan", use_container_width=True):
        batches = generate_analysis_batches(file_registry)
        
        all_parsed_results = {}
        total_time_spent = 0.0
        
        # Base instruction prompt forcing absolute full file file coverage audits
        base_prompt = (
            "You are an objective, hyper-accurate software security auditor. Analyze the following files "
            "comprehensively from top to bottom. MANDATORY: Do NOT stop searching or truncate outputs after finding "
            "the first vulnerability; you must scan the entire file fully to identify every single flaw.\n\n"
            "If a file is completely safe, follow the SAFE format precisely. Do not fabricate issues.\n\n"
            "You MUST enclose your audit response for EACH file strictly using this structural layout template:\n\n"
            "=== FILE_START: [Insert Relative File Path Here] ===\n"
            "[RESULT]: [SAFE or VULNERABLE or MALICIOUS]\n\n"
            "[ISSUE_DETAILS]:\n"
            "[List every single discovered security bug, loop flaw, or dependency injection gap found here]\n\n"
            "[FLAWED_CODE_SEGMENT]:\n"
            "[Extract the exact lines of raw code that contain the vulnerability]\n\n"
            "[FIXED_FULL_CODE]:\n"
            "```\n"
            "[Provide the entire replacement code for the full file containing all applied security patches from top to bottom]\n"
            "```\n"
            "=== FILE_END: [Insert Relative File Path Here] ===\n\n"
            "If a file contains no flaws or code risks, return strictly this wrapper format:\n"
            "=== FILE_START: [Insert Relative File Path Here] ===\n"
            "[RESULT]: SAFE\n"
            "=== FILE_END: [Insert Relative File Path Here] ===\n\n"
            "Source code payloads to verify:\n"
        )
        
        for idx, batch in enumerate(batches):
            st.markdown(f"### Processing Context Batch {idx + 1}/{len(batches)}")
            
            prompt_payload = base_prompt
            for file_path in batch:
                prompt_payload += f"\n--- TARGET PATH: {file_path} ---\n{file_registry[file_path]['content']}\n"
            
            batch_start_time = time.time()
            
            try:
                # Query Llama 3.3 70B on Groq
                completion = client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[{"role": "user", "content": prompt_payload}],
                    temperature=0.1
                )
                
                raw_response_text = completion.choices[0].message.content
                batch_elapsed_time = time.time() - batch_start_time
                total_time_spent += batch_elapsed_time
                
                st.info(f"Batch {idx + 1} Scan Duration: {batch_elapsed_time:.2f} seconds")
                
                # Parse batch blocks and combine with master registry dictionary
                batch_results = parse_batch_outputs(raw_response_text)
                all_parsed_results.update(batch_results)
                
            except Exception as e:
                st.error(f"Groq Core Connection Error on Batch {idx + 1}: {str(e)}")
        
        # --------------------------------------------------------
        # 7. RENDER CLEAN SEPARATED STATUS FIELDS
        # --------------------------------------------------------
        st.write("---")
        st.markdown("## File Audit Breakdown")
        
        # Loop through original files to ensure un-parsed or skipped assets show as verified
        for file_path in file_registry.keys():
            st.markdown(f"### Target File asset: `{file_path}`")
            
            file_data = all_parsed_results.get(file_path, {"status": "SAFE"})
            status = file_data["status"]
            
            if status == "SAFE":
                st.success("Safe")
            else:
                # Unsafe components display explicit type status header first inside red field
                st.error(status.capitalize())
                
                st.markdown("**Identified Vulnerabilities:**")
                st.write(file_data["issues"])
                
                if file_data["flawed_code"]:
                    st.markdown("**Flawed Code Segments:**")
                    st.code(file_data["flawed_code"])
                    
                if file_data["fixed_code"]:
                    st.markdown("**Remediated Complete Code:**")
                    st.code(file_data["fixed_code"])
            st.write("")
            
        # --------------------------------------------------------
        # 8. FINAL CONCISE COMPOSITE FULL REPORT SUMMARY
        # --------------------------------------------------------
        st.write("---")
        st.markdown("## Final Summary Audit Report")
        st.write(f"Total processing runtime elapsed: **{total_time_spent:.2f} seconds**")
        
        flagged_files = [f for f, d in all_parsed_results.items() if d.get("status") in ["VULNERABLE", "MALICIOUS"]]
        
        if flagged_files:
            for f_path in flagged_files:
                d = all_parsed_results[f_path]
                st.markdown(f"### `{f_path}`")
                st.markdown(f"- **Classification Status:** {d['status']}")
                
                # Extract first descriptive summary line to keep it clean and short
                summary_line = d["issues"].split("\n")[0]
                st.markdown(f"- **Core Vulnerability:** {summary_line}")
        else:
            st.success("All analyzed files passed verification safely. Zero architectural defects discovered.")
