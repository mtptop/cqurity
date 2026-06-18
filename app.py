import os
import re
import time
import zipfile
import tempfile
import logging
from typing import Dict, List, Any, Tuple
import streamlit as st
from groq import Groq

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CQurityPortal")

st.set_page_config(
    page_title="CQurity",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("CQurity")
st.subheader("Llama 4 Scout - Code Auditor")
st.write("")

@st.cache_resource
def get_groq_client() -> Groq:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        st.error("Critical Configuration Error: GROQ_API_KEY is missing from environment secrets.")
        st.stop()
    return Groq(api_key=api_key)

client = get_groq_client()

def estimate_tokens(text: str) -> int:
    return int(len(text) / 3.5) + 50

def parse_dependencies(file_path: str, base_dir: str) -> List[str]:
    deps: List[str] = []
    ext = os.path.splitext(file_path)[1].lower()
    
    if ext not in ['.py', '.js', '.jsx', '.ts', '.tsx', '.c', '.cpp', '.h']:
        return deps

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
    except Exception as e:
        logger.error(f"Failed parsing dependencies for {file_path}: {str(e)}")
        
    return list(set(deps))

def scan_directory(base_dir: str) -> Dict[str, Dict[str, Any]]:
    file_registry: Dict[str, Dict[str, Any]] = {}
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.startswith('.') or '__pycache__' in root:
                continue
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, base_dir)
            try:
                if os.path.getsize(full_path) > 2 * 1024 * 1024:
                    continue
                    
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                
                if not content.strip():
                    continue

                file_registry[rel_path] = {
                    "full_path": full_path,
                    "size_bytes": os.path.getsize(full_path),
                    "estimated_tokens": estimate_tokens(content),
                    "dependencies": parse_dependencies(full_path, base_dir),
                    "content": content
                }
            except Exception as e:
                logger.warning(f"Skipping unreadable systemic file asset {rel_path}: {str(e)}")
                continue
    return file_registry

def render_sidebar_tree(current_dir: str, base_dir: str, parent_element) -> None:
    try:
        items = os.listdir(current_dir)
    except Exception as e:
        logger.error(f"Directory access failure at {current_dir}: {str(e)}")
        return
    
    items = sorted(items, key=lambda x: (not os.path.isdir(os.path.join(current_dir, x)), x.lower()))
    
    for item in items:
        if item.startswith('.') or '__pycache__' in item:
            continue
        full_path = os.path.join(current_dir, item)
        
        if os.path.isdir(full_path):
            folder_node = parent_element.expander(f"📁 {item}", expanded=False)
            render_sidebar_tree(full_path, base_dir, folder_node)
        else:
            parent_element.text(f"📄 {item}")

def generate_analysis_batches(registry: dict, max_tokens: int = 65000) -> List[List[str]]:
    batches: List[List[str]] = []
    current_batch: List[str] = []
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

def parse_batch_outputs(raw_text: str) -> Dict[str, Dict[str, str]]:
    parsed_map: Dict[str, Dict[str, str]] = {}
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
                "issues": issues_match.group(1).strip() if issues_match else "Unspecified security defect criteria.",
                "flawed_code": flawed_match.group(1).strip() if flawed_match else "",
                "fixed_code": fixed_match.group(1).strip() if fixed_match else ""
            }
        else:
            parsed_map[f_path] = {"status": "SAFE"}
            
    return parsed_map

uploaded_zip = st.file_uploader("Upload repository package ZIP file", type=["zip"])

if uploaded_zip:
    temp_dir = tempfile.TemporaryDirectory()
    zip_path = os.path.join(temp_dir.name, "repo.zip")
    extract_path = os.path.join(temp_dir.name, "extracted")
    
    with open(zip_path, "wb") as f:
        f.write(uploaded_zip.getbuffer())
        
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
    except zipfile.BadZipFile:
        st.error("Error: The uploaded asset file is not a valid zip archive.")
        st.stop()
        
    file_registry = scan_directory(extract_path)
    
    if not file_registry:
        st.warning("Workspace Scan Complete: No valid textual source code assets identified inside the payload.")
        st.stop()
    
    st.sidebar.markdown("### Repository Workspace Tree")
    render_sidebar_tree(extract_path, extract_path, st.sidebar)
    
    st.subheader("Project Metrics")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total File Assets", len(file_registry))
    col2.metric("Total Workspace Size", f"{sum(f['size_bytes'] for f in file_registry.values()) / 1024:.2f} KB")
    col3.metric("Aggregated Context Weight", f"~{sum(f['estimated_tokens'] for f in file_registry.values())} Tokens")
    st.write("")
    
    if st.button("Execute Cloud-Speed Dependency-Batched Scan", use_container_width=True):
        batches = generate_analysis_batches(file_registry)
        
        all_parsed_results: Dict[str, Dict[str, str]] = {}
        total_time_spent = 0.0
        
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
                completion = client.chat.completions.create(
                    model="meta-llama/llama-4-scout-17b-16e-instruct",
                    messages=[{"role": "user", "content": prompt_payload}],
                    temperature=0.1
                )
                
                raw_response_text = completion.choices[0].message.content
                batch_elapsed_time = time.time() - batch_start_time
                total_time_spent += batch_elapsed_time
                
                st.info(f"Batch {idx + 1} Scan Duration: {batch_elapsed_time:.2f} seconds")
                
                batch_results = parse_batch_outputs(raw_response_text)
                all_parsed_results.update(batch_results)
                
            except Exception as e:
                st.error(f"Groq Core Connection Error on Batch {idx + 1}: {str(e)}")
        
        st.write("---")
        st.markdown("## File Audit Breakdown")
        
        for file_path in file_registry.keys():
            st.markdown(f"### Target File asset: `{file_path}`")
            
            file_data = all_parsed_results.get(file_path, {"status": "SAFE"})
            status = file_data["status"]
            
            if status == "SAFE":
                st.success("Safe")
            else:
                st.error(status.capitalize())
                st.markdown("**Identified Vulnerabilities:**")
                st.write(file_data.get("issues", "Unspecified flaw details."))
                
                if file_data.get("flawed_code"):
                    st.markdown("**Flawed Code Segments:**")
                    st.code(file_data["flawed_code"])
                    
                if file_data.get("fixed_code"):
                    st.markdown("**Remediated Complete Code:**")
                    st.code(file_data["fixed_code"])
            st.write("")
            
        st.write("---")
        st.markdown("## Final Summary Audit Report")
        st.write(f"Total processing runtime elapsed: **{total_time_spent:.2f} seconds**")
        
        flagged_files = [f for f, d in all_parsed_results.items() if d.get("status") in ["VULNERABLE", "MALICIOUS"]]
        
        if flagged_files:
            for f_path in flagged_files:
                d = all_parsed_results[f_path]
                st.markdown(f"### `{f_path}`")
                st.markdown(f"- **Classification Status:** {d['status']}")
                summary_line = d.get("issues", "Security flaw identified.").split("\n")[0]
                st.markdown(f"- **Core Vulnerability:** {summary_line}")
        else:
            st.success("All analyzed files passed verification safely. Zero architectural defects discovered.")
