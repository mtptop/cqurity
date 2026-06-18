import os
import re
import time
import zipfile
import tempfile
import logging
from typing import Dict, List, Any, Tuple
import streamlit as st
from groq import Groq

# ლოგერის კონფიგურაცია სისტემური მოვლენების მონიტორინგისთვის
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CQurityPortal")

# Streamlit-ის გვერდის ძირითადი პარამეტრები
st.set_page_config(
    page_title="CQurity",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("CQurity")
st.subheader("Llama 4 Scout - Code Auditor")
st.write("")

# session state ცვლადების თრექინგის ინიციალიზაცია
if "all_parsed_results" not in st.session_state:
    st.session_state.all_parsed_results = {}
if "scan_completed" not in st.session_state:
    st.session_state.scan_completed = False
if "total_time_spent" not in st.session_state:
    st.session_state.total_time_spent = 0.0

@st.cache_resource
def get_groq_client() -> Groq:
    """
    გარემოს ცვლადებიდან Groq client-ს უკეთებს ინიციალიზაციას. 
    GROQ_API_KEY-ის არარსებობის შემთხვევაში აჩერებს აპლიკაციის მუშაობას.
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        st.error("Critical Configuration Error: GROQ_API_KEY is missing from environment secrets.")
        st.stop()
    return Groq(api_key=api_key)

# გლობალური API client-ის შექმნა
client = get_groq_client()

def estimate_tokens(text: str) -> int:
    """
    აკოდის ტექსტის ტოკენების რაოდენობის უხეში ვარაუდი.
    საშუალოდ 3.5 სიმბოლო ითვლება 1 ტოკენად. მცირე ბუფერი უსაფრთხოებისთვის(50).
    """
    return int(len(text) / 3.5) + 50

def parse_dependencies(file_path: str, base_dir: str) -> List[str]:
    """
    სტატიკურად აანალიზებს ფაილის იმპორტებს (dependencies) ფაილის გაფართოების მიხედვით.
    მხარდაჭერილია: Python, JS/TS (ES6 & CommonJS), C/C++.
    """
    deps: List[str] = []
    ext = os.path.splitext(file_path)[1].lower()
    
    # ვამუშავებთ მხოლოდ იმ ფაილებს, რომლებსაც აქვთ იმპორტების ლოგიკა
    if ext not in ['.py', '.js', '.jsx', '.ts', '.tsx', '.c', '.cpp', '.h']:
        return deps

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
        # Regex პატერნები სხვადასხვა ენის იმპორტის სინტაქსისთვის
        patterns = [
            r'(?:import|from)\s+([a-zA-Z0-9_\.]+)', # Python & ES6 import
            r'require\([\'"](.+)[\'"]\)',            # CommonJS require
            r'#include\s+[\'"](.+)[\'"]'             # C/C++ include
        ]
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                # Python-ის შემთხვევაში ვიღებთ მხოლოდ ძირეულ მოდულს
                clean_dep = match.split('.')[0] if ext == '.py' else match
                deps.append(clean_dep)
    except Exception as e:
        logger.error(f"Failed parsing dependencies for {file_path}: {str(e)}")
        
    return list(set(deps)) # აბრუნებს უნიკალურ იმპორტებს

def scan_directory(base_dir: str) -> Dict[str, Dict[str, Any]]:
    """
    რეპოზიტორიის სრული სკანირება. ფილტრავს ფარულ ფაილებს, ქეშებს და 
    2MB-ზე დიდ ბინარულ/ტექსტურ აქტივებს, შემდეგ აშენებს ფაილების რეესტრს.
    """
    file_registry: Dict[str, Dict[str, Any]] = {}
    for root, _, files in os.walk(base_dir):
        for file in files:
            # ვალაგებთ სისტემურ და ფარულ ფაილებს/საქაღალდეებს
            if file.startswith('.') or '__pycache__' in root:
                continue
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, base_dir)
            try:
                # ფაილის ზომის ლიმიტი (2MB), რათა თავიდან ავიცილოთ დიდი მონაცემების დამუშავება
                if os.path.getsize(full_path) > 2 * 1024 * 1024:
                    continue
                    
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                
                # ცარიელი ფაილების იგნორირება
                if not content.strip():
                    continue

                # ფაილის metadata რეგისტრაცია
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

def render_sidebar_tree(current_dir: str, base_dir: str, parent_element, flagged_paths: set) -> None:
    """
    რეკურსიულად აშენებს პროექტის ფაილურ იერარქიას (Tree View) Streamlit-ის sidebar მენიუში.
    თუ ფაილი მონიშნულია როგორც საფრთხე, მას და მის მშობელ საქაღალდეებს ენიჭებათ '🛑' პრეფიქსი.
    """
    try:
        items = os.listdir(current_dir)
    except Exception as e:
        logger.error(f"Directory access failure at {current_dir}: {str(e)}")
        return
    
    # ვასორტირებთ: ჯერ საქაღალდეები, შემდეგ ფაილები
    items = sorted(items, key=lambda x: (not os.path.isdir(os.path.join(current_dir, x)), x.lower()))
    
    for item in items:
        if item.startswith('.') or '__pycache__' in item:
            continue
        full_path = os.path.join(current_dir, item)
        rel_path = os.path.relpath(full_path, base_dir)
        
        # ვამოწმებთ არის თუ არა ფაილი ან საქაღალდე საფრთხის შემცველ კავშირში
        is_flagged = rel_path in flagged_paths
        prefix = "🛑 " if is_flagged else ""
        
        if os.path.isdir(full_path):
            # საქაღალდეებისთვის ვიყენებთ expander კომპონენტს რეკურსიულად
            folder_node = parent_element.expander(f"{prefix}📁 {item}", expanded=False)
            render_sidebar_tree(full_path, base_dir, folder_node, flagged_paths)
        else:
            parent_element.text(f"{prefix}📄 {item}")

def generate_analysis_batches(registry: dict, max_tokens: int = 65000) -> List[List[str]]:
    """
    იმპლემენტირებულია Greedy Bin-Packing ალგორითმი.
    აფასებს ფაილებს ტოკენების მიხედვით და აჯგუფებს ოპტიმალურ batch-ებად,
    რათა მაქსიმალურად ეფექტურად იქნას გამოყენებული LLM-ის კონტექსტური ფანჯარა (Context Window).
    """
    batches: List[List[str]] = []
    current_batch: List[str] = []
    current_tokens = 0
    
    # სორტირება dependencies რაოდენობის მიხედვით, რათა დაკავშირებული ფაილები ერთად მოხვდნენ
    sorted_files = sorted(registry.keys(), key=lambda x: len(registry[x]['dependencies']), reverse=True)
    
    for file_path in sorted_files:
        file_tokens = registry[file_path]['estimated_tokens']
        
        # თუ ერთი ფაილი აჭარბებს მაქსიმალურ ლიმიტს, მას ცალკე გამოვყოფთ
        if file_tokens > max_tokens:
            batches.append([file_path])
            continue
            
        # ახალი batch-ის შექმნა, თუ მიმდინარე ლიმიტს გადავაცილეთ
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
    """
    ახდენს LLM-ისგან მიღებული ნედლი პასუხის დეკონსტრუქციას მკაცრად განსაზღვრული
    ტეგების (FILE_START / FILE_END) და Regex პატერნების მიხედვით.
    """
    parsed_map: Dict[str, Dict[str, str]] = {}
    pattern = r"=== FILE_START:\s*(.*?)\s*===(.*?)=== FILE_END:\s*\1\s*==="
    matches = re.findall(pattern, raw_text, re.DOTALL | re.IGNORECASE)
    
    for file_path, block_content in matches:
        f_path = file_path.strip()
        
        # სტატუსის ამოღება
        status_match = re.search(r"\[RESULT\]:\s*(\w+)", block_content, re.IGNORECASE)
        status = status_match.group(1).strip().upper() if status_match else "SAFE"
        
        if status in ["VULNERABLE", "MALICIOUS"]:
            # დეტალური ინფორმაციის ამოღება სხვადასხვა სექციიდან
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

# მომხმარებლის ინტერფეისის მთავარი ლოგიკა

uploaded_zip = st.file_uploader("Upload repository package ZIP file", type=["zip"])

if uploaded_zip:
    # ახალი ფაილის ატვირთვისას ხდება წინა სკანირების ქეშის და session_state-ის გასუფთავება
    if "current_zip_name" not in st.session_state or st.session_state.current_zip_name != uploaded_zip.name:
        st.session_state.current_zip_name = uploaded_zip.name
        st.session_state.all_parsed_results = {}
        st.session_state.scan_completed = False
        st.session_state.total_time_spent = 0.0

    # დროებითი საქაღალდის შექმნა ფაილების დეკომპრესიისთვის
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
        
    # საფრთხის შემცველი გზების იდენტიფიცირება sidebar ხეში წითლად მოსანიშნად
    flagged_paths = set()
    for rel_path, data in st.session_state.all_parsed_results.items():
        if data.get("status") in ["VULNERABLE", "MALICIOUS"]:
            flagged_paths.add(rel_path)
            
            # მონიშვნა ვრცელდება მშობელ საქაღალდეებზეც ინდიკატორების სახით
            parent = os.path.dirname(rel_path)
            while parent and parent != ".":
                flagged_paths.add(parent)
                parent = os.path.dirname(parent)
        
    st.sidebar.markdown(f"### {uploaded_zip.name}")
    render_sidebar_tree(extract_path, extract_path, st.sidebar, flagged_paths)
    
    # პროექტის ძირითადი სტატისტიკური მონაცემების გამოტანა
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
        
        # System prompt, რომელიც განსაზღვრავს მოდელის ქცევას და პასუხის მკაცრ ფორმატს
        base_prompt = (
            "You are an objective, hyper-accurate software security auditor. Analyze the following files "
            "comprehensively from top to bottom. MANDATORY: Do NOT stop searching or truncate outputs after finding "
            "the first vulnerability; you must scan the entire file fully to identify every single flaw.\n\n"
            "CRITICAL CLASSIFICATION RULES:\n"
            "- Set [RESULT] to VULNERABLE if the file contains accidental security bugs, logical flaws, or risky code left by a developer.\n"
            "- Set [RESULT] to MALICIOUS if the code contains intentional threats, data exfiltration, backdoors, spyware, hidden scripts, or explicit malware logic.\n\n"
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
        
        # ასინქრონული/თანმიმდევრული მოთხოვნები Groq API-სთან თითოეული batch-ისთვის
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
                    temperature=0.1 # დაბალი ტემპერატურა დეტექციის სტაბილურობისთვის
                )
                
                raw_response_text = completion.choices[0].message.content
                batch_elapsed_time = time.time() - batch_start_time
                total_time_spent += batch_elapsed_time
                
                st.info(f"Batch {idx + 1} Scan Duration: {batch_elapsed_time:.2f} seconds")
                
                # პასუხის პარსინგი და შედეგების შეგროვბა
                batch_results = parse_batch_outputs(raw_response_text)
                all_parsed_results.update(batch_results)
                
            except Exception as e:
                st.error(f"Groq Core Connection Error on Batch {idx + 1}: {str(e)}")
        
        # შედეგების შენახვა და გვერდის განახლება ინდიკატორების გამოსაჩენად
        st.session_state.all_parsed_results = all_parsed_results
        st.session_state.total_time_spent = total_time_spent
        st.session_state.scan_completed = True
        st.rerun()

    # სკანირების შედეგების ვიზუალიზაციის ბლოკი
    if st.session_state.scan_completed:
        st.write("---")
        st.markdown("## File Audit Breakdown")
        
        for file_path in file_registry.keys():
            st.markdown(f"### Target File asset: `{file_path}`")
            
            file_data = st.session_state.all_parsed_results.get(file_path, {"status": "SAFE"})
            status = file_data["status"]
            
            if status == "SAFE":
                st.success("Safe")
            else:
                # ვიზუალური დიფერენცირება საფრთხეების მიხედვით
                st.error(status.upper())
                st.markdown("**Identified Threat Metrics:**")
                st.write(file_data.get("issues", "Unspecified flaw details."))
                
                if file_data.get("flawed_code"):
                    st.markdown("**Flawed Code Segments:**")
                    st.code(file_data["flawed_code"])
                    
                if file_data.get("fixed_code"):
                    st.markdown("**Remediated Complete Code:**")
                    st.code(file_data["fixed_code"])
            st.write("")
            
        # საბოლოო შეჯამებული ანგარიში (Summary Report)
        st.write("---")
        st.markdown("## Final Summary Audit Report")
        st.write(f"Total processing runtime elapsed: **{st.session_state.total_time_spent:.2f} seconds**")
        
        flagged_files = [f for f, d in st.session_state.all_parsed_results.items() if d.get("status") in ["VULNERABLE", "MALICIOUS"]]
        
        if flagged_files:
            for f_path in flagged_files:
                d = st.session_state.all_parsed_results[f_path]
                st.markdown(f"### `{f_path}`")
                st.markdown(f"- **Classification Status:** **{d['status']}**")
                
                label_prefix = "Core Threat/Malware Logic" if d['status'] == "MALICIOUS" else "Core Vulnerability"
                summary_line = d.get("issues", "Security flaw identified.").split("\n")[0]
                st.markdown(f"- **{label_prefix}:** {summary_line}")
        else:
            st.success("All analyzed files passed verification safely. Zero architectural defects discovered.")
