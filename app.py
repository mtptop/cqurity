import streamlit as st
import json
import time
import google.generativeai as genai

# 1. Page Configuration Settings
st.set_page_config(page_title="AI Security Sentinel", layout="wide")
st.title("🛡️ AI Security Sentinel: Vulnerability & Malware Analyzer")
st.caption("Bachelor Project Prototyping - Production Ready Cloud Execution Engine")

# 2. Automated Secrets Vault & Sidebar API Key Fallback Configuration
# It first checks if the key exists in Streamlit's hidden cloud secrets vault.
# If not found, it provides a fallback input field in the sidebar.
api_key_source = ""
if "GEMINI_API_KEY" in st.secrets:
    api_key_source = st.secrets["GEMINI_API_KEY"]
    st.sidebar.success("🔒 System Access Layer: Secured via Cloud Secrets Vault")
else:
    st.sidebar.header("System Access Layer")
    api_key_source = st.sidebar.text_input("Enter Gemini API Key:", type="password", help="Provide your free key if cloud secrets are not configured.")

if api_key_source:
    genai.configure(api_key=api_key_source)

tab1, tab2 = st.tabs(["🔍 Source Code Vulnerabilities (SAST)", "☣️ Injected Malicious Code Detector"])

# -------------------------------------------------------------------------
# TAB 1: ACCIDENTAL VULNERABILITIES (DEVELOPER MISTAKES)
# -------------------------------------------------------------------------
with tab1:
    st.header("Static Application Security Testing (SAST) Matrix")
    st.markdown("Upload active code scripts to sweep logic lines for security oversights like buffer vulnerabilities or injections.")
    
    uploaded_files = st.file_uploader("Stage Source Scripts", type=["py", "c", "cpp", "java", "js"], accept_multiple_files=True, key="sast_upload")
    
    if uploaded_files:
        if not api_key_source:
            st.warning("⚠️ Please provide a valid Gemini API Key to activate the AI analyzer engine.")
        else:
            st.success(f"{len(uploaded_files)} source files successfully staged in local browser memory.")
            
            if st.button("Run Architecture Vulnerability Scan"):
                for uploaded_file in uploaded_files:
                    file_bytes = uploaded_file.read()
                    file_text = file_bytes.decode("utf-8", errors="ignore")
                    
                    st.markdown(f"#### Scanning file nodes: `{uploaded_file.name}`")
                    
                    # Flexible conditional prompt that explicitly allows for completely clean code passes
                    prompt = f"""
                    You are an expert automated security auditor. Analyze the following code.
                    Determine if a genuine security vulnerability, logical flaw, or operational risk is present.

                    If the code is structurally safe, self-contained, handles data boundaries properly, and poses no real exploitation or compliance risks, you MUST output this identical JSON schema:
                    {{
                        "vulnerability_found": "NONE",
                        "cwe_id": "VALID",
                        "risk_level": "Safe",
                        "attack_vector_summary": "The analyzed code structure follows secure coding standards and contains no identifiable vulnerability pathways.",
                        "remediated_code_patch": "No remediation required."
                    }}

                    Otherwise, if a legitimate risk or flaw is present, output ONLY a valid JSON object string using this layout:
                    {{
                        "vulnerability_found": "Name of Security Flaw",
                        "cwe_id": "CWE-XXX",
                        "risk_level": "Critical/High/Medium",
                        "attack_vector_summary": "Explain how an attacker physically exploits this exact flaw structure",
                        "remediated_code_patch": "Provide the fully safe and rewritten version of the entire code block here"
                    }}
                    
                    Do not include extra conversational text outside the JSON block.
                    Source Code Text to Scan:
                    {file_text}
                    """
                    
                    with st.spinner("Processing syntax embeddings..."):
                        try:
                            model = genai.GenerativeModel("gemini-2.5-flash")
                            response = model.generate_content(prompt)
                            
                            # Clean response text structures safely
                            raw_text = response.text.strip()
                            if "```json" in raw_text:
                                raw_text = raw_text.split("```json")[1].split("```")[0].strip()
                            elif "```" in raw_text:
                                raw_text = raw_text.split("```")[1].split("```")[0].strip()
                                
                            parsed_output = json.loads(raw_text)
                            
                            # Route the UI display based on whether a vulnerability was actually discovered
                            if parsed_output.get('vulnerability_found', '').upper() == "NONE":
                                st.success(f"✅ Clean Pass: `{uploaded_file.name}` matches all verified secure coding baseline parameters.")
                            else:
                                with st.expander(f"⚠️ Flagged Item: {parsed_output.get('vulnerability_found', 'Logic Issue')} ({parsed_output.get('risk_level', 'High')})"):
                                    st.markdown(f"**Classification ID:** `{parsed_output.get('cwe_id', 'N/A')}`")
                                    st.error(f"**Exploit Mechanism:** {parsed_output.get('attack_vector_summary', 'No summary generated.')}")
                                    
                                    st.markdown("**Remediated Safe Production Code Patch:**")
                                    st.code(parsed_output.get('remediated_code_patch', '# No patch provided'), language="python")
                                    
                                    st.download_button(
                                        label="💾 Download Remediated Code Script",
                                        data=parsed_output.get('remediated_code_patch', ''),
                                        file_name=f"fixed_{uploaded_file.name}",
                                        mime="text/plain",
                                        key=f"dl_{uploaded_file.name}"
                                    )
                        except json.JSONDecodeError:
                            st.warning(f"⚠️ Raw structural data returned for `{uploaded_file.name}`. Parsing formatting wrapper below:")
                            with st.expander("View Unstructured Report"):
                                st.write(response.text)
                        except Exception as error_msg:
                            st.error(f"Execution Error processing target block: {error_msg}")
                    
                    time.sleep(4)

# -------------------------------------------------------------------------
# TAB 2: INJECTED MALICIOUS CODE (SUPPLY CHAIN ATTACKS & TROJANS)
# -------------------------------------------------------------------------
with tab2:
    st.header("Injected Logic & Trojanized Backdoor Auditor")
    st.markdown("Upload suspected software scripts or source code repositories to check for foreign code fragments planted by malicious third parties.")
    
    malware_files = st.file_uploader("Stage Target System Files for Malware Sweep", type=["py", "js", "html", "sh"], accept_multiple_files=True, key="mal_upload")
    
    if malware_files:
        if not api_key_source:
            st.warning("⚠️ Please provide a valid Gemini API Key to activate the AI analyzer engine.")
        else:
            st.info(f"{len(malware_files)} payloads loaded into processing vectors.")
            
            if st.button("Scan Content Vectors for Injected Exploits"):
                for mal_file in malware_files:
                    m_bytes = mal_file.read()
                    m_text = m_bytes.decode("utf-8", errors="ignore")
                    
                    st.markdown(f"#### Auditing content structure: `{mal_file.name}`")
                    
                    prompt = f"""
                    You are a reverse-engineering security response agent. Scan this file content.
                    Determine if an attacker has deliberately injected malicious logic (e.g., trojans, backdoors, hidden data exfiltration, obscured bash shells).
                    
                    If the code contains no backdoors or malicious alterations, you MUST output this JSON schema:
                    {{
                        "verdict": "CLEAN STRUCTURE",
                        "confidence_rating": "100%",
                        "malicious_snippet_location": "None",
                        "threat_behavior_profile": "No active backdoors, tracking modules, or malicious modifications identified."
                    }}
                    
                    Otherwise, output ONLY a valid JSON object string using this layout:
                    {{
                        "verdict": "MALICIOUS CODE FOUND",
                        "confidence_rating": "Percentage (e.g. 95%)",
                        "malicious_snippet_location": "Identify line strings or functions containing the anomaly",
                        "threat_behavior_profile": "Describe precisely what the injected script attempts to execute covertly"
                    }}
                    
                    Do not include extra text outside the JSON structure.
                    File Payload Content to Audit:
                    {m_text}
                    """
                    
                    with st.spinner("Tracking malicious signature patterns..."):
                        try:
                            model = genai.GenerativeModel("gemini-2.5-flash")
                            response = model.generate_content(prompt)
                            
                            clean_m_text = response.text.strip()
                            if "```json" in clean_m_text:
                                clean_m_text = clean_m_text.split("```json")[1].split("```")[0].strip()
                            elif "```" in clean_m_text:
                                clean_m_text = clean_m_text.split("```")[1].split("```")[0].strip()
                                
                            m_parsed = json.loads(clean_m_text)
                            
                            if "MALICIOUS" in m_parsed.get("verdict", "").upper():
                                st.error(f"🚨 Verdict: {m_parsed.get('verdict')} (Confidence: {m_parsed.get('confidence_rating', 'Unknown')})")
                                st.markdown(f"**Identified Anomaly Vector Location:** `{m_parsed.get('malicious_snippet_location')}`")
                                st.markdown(f"**Threat Behavior Profile:** {m_parsed.get('threat_behavior_profile')}")
                            else:
                                st.success(f"✅ Verdict: {m_parsed.get('verdict', 'CLEAN STRUCTURE')} (Confidence: {m_parsed.get('confidence_rating', '100%')})")
                                st.markdown(f"**Threat Behavior Profile:** {m_parsed.get('threat_behavior_profile')}")
                                
                        except json.JSONDecodeError:
                            st.warning(f"⚠️ Raw structural malware report generated for `{mal_file.name}`:")
                            with st.expander("View Unstructured Threat Profile"):
                                st.write(response.text)
                        except Exception as e:
                            st.error(f"Error executing threat audit sequence: {e}")
                    
                    time.sleep(4)
