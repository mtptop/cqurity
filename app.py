import streamlit as st
import json
import time
import google.generativeai as genai

# 1. Page Configuration Settings
st.set_page_config(page_title="AI Security Sentinel", layout="wide")
st.title("🛡️ AI Security Sentinel: Vulnerability & Malware Analyzer")
st.caption("Bachelor Project Prototyping - Engineered with Google Gemini 2.5 Flash")

# 2. Sidebar Configuration for API Key Verification
st.sidebar.header("System Access Layer")
user_api_key = st.sidebar.text_input("Enter Gemini API Key:", type="password")

if user_api_key:
    genai.configure(api_key=user_api_key)

tab1, tab2 = st.tabs(["🔍 Source Code Vulnerabilities (SAST)", "☣️ Injected Malicious Code Detector"])

# -------------------------------------------------------------------------
# TAB 1: ACCIDENTAL VULNERABILITIES (DEVELOPER MISTAKES)
# -------------------------------------------------------------------------
with tab1:
    st.header("Static Application Security Testing (SAST) Matrix")
    st.markdown("Upload active code scripts to sweep logic lines for security oversights like buffer vulnerabilities or injections.")
    
    uploaded_files = st.file_uploader("Stage Source Scripts", type=["py", "c", "cpp", "java", "js"], accept_multiple_files=True, key="sast_upload")
    
    if uploaded_files:
        if not user_api_key:
            st.sidebar.warning("⚠️ Provide your free system key in the sidebar configuration panel to run the AI analyzer engine.")
        else:
            st.success(f"{len(uploaded_files)} source files successfully staged in local browser memory.")
            
            if st.button("Run Architecture Vulnerability Scan"):
                for uploaded_file in uploaded_files:
                    file_bytes = uploaded_file.read()
                    file_text = file_bytes.decode("utf-8", errors="ignore")
                    
                    st.markdown(f"#### Scanning file nodes: `{uploaded_file.name}`")
                    
                    # Formatting custom constraints specifically optimized for structural parsing
                    prompt = f"""
                    You are an expert automated security auditor. Analyze the following code.
                    Identify the single most critical accidental security vulnerability present.
                    You MUST return ONLY a valid JSON object string. Do not include extra conversational text or explanations outside the JSON block.
                    Use this identical JSON schema layout:
                    {{
                        "vulnerability_found": "Name of Security Flaw",
                        "cwe_id": "CWE-XXX",
                        "risk_level": "Critical/High/Medium",
                        "attack_vector_summary": "Explain how an attacker physically exploits this exact flaw structure",
                        "remediated_code_patch": "Provide the fully safe and rewritten version of the entire code block here"
                    }}
                    Source Code Text to Scan:
                    {file_text}
                    """
                    
                    with st.spinner("Processing syntax embeddings..."):
                        try:
                            # Declare the stable workhorse model: gemini-2.5-flash
                            model = genai.GenerativeModel("gemini-2.5-flash")
                            response = model.generate_content(prompt)
                            
                            # Clean response text structures safely
                            raw_text = response.text.strip()
                            if "```json" in raw_text:
                                raw_text = raw_text.split("```json")[1].split("```")[0].strip()
                            elif "```" in raw_text:
                                raw_text = raw_text.split("```")[1].split("```")[0].strip()
                                
                            parsed_output = json.loads(raw_text)
                            
                            # Render UI Analytics Cards
                            with st.expander(f"⚠️ Flagged Item: {parsed_output.get('vulnerability_found', 'Logic Issue')} ({parsed_output.get('risk_level', 'High')})"):
                                st.markdown(f"**Classification ID:** `{parsed_output.get('cwe_id', 'N/A')}`")
                                st.error(f"**Exploit Mechanism:** {parsed_output.get('attack_vector_summary', 'No summary generated.')}")
                                
                                st.markdown("**Remediated Safe Production Code Patch:**")
                                st.code(parsed_output.get('remediated_code_patch', '# No patch provided'), language="python")
                                
                                # Download trigger giving users the ability to export fixed files immediately
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
                    
                    # Rate-limiting cushion ensuring smooth compliance with standard free-tier boundaries
                    time.sleep(4)

# -------------------------------------------------------------------------
# TAB 2: INJECTED MALICIOUS CODE (SUPPLY CHAIN ATTACKS & TROJANS)
# -------------------------------------------------------------------------
with tab2:
    st.header("Injected Logic & Trojanized Backdoor Auditor")
    st.markdown("Upload suspected software scripts or source code repositories to check for foreign code fragments planted by malicious third parties.")
    
    malware_files = st.file_uploader("Stage Target System Files for Malware Sweep", type=["py", "js", "html", "sh"], accept_multiple_files=True, key="mal_upload")
    
    if malware_files:
        if not user_api_key:
            st.sidebar.warning("⚠️ Provide your free system key in the sidebar configuration panel to run the AI analyzer engine.")
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
                    You MUST return ONLY a valid JSON object string. Do not include extra text.
                    Use this identical JSON schema layout:
                    {{
                        "verdict": "MALICIOUS CODE FOUND or CLEAN STRUCTURE",
                        "confidence_rating": "Percentage (e.g. 95%)",
                        "malicious_snippet_location": "Identify line strings or functions containing the anomaly",
                        "threat_behavior_profile": "Describe precisely what the injected script attempts to execute covertly"
                    }}
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
                            
                            # Dynamic UI color shifting depending on malware verdicts
                            if "MALICIOUS" in m_parsed.get("verdict", "").upper():
                                st.error(f"🚨 Verdict: {m_parsed.get('verdict')} (Confidence: {m_parsed.get('confidence_rating', 'Unknown')})")
                                st.markdown(f"**Identified Anomaly Vector Location:** `{m_parsed.get('malicious_snippet_location')}`")
                                st.markdown(f"**Threat Behavior Profile:** {m_parsed.get('threat_behavior_profile')}")
                            else:
                                st.success(f"✅ Verdict: {m_parsed.get('verdict', 'CLEAN STRUCTURE')} (Confidence: {m_parsed.get('confidence_rating', '100%')})")
                                st.markdown("No active backdoors, hidden supply-chain dependency injections, or trojanized payloads identified inside this source block.")
                                
                        except json.JSONDecodeError:
                            st.warning(f"⚠️ Raw structural malware report generated for `{mal_file.name}`:")
                            with st.expander("View Unstructured Threat Profile"):
                                st.write(response.text)
                        except Exception as e:
                            st.error(f"Error executing threat audit sequence: {e}")
                    
                    time.sleep(4)
