import requests
import re
import sys
import json
import os
import time
from pathlib import Path
from requests.exceptions import Timeout, RequestException

# --- CẤU HÌNH ---
BASE_URL = "http://localhost:42110"
CHAT_ENDPOINT = f"{BASE_URL}/api/chat"
GEMINI_API_KEY = "YOUR_GEMINI_API_KEY_HERE"
DEFAULT_TIMEOUT = 300

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

# --- PROMPT ---
PROMPT_DISCOVERY_TEMPLATE = """
CONTEXT SOURCE: "{filename}"
KEYWORDS: Vulnerabilities Findings Security Issues Bugs

INSTRUCTION:
Based ONLY on the provided context chunks from the audit report "{filename}", identify the main vulnerability or finding described in this report.
**IGNORE SEVERITY LEVELS.** Even if the finding is marked as Low, Informational, or unclassified, you MUST list it.

For each finding, provide a short summary in this format:
1. ID/Name: (e.g., VUL-01: Reentrancy)
2. Affected Function: (The specific function name mentioned. If global, say "Global")
3. Root Cause: (A one-sentence explanation of the logic failure)

Do not go into deep detail yet, just provide the list.
"""

def query_rag(prompt, n_context=100, custom_timeout=None, max_retries=3):
    effective_timeout = custom_timeout if custom_timeout else DEFAULT_TIMEOUT
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {GEMINI_API_KEY}"
    }
    payload = {
        "q": prompt,
        "stream": False,
        "client": "web",
        "n": n_context,
    }
    
    for attempt in range(max_retries):
        print(f"⏳ Sending request to Khoj... (Attempt {attempt+1}/{max_retries}, Waiting up to {effective_timeout}s)")
        
        try:
            response = requests.post(CHAT_ENDPOINT, json=payload, headers=headers, timeout=effective_timeout)
            if response.status_code == 200:
                return response.json().get('response', '')
            elif response.status_code == 429:
                # Rate limit hit
                if attempt < max_retries - 1:
                    wait_time = 30  # Wait 30 seconds for rate limit
                    print(f"{Colors.YELLOW}⚠️  Rate limit hit. Waiting {wait_time}s before retry...{Colors.END}")
                    time.sleep(wait_time)
                    continue
                else:
                    print(f"{Colors.RED}❌ Rate limit exceeded after {max_retries} attempts{Colors.END}")
                    return None
            else:
                print(f"{Colors.RED}❌ API Error {response.status_code}: {response.text}{Colors.END}")
                return None
        except Timeout:
            print(f"{Colors.RED}❌ TIMEOUT ERROR: Khoj did not respond within {effective_timeout}s.{Colors.END}")
            if attempt < max_retries - 1:
                print(f"Retrying... ({attempt+2}/{max_retries})")
                continue
            return None
        except RequestException as e:
            print(f"{Colors.RED}❌ Connection Error: {e}{Colors.END}")
            return None
    
    return None

def extract_features_from_code(solidity_code):
    features = {"contract_name": None, "functions": []}
    c_match = re.search(r'contract\s+(\w+)', solidity_code)
    if c_match:
        features["contract_name"] = c_match.group(1)
    
    f_matches = re.findall(r'function\s+(\w+)\s*\(', solidity_code)
    ignore = ['constructor', 'receive', 'fallback']
    features["functions"] = [f for f in f_matches if f not in ignore][:5]
    return features

def identify_audit_report(features):
    c_name = features.get("contract_name", "Unknown")
    funcs = ", ".join(features.get("functions", []))
    
    print(f"{Colors.YELLOW}🔍 Phase 1: Identifying Audit Report...{Colors.END}")
    prompt = f"""
    I have a Solidity smart contract. Name: "{c_name}". Functions: {funcs}.
    Search your Knowledge Base. Which PDF Audit Report analyzes this code?
    Return ONLY the filename (e.g., "Audit.pdf"). If unknown, say "UNKNOWN".
    """
    answer = query_rag(prompt, n_context=3)
    if not answer or "UNKNOWN" in answer:
        return None
    
    match = re.search(r'[\w\-\_\.]+\.pdf', answer)
    return match.group(0) if match else None

def parse_discovery_response(text_response):
    """
    Parse Khoj response with markdown formatting like:
    1. **ID/Name**: XXX
       **Affected Function**: YYY
       **Root Cause**: ZZZ
    """
    vulns = []
    
    # Split by numbered items (1. 2. 3. etc.)
    # Use lookahead to keep the number
    items = re.split(r'\n(?=\d+\.\s+\*{0,2}ID/Name)', text_response)
    
    for item in items:
        # Skip if doesn't contain ID/Name
        if 'ID/Name' not in item:
            continue
        
        v_obj = {}
        
        # Extract ID/Name (handles both **ID/Name** and ID/Name)
        # Pattern: **ID/Name**: XXX or ID/Name: XXX
        id_match = re.search(r'\*{0,2}ID/Name\*{0,2}:\s*(.+?)(?=\n|\*{0,2}Affected Function|\Z)', item, re.DOTALL)
        if id_match:
            v_obj["id_name"] = id_match.group(1).strip()
        else:
            continue  # Skip if no ID/Name found
        
        # Extract Affected Function
        func_match = re.search(r'\*{0,2}Affected Function\*{0,2}:\s*(.+?)(?=\n|\*{0,2}Root Cause|\Z)', item, re.DOTALL)
        if func_match:
            v_obj["affected_function"] = func_match.group(1).strip()
        else:
            v_obj["affected_function"] = "Unknown"
        
        # Extract Root Cause
        cause_match = re.search(r'\*{0,2}Root Cause\*{0,2}:\s*(.+?)(?=\n\d+\.|\Z)', item, re.DOTALL)
        if cause_match:
            v_obj["root_cause"] = cause_match.group(1).strip()
        else:
            v_obj["root_cause"] = "Not specified"
        
        vulns.append(v_obj)
    
    return vulns

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 phase1_discovery.py <path_to_sol_file>")
        sys.exit(1)
    
    sol_file = sys.argv[1]
    
    if not os.path.exists(sol_file):
        print(f"{Colors.RED}❌ File not found: {sol_file}{Colors.END}")
        sys.exit(1)
    
    with open(sol_file, 'r', encoding='utf-8') as f:
        code_content = f.read()
    
    # Step 1: Extract Code Context
    features = extract_features_from_code(code_content)
    print(f"📄 Code Context: Contract [{features['contract_name']}], Functions {features['functions']}")
    
    # Step 2: Phase 1 - Identify PDF Report
    pdf_file = identify_audit_report(features)
    if not pdf_file:
        print(f"{Colors.RED}❌ Report not found via Khoj.{Colors.END}")
        sys.exit(1)
    print(f"{Colors.GREEN}✅ Identified Report: {pdf_file}{Colors.END}")
    
    # Delay before next request to avoid rate limit
    print(f"\n⏳ Waiting 15 seconds before Phase 2 (Rate limit protection)...")
    time.sleep(15)
    
    # Step 3: Phase 2 - Discovery (List vulnerabilities)
    print(f"\n{Colors.YELLOW}🔍 Phase 2: Discovery (List vulnerabilities)...{Colors.END}")
    discovery_prompt = PROMPT_DISCOVERY_TEMPLATE.format(filename=pdf_file)
    discovery_res = query_rag(discovery_prompt)
    
    if not discovery_res:
        print("❌ Discovery Phase returned empty.")
        sys.exit(1)
    
    # Debug: Print raw response
    print(f"\n{Colors.BLUE}--- DEBUG: Raw Khoj Response ---{Colors.END}")
    print(discovery_res[:500])
    print(f"{Colors.BLUE}--- End Debug ---{Colors.END}\n")
    
    vuln_list = parse_discovery_response(discovery_res)
    print(f"📊 Found {len(vuln_list)} potential vulnerabilities.")
    
    # Prepare output with smart selection
    # Find the most likely vulnerability matching the contract functions
    most_likely_index = -1
    input_funcs_lower = [f.lower() for f in features['functions']]
    
    # Strategy 1: Exact function name match
    for idx, v in enumerate(vuln_list):
        affected_func = v.get("affected_function", "").lower()
        if any(f_in in affected_func for f_in in input_funcs_lower):
            most_likely_index = idx
            print(f"\n{Colors.GREEN}🎯 SMART MATCH: Vulnerability #{idx+1} matches target function!{Colors.END}")
            print(f"   Vulnerability: {v['id_name']}")
            print(f"   Function: {v['affected_function']}")
            break
    
    # Strategy 2: If no exact match, pick first High/Critical severity or first item
    if most_likely_index == -1:
        # Check for severity keywords
        for idx, v in enumerate(vuln_list):
            name_lower = v.get("id_name", "").lower()
            cause_lower = v.get("root_cause", "").lower()
            if any(severity in name_lower or severity in cause_lower 
                   for severity in ["critical", "high", "stuck funds", "loss of funds"]):
                most_likely_index = idx
                print(f"\n{Colors.YELLOW}⚠️  HIGH SEVERITY MATCH: Selected vulnerability #{idx+1}{Colors.END}")
                print(f"   Vulnerability: {v['id_name']}")
                break
        
        # Fallback to first vulnerability
        if most_likely_index == -1 and vuln_list:
            most_likely_index = 0
            print(f"\n{Colors.BLUE}ℹ️  DEFAULT SELECTION: Using first vulnerability #{most_likely_index+1}{Colors.END}")
            print(f"   Vulnerability: {vuln_list[0]['id_name']}")
    
    output_data = {
        "report_file": pdf_file,
        "contract_name": features["contract_name"],
        "most_likely_vulnerability_index": most_likely_index,
        "vulnerabilities": vuln_list
    }
    
    # Create output directory
    os.makedirs("./list", exist_ok=True)
    output_file = "./list/list_vul.json"
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n{Colors.GREEN}✅ SUCCESS! Saved to '{output_file}'{Colors.END}")
    print(f"{Colors.BLUE}📋 Summary ({len(vuln_list)} total vulnerabilities):{Colors.END}")
    for i, v in enumerate(vuln_list):
        prefix = "🎯 [SELECTED]" if i == most_likely_index else "  "
        print(f"{prefix} {i+1}. {v['id_name']}")
        print(f"     Function: {v['affected_function']}")
        print(f"     Cause: {v['root_cause'][:80]}...")

if __name__ == "__main__":
    main()