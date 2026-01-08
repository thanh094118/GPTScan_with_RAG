import requests
import re
import json
import os
import time
from pathlib import Path
from requests.exceptions import Timeout, RequestException

# --- CẤU HÌNH ---
BASE_URL = "http://localhost:42110"
CHAT_ENDPOINT = f"{BASE_URL}/api/chat"
GEMINI_API_KEY = "YOUR_GEMINI_API_KEY_HERE"
EXTRACTION_TIMEOUT = 1200  # 20 minutes

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

# --- PROMPT ---
PROMPT_EXTRACTION_TEMPLATE = """
I want to configure a GPTScan Rule for the vulnerability: "{vuln_name}".
Context: This vulnerability is found in the audit report "{filename}".

Please analyze the technical details, code snippets, and recommendations provided for this specific finding in the PDF. Focus heavily on the ROOT CAUSE (the specific variable or logic causing the issue).

Extract the following information to help me configure the detection logic.

*** CRITICAL TECHNICAL CONSTRAINTS ***
My system ONLY supports post-processing logic using the following Python functions. You must map the PDF's recommendation to the most appropriate function below:

1. MISSING CHECK GROUP:
   - `has_eq_check(VarA, VarB)`: Use if the report recommends checking equality (e.g., `require(msg.sender == owner)`).
   - `has_min_check(VarA)`: Use if the report recommends a limit/threshold check (e.g., slippage, minAmount, `val > 0`).
   - `has_check(VarA)`: General check. Use if a variable needs any validation/sanitization.

2. EXISTENCE & DEAD CODE GROUP:
   - `in_code(Snippet)`: Use if the vulnerability is the *mere presence* of specific code that should not be there (e.g., Dead Code, specific hardcoded addresses, debug prints).
   - `check_require(CodeSnippet)`: Use to check if a specific logic is wrapped in a `require/if` statement.

3. ORDER & DEPENDENCY GROUP:
   - `order_first_b(StatementsA, StatementsB)`: Use if the report states code B must execute before code A (e.g., CEI pattern).
   - `find_data_dependency(VarDest, VarSource)`: Use if a critical variable is calculated using an unsafe source (e.g., spot price manipulation, incorrect key usage).

4. SPECIAL GROUP:
   - `emit_at_end(EventName)`: Use if an event must be emitted at the end.
   - `first_deposit_check(VarB, VarC, VarA)`: Specific to ERC4626 inflation attacks.

*** REQUIRED OUTPUT FORMAT ***

Please provide the answer in the following structure:

1. Context & Static Filter:
   - What is the exact name of the **Target Function** where the bug exists?
   - List unique **Code Keywords** (variables, function calls) found inside this function that I can use as a static filter (Regex).

2. Analysis for LLM Prompt:
   - To detect this bug, what specific variables or statements do I need to ask the LLM to identify? (Focus on the ROOT CAUSE variable. Example: If the bug is "division by zero due to flips=0", identify "flips", NOT "amount").
   - What are the **Actual Variable Names** used in the PDF's code snippet?

3. Logic Selection:
   - Which SINGLE Python function from the "Constraints" list above is best for this bug?
   - **Reasoning:** Explain why you chose this function based on the PDF's recommendation.

4. Remediation:
   - Extract a concise one-sentence recommendation from the report on how to fix this issue.
"""

def query_rag(prompt, n_context=100, custom_timeout=None, max_retries=3):
    effective_timeout = custom_timeout if custom_timeout else EXTRACTION_TIMEOUT
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

def clean_json_string(json_str):
    if "```json" in json_str:
        json_str = json_str.split("```json")[1].split("```")[0]
    elif "```" in json_str:
        json_str = json_str.split("```")[1].split("```")[0]
    return json_str.strip()

def parse_extraction_to_json(text_response):
    """
    Parse Khoj response in various Markdown formats:
    Format 1: ### 1. Context & Static Filter:
    Format 2: 1. **Context & Static Filter**:
    Format 3: **1. Context & Static Filter**:
    """
    # First try JSON format
    try:
        clean_text = clean_json_string(text_response)
        data = json.loads(clean_text)
        if "logic_selection" in data:
            logic = data["logic_selection"]
            if "function_name" in logic and "function_call" not in logic:
                logic["function_call"] = logic.pop("function_name")
        return data
    except (json.JSONDecodeError, TypeError):
        pass

    result = {
        "context_static_filter": {},
        "analysis_for_llm_prompt": {},
        "logic_selection": {},
        "remediation": ""
    }

    try:
        # Section 1: Context & Static Filter
        # Patterns: "### 1." or "1. **" or "**1."
        section1 = re.search(
            r'(?:###\s*)?(?:\*{0,2})?\s*1\.\s*\*{0,2}\s*Context\s*&\s*Static\s*Filter\*{0,2}\s*:?\s*(.*?)(?=(?:###\s*)?(?:\*{0,2})?\s*2\.\s*\*{0,2}\s*Analysis|$)',
            text_response, 
            re.DOTALL | re.IGNORECASE
        )
        if section1:
            content = section1.group(1)
            
            # Extract Target Function
            target_func = re.search(r'[\*\-]\s*\*{0,2}Target Function\*{0,2}\s*:?\s*[`]?([^`\n]+)[`]?', content)
            if target_func:
                result["context_static_filter"]["target_function"] = target_func.group(1).strip()
            
            # Extract Code Keywords
            keywords_match = re.search(r'[\*\-]\s*\*{0,2}Code Keywords\*{0,2}\s*:?\s*(.+?)(?=\n\s*[\*\-]|\n\s*(?:###\s*)?(?:\*{0,2})?\s*\d+\.|\Z)', content, re.DOTALL)
            if keywords_match:
                keywords_raw = keywords_match.group(1).strip()
                # Split by comma and clean
                keywords = [k.strip(' `"\'') for k in keywords_raw.split(',') if k.strip()]
                result["context_static_filter"]["code_keywords"] = keywords

        # Section 2: Analysis for LLM Prompt
        section2 = re.search(
            r'(?:###\s*)?(?:\*{0,2})?\s*2\.\s*\*{0,2}\s*Analysis\s*for\s*LLM\s*Prompt\*{0,2}\s*:?\s*(.*?)(?=(?:###\s*)?(?:\*{0,2})?\s*3\.\s*\*{0,2}\s*Logic|$)',
            text_response,
            re.DOTALL | re.IGNORECASE
        )
        if section2:
            content = section2.group(1)
            result["analysis_for_llm_prompt"]["raw_content"] = content.strip()
            
            # Extract Variables/Statements to Identify
            vars_identify = re.search(r'[\*\-]\s*\*{0,2}Variables?[/\s]*Statements?\s*to\s*Identify\*{0,2}\s*:?\s*(.+?)(?=\n\s*[\*\-]|\n\s*(?:###\s*)?(?:\*{0,2})?\s*\d+\.|\Z)', content, re.DOTALL)
            if vars_identify:
                result["analysis_for_llm_prompt"]["variables_to_identify"] = vars_identify.group(1).strip()
            
            # Extract Actual Variable Names
            var_names = re.search(r'[\*\-]\s*\*{0,2}Actual\s*Variable\s*Names\*{0,2}\s*:?\s*(.+?)(?=\n\s*[\*\-]|\n\s*(?:###\s*)?(?:\*{0,2})?\s*\d+\.|\Z)', content, re.DOTALL)
            if var_names:
                vars_raw = var_names.group(1).strip()
                # Clean and split
                vars_list = [v.strip(' `"\'') for v in vars_raw.split(',') if v.strip()]
                result["analysis_for_llm_prompt"]["actual_variable_names"] = vars_list

        # Section 3: Logic Selection
        section3 = re.search(
            r'(?:###\s*)?(?:\*{0,2})?\s*3\.\s*\*{0,2}\s*Logic\s*Selection\*{0,2}\s*:?\s*(.*?)(?=(?:###\s*)?(?:\*{0,2})?\s*4\.\s*\*{0,2}\s*Remediation|$)',
            text_response,
            re.DOTALL | re.IGNORECASE
        )
        if section3:
            content = section3.group(1)
            
            # Extract Python Function
            func_match = re.search(r'[\*\-]\s*\*{0,2}Python\s*Function\*{0,2}\s*:?\s*[`]?([a-z_]+\([^)]*\))[`]?', content, re.IGNORECASE)
            if func_match:
                result["logic_selection"]["function_call"] = func_match.group(1).strip()
            else:
                # Try simpler pattern
                func_simple = re.search(r'[`]([a-z_]+\([^)]*\))[`]', content)
                if func_simple:
                    result["logic_selection"]["function_call"] = func_simple.group(1).strip()
            
            # Extract Reasoning
            reasoning_match = re.search(r'[\*\-]\s*\*{0,2}Reasoning\*{0,2}\s*:?\s*(.+?)(?=\n\s*(?:###\s*)?(?:\*{0,2})?\s*\d+\.|\Z)', content, re.DOTALL)
            if reasoning_match:
                result["logic_selection"]["reasoning"] = reasoning_match.group(1).strip()

        # Section 4: Remediation
        section4 = re.search(
            r'(?:###\s*)?(?:\*{0,2})?\s*4\.\s*\*{0,2}\s*Remediation\*{0,2}\s*:?\s*(.*?)(?=\n\s*(?:###\s*)?(?:\*{0,2})?\s*\d+\.|\Z)',
            text_response,
            re.DOTALL | re.IGNORECASE
        )
        if section4:
            content = section4.group(1).strip()
            # Extract recommendation (may start with bullet or **)
            remediation_match = re.search(r'[\*\-]?\s*\*{0,2}Recommendation\*{0,2}\s*:?\s*(.+)', content, re.DOTALL)
            if remediation_match:
                result["remediation"] = remediation_match.group(1).strip()
            else:
                # No label, just take the content
                result["remediation"] = content.strip()

    except Exception as e:
        print(f"{Colors.RED}⚠️ Parsing Text Error: {e}{Colors.END}")
    
    return result

def sanitize_filename(name):
    """Convert vulnerability name to safe filename"""
    name = re.sub(r'[^\w\s-]', '', name)
    name = re.sub(r'[-\s]+', '_', name)
    return name[:50]  # Limit length

def main():
    list_file = "./list/list_vul.json"
    
    if not os.path.exists(list_file):
        print(f"{Colors.RED}❌ File not found: {list_file}{Colors.END}")
        print("Please run phase1_discovery.py first!")
        return
    
    with open(list_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    report_file = data.get("report_file")
    vulnerabilities = data.get("vulnerabilities", [])
    most_likely_idx = data.get("most_likely_vulnerability_index", 0)
    
    if not vulnerabilities:
        print(f"{Colors.RED}❌ No vulnerabilities found in {list_file}{Colors.END}")
        return
    
    print(f"{Colors.BLUE}📋 Found {len(vulnerabilities)} vulnerabilities in report{Colors.END}")
    print(f"📄 Report: {report_file}\n")
    
    # Create output directory
    os.makedirs("./vul", exist_ok=True)
    
    # Process MOST LIKELY vulnerability first
    print(f"{Colors.GREEN}{'='*70}")
    print(f"🎯 PROCESSING MOST LIKELY VULNERABILITY (Auto-selected)")
    print(f"{'='*70}{Colors.END}\n")
    
    vuln = vulnerabilities[most_likely_idx]
    process_vulnerability(vuln, most_likely_idx + 1, report_file, auto_mode=True)
    
    # Ask user about remaining vulnerabilities
    remaining = [v for i, v in enumerate(vulnerabilities) if i != most_likely_idx]
    
    if remaining:
        print(f"\n{Colors.YELLOW}{'='*70}")
        print(f"📋 REMAINING VULNERABILITIES ({len(remaining)} items)")
        print(f"{'='*70}{Colors.END}\n")
        
        for i, v in enumerate(remaining, 1):
            actual_idx = vulnerabilities.index(v) + 1
            print(f"{i}. {v['id_name']}")
            print(f"   Function: {v['affected_function']}")
            print(f"   Cause: {v['root_cause'][:80]}...\n")
        
        print(f"{Colors.BLUE}Options:{Colors.END}")
        print("  [A] Process ALL remaining vulnerabilities")
        print("  [N] Process specific vulnerability by number (e.g., 1, 2, 3)")
        print("  [S] Skip all remaining")
        
        choice = input(f"\n{Colors.BOLD}Your choice: {Colors.END}").strip().upper()
        
        if choice == 'A':
            # Process all remaining
            for i, v in enumerate(remaining):
                actual_idx = vulnerabilities.index(v) + 1
                print(f"\n{Colors.YELLOW}{'='*70}")
                print(f"🔍 Processing Remaining Vulnerability {i+1}/{len(remaining)}")
                print(f"{'='*70}{Colors.END}")
                process_vulnerability(v, actual_idx, report_file, auto_mode=False)
                
        elif choice.isdigit():
            # Process specific number
            num = int(choice) - 1
            if 0 <= num < len(remaining):
                v = remaining[num]
                actual_idx = vulnerabilities.index(v) + 1
                print(f"\n{Colors.YELLOW}{'='*70}")
                print(f"🔍 Processing Selected Vulnerability #{choice}")
                print(f"{'='*70}{Colors.END}")
                process_vulnerability(v, actual_idx, report_file, auto_mode=False)
            else:
                print(f"{Colors.RED}❌ Invalid number. Skipping.{Colors.END}")
                
        elif choice == 'S':
            print(f"{Colors.BLUE}ℹ️  Skipped remaining vulnerabilities.{Colors.END}")
        else:
            print(f"{Colors.RED}❌ Invalid choice. Skipping remaining.{Colors.END}")
    
    print(f"\n{Colors.GREEN}{'='*70}")
    print(f"🎉 COMPLETED!")
    print(f"{'='*70}{Colors.END}")
    print(f"📁 Check './vul/' folder for extraction results")

def process_vulnerability(vuln, vuln_number, report_file, auto_mode=False):
    """Process a single vulnerability"""
    vuln_name = vuln.get("id_name", "Unknown")
    
    mode_label = "AUTO-SELECTED" if auto_mode else "USER-REQUESTED"
    print(f"📌 [{mode_label}] Vulnerability #{vuln_number}: {vuln_name}")
    print(f"📌 Function: {vuln.get('affected_function')}")
    if not auto_mode:
        print(f"{Colors.BLUE}ℹ️  Waiting up to 20 minutes for response...{Colors.END}\n")
    
    # Create extraction prompt
    extraction_prompt = PROMPT_EXTRACTION_TEMPLATE.format(
        vuln_name=vuln_name,
        filename=report_file
    )
    
    # Query RAG
    extraction_res = query_rag(extraction_prompt, n_context=5, custom_timeout=EXTRACTION_TIMEOUT)
    
    if extraction_res:
        # Debug: Print full raw response
        print(f"\n{Colors.BLUE}{'='*60}")
        print(f"--- DEBUG: Full Raw Khoj Response ---")
        print(f"{'='*60}{Colors.END}")
        print(extraction_res)
        print(f"{Colors.BLUE}{'='*60}")
        print(f"--- End Debug ---")
        print(f"{'='*60}{Colors.END}\n")
        
        # Parse response
        parsed_rule = parse_extraction_to_json(extraction_res)
        
        # Construct final output
        final_output = {
            "source_info": {
                "report_file": report_file,
                "vulnerability_id_name": vuln.get("id_name"),
                "affected_function": vuln.get("affected_function"),
                "root_cause": vuln.get("root_cause"),
                "vulnerability_number": vuln_number,
                "model_used": "Server Default"
            },
            "raw_extraction_response": extraction_res,
            "gptscan_rule_config": parsed_rule
        }
        
        # Generate safe filename
        safe_name = sanitize_filename(vuln_name)
        output_filename = f"./vul/vul{vuln_number}_{safe_name}.json"
        
        with open(output_filename, 'w', encoding='utf-8') as f:
            json.dump(final_output, f, indent=2, ensure_ascii=False)
        
        print(f"{Colors.GREEN}✅ SUCCESS! Saved to '{output_filename}'{Colors.END}")
        
        # Rate limit delay
        if not auto_mode:
            wait_time = 30
            print(f"\n⏳ Waiting {wait_time} seconds (Rate limit protection)...")
            time.sleep(wait_time)
    else:
        print(f"{Colors.RED}❌ Extraction failed for: {vuln_name}{Colors.END}")

if __name__ == "__main__":
    main()