import os
import json
import yaml
import re
import google.generativeai as genai
from pathlib import Path

# --- CẤU HÌNH ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "AIzaSyDl4GOtAb41jV3NgndjYcPYH7x7ZP4CvdQ")
genai.configure(api_key=GEMINI_API_KEY)

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

class GPTScanRuleGenerator:
    def __init__(self, model_name="gemini-2.5-flash"):
        self.model = genai.GenerativeModel(model_name)

    def _create_system_prompt(self, vuln_info: dict, rule_config: dict) -> str:
        """Tạo Prompt kỹ thuật để ép Gemini sinh YAML chuẩn GPTScan"""
        
        combined_input = {
            "vulnerability_info": vuln_info,
            "rule_config": rule_config
        }
        
        return f"""
You are a Senior Security Engineer and GPTScan Configuration Expert.
Your task is to convert the provided VULNERABILITY CONTEXT into a valid GPTScan YAML Rule file.

*** INPUT DATA ***
*** CRITICAL: TARGET LANGUAGE IS SOLIDITY ***
You MUST translate generic/Rust terms to Solidity:
- `instantiate()` -> `constructor`
- `info.sender` -> `msg.sender`
- `Addr` -> `address`
{json.dumps(combined_input, indent=2, ensure_ascii=False)}

*** STRICT YAML SYNTAX RULES (MUST FOLLOW) ***
1. **Property Field:** MUST be a list of strings with AT LEAST 2 ITEMS.
   - Bad: `property: ["description"]` (Causes IndexError crash)
   - Good: `property: ["Line 1 of description", "Line 2 of description"]`

2. **Name Field:** Use the vulnerability ID/Name as rule name (lowercase, no spaces)

3. **Activate:** Must be "yes" (with quotes)

4. **Functions Field:** Use the target_function from context_static_filter

5. **Function_Inside Field:** MUST be a LIST of strings (code keywords), NOT a regex pattern
   - Bad: `function_inside: "(var1|var2)"`
   - Good: `function_inside: ["var1", "var2", "var3"]`

6. **Static Block:**
   - `format`: Must be "json"
   - `prompt`: Write a clear prompt that asks LLM to extract variables into JSON format
   - `output_keys`: Must match the variable names you define (e.g., ["VariableA", "VariableB"])
   - **`rule` (CRITICAL):** Logic MUST be inside static block with structure:
     ```yaml
     rule:
       name: "function_name"
       args:
         - "VariableA"
         - "VariableB"
     ```

7. **Logic Functions (for static.rule.name):**
   Map the function_call from logic_selection to ONE of these:
   - `has_min_check` - For minimum/threshold checks
   - `has_eq_check` - For equality checks
   - `has_check` - For general validation checks
   - `in_code` - For existence/dead code checks
   - `find_data_dependency` - For data flow issues
   - `check_require` - For require statement checks
   - `order_first_b` - For execution order issues
   - `emit_at_end` - For event emission checks

8. **Output Block (REQUIRED):**
   Must have structure:
   ```yaml
   output:
     title: "CATEGORY: Vulnerability Name"
     description: "Detailed description of the issue"
     recommendation: "How to fix the issue"
   ```

*** CORRECT YAML STRUCTURE ***
```yaml
name: "incorrect_storage_key_handling"
property:
  - "Incorrect storage key handling in resolve_bet()"
  - "causes record overwrite and accounting issues"
activate: "yes"
functions:
  - "resolve_bet"
function_inside:
  - "state.bet_id"
  - "bet.bet_id"
  - "GAME"
static:
  format: "json"
  prompt: |
    Analyze the resolve_bet() function and extract:
    - VarDest: The destination variable for GAME storage key
    - VarSource: The source variable being used (should be bet.bet_id)
    Return as JSON: {{"VarDest": "...", "VarSource": "..."}}
  output_keys:
    - "VarDest"
    - "VarSource"
  rule:
    name: "find_data_dependency"
    args:
      - "VarDest"
      - "VarSource"
output:
  title: "Incorrect Storage Key Handling"
  description: "The resolve_bet() function uses state.bet_id instead of bet.bet_id as storage key"
  recommendation: "Use unique bet.bet_id for storing results in GAME storage"
```

*** GENERATION INSTRUCTIONS ***
- Extract target_function from context_static_filter → functions field
- Extract code_keywords from context_static_filter → function_inside as LIST
- Use actual_variable_names for static.output_keys and static.rule.args
- Extract function_call name (e.g., "find_data_dependency") → static.rule.name
- Use root_cause for output.description
- Use remediation for output.recommendation
- OUTPUT ONLY RAW YAML CONTENT. NO ```yaml MARKDOWN BLOCK. NO EXPLANATION.
"""

    def generate_yaml(self, vuln_info: dict, rule_config: dict) -> str:
        """Gửi request tới Gemini và nhận YAML"""
        prompt = self._create_system_prompt(vuln_info, rule_config)
        
        try:
            response = self.model.generate_content(prompt)
            yaml_content = response.text
            
            # Clean markdown blocks
            yaml_content = re.sub(r"^```yaml\s*", "", yaml_content, flags=re.MULTILINE)
            yaml_content = re.sub(r"^```\s*", "", yaml_content, flags=re.MULTILINE)
            yaml_content = re.sub(r"\s*```$", "", yaml_content, flags=re.MULTILINE)
            
            return yaml_content.strip()
        except Exception as e:
            print(f"{Colors.RED}❌ Error generating rule: {e}{Colors.END}")
            return None

    def validate_yaml(self, yaml_content: str) -> bool:
        """Validate YAML syntax"""
        try:
            parsed = yaml.safe_load(yaml_content)
            
            # Check critical fields
            if "property" not in parsed:
                print(f"{Colors.RED}❌ Missing 'property' field{Colors.END}")
                return False
            
            if not isinstance(parsed["property"], list) or len(parsed["property"]) < 2:
                print(f"{Colors.RED}❌ 'property' must be a list with at least 2 items{Colors.END}")
                return False
            
            required_fields = ["name", "activate", "functions", "static", "output"]
            for field in required_fields:
                if field not in parsed:
                    print(f"{Colors.RED}❌ Missing required field: {field}{Colors.END}")
                    return False
            
            # Validate static block has rule inside
            static_block = parsed["static"]
            if "rule" not in static_block:
                print(f"{Colors.RED}❌ Missing 'rule' inside 'static' block{Colors.END}")
                return False
            
            rule_block = static_block["rule"]
            if "name" not in rule_block or "args" not in rule_block:
                print(f"{Colors.RED}❌ 'static.rule' must contain 'name' and 'args'{Colors.END}")
                return False
            
            # Validate output block
            output_block = parsed["output"]
            if "title" not in output_block or "description" not in output_block:
                print(f"{Colors.RED}❌ 'output' block must contain title and description{Colors.END}")
                return False
            
            return True
        except yaml.YAMLError as e:
            print(f"{Colors.RED}❌ Invalid YAML syntax: {e}{Colors.END}")
            return False

    def save_rule(self, yaml_content: str, vuln_number: int, folder="generated_rules"):
        """Lưu rule thành file .yml"""
        try:
            parsed = yaml.safe_load(yaml_content)
            rule_name = parsed.get("name", "unknown_rule")
            safe_name = re.sub(r'[^\w\-]', '_', rule_name)
            filename = f"rule{vuln_number}_{safe_name}.yml"
            
            os.makedirs(folder, exist_ok=True)
            filepath = os.path.join(folder, filename)
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(yaml_content)
            
            print(f"{Colors.GREEN}✅ Rule saved: {filepath}{Colors.END}")
            return filepath
        except Exception as e:
            print(f"{Colors.RED}❌ Error saving rule: {e}{Colors.END}")
            return None

def main():
    print(f"{Colors.BLUE}{'='*70}")
    print(f"🔧 Phase 3: Generate GPTScan YAML Rules")
    print(f"{'='*70}{Colors.END}\n")
    
    # Read list_vul.json
    list_file = "./list/list_vul.json"
    if not os.path.exists(list_file):
        print(f"{Colors.RED}❌ File not found: {list_file}{Colors.END}")
        return
    
    with open(list_file, 'r', encoding='utf-8') as f:
        list_data = json.load(f)
    
    most_likely_idx = list_data.get("most_likely_vulnerability_index", 0)
    vuln_info = list_data["vulnerabilities"][most_likely_idx]
    vuln_number = most_likely_idx + 1
    
    print(f"📌 Selected Vulnerability #{vuln_number}")
    print(f"   Name: {vuln_info['id_name']}")
    print(f"   Function: {vuln_info['affected_function']}\n")
    
    # Find corresponding vul json file
    vul_files = list(Path("./vul").glob(f"vul{vuln_number}_*.json"))
    if not vul_files:
        print(f"{Colors.RED}❌ No extraction file found for vulnerability #{vuln_number}{Colors.END}")
        print("Please run phase2_extraction.py first!")
        return
    
    vul_file = vul_files[0]
    print(f"📄 Reading extraction file: {vul_file}\n")
    
    with open(vul_file, 'r', encoding='utf-8') as f:
        extraction_data = json.load(f)
    
    rule_config = extraction_data.get("gptscan_rule_config", {})
    
    # Generate YAML rule
    print(f"{Colors.YELLOW}⏳ Generating GPTScan YAML rule via Gemini...{Colors.END}\n")
    
    generator = GPTScanRuleGenerator()
    yaml_content = generator.generate_yaml(vuln_info, rule_config)
    
    if not yaml_content:
        print(f"{Colors.RED}❌ Failed to generate YAML{Colors.END}")
        return
    
    print(f"{Colors.BLUE}{'='*70}")
    print(f"--- GENERATED YAML RULE ---")
    print(f"{'='*70}{Colors.END}\n")
    print(yaml_content)
    print(f"\n{Colors.BLUE}{'='*70}{Colors.END}\n")
    
    # Validate YAML
    if generator.validate_yaml(yaml_content):
        print(f"{Colors.GREEN}✅ YAML validation passed{Colors.END}\n")
        generator.save_rule(yaml_content, vuln_number)
    else:
        print(f"{Colors.RED}❌ YAML validation failed. Rule NOT saved.{Colors.END}")
        print("Please check the output above for errors.")

if __name__ == "__main__":
    main()