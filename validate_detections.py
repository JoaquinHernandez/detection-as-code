cat << 'EOF' > validate_detections.py
import glob
import os
import subprocess
import sys
import yaml

MANDATORY_FIELDS = ["id", "title", "status", "description", "tags", "logsource", "detection", "level"]

def validate_rule_metadata(filepath: str) -> dict:
    with open(filepath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    for field in MANDATORY_FIELDS:
        if field not in data:
            raise ValueError(f"Rule {filepath} is missing mandatory field: {field}")

    # Validate MITRE ATT&CK formatting in tags
    attack_tags = [t for t in data["tags"] if t.startswith("attack.t")]
    if not attack_tags:
        raise ValueError(f"Rule {filepath} must include at least one valid MITRE technique tag (e.g., attack.t1053.003)")

    return data

def transpile_rule(filepath: str, target: str) -> str:
    cmd = ["sigma", "convert", "-t", target, filepath]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Sigma conversion to {target} failed:\n{result.stderr}")
    return result.stdout.strip()

def main():
    rule_files = glob.glob("rules/*.yml")
    if not rule_files:
        print("[-] No Sigma rules found in rules/")
        sys.exit(1)

    print(f"[*] Found {len(rule_files)} Sigma detection rule(s). Commencing validation pipeline...\n")
    all_passed = True

    for rf in rule_files:
        rule_name = os.path.basename(rf)
        print(f"=== Validating: {rule_name} ===")
        try:
            validate_rule_metadata(rf)
            print("  [+] Schema Validation: PASSED")

            # Transpile to Splunk
            splunk_query = transpile_rule(rf, "splunk")
            print("  [+] Transpile Splunk SPL: SUCCESS")
            print(f"      Query: {splunk_query}")

            # Transpile to Elasticsearch Query DSL
            elastic_query = transpile_rule(rf, "elasticsearch")
            print("  [+] Transpile Elastic DSL: SUCCESS")

        except Exception as e:
            print(f"  [-] Error: {e}")
            all_passed = False

    if not all_passed:
        print("\n[-] Pipeline Validation Failed!")
        sys.exit(1)

    print("\n[+] All Detection-as-Code validations passed successfully.")

if __name__ == "__main__":
    main()
EOF
