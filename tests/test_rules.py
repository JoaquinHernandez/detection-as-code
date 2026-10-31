cat << 'EOF' > tests/test_rules.py
import json
import os
import yaml
import pytest
from validate_detections import validate_rule_metadata

RULE_PATH = "rules/persistence_cron_modification.yml"

@pytest.fixture
def rule_data():
    with open(RULE_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def test_rule_metadata_integrity():
    data = validate_rule_metadata(RULE_PATH)
    assert data["status"] == "production"
    assert data["level"] in ["low", "medium", "high", "critical"]
    assert "attack.persistence" in data["tags"]

def test_synthetic_attack_detection(rule_data):
    with open("tests/telemetry/attack_cron_telemetry.json", "r") as f:
        event = json.load(f)

    # Validate image filter matches
    image_matches = any(event["Image"].endswith(img.replace("'", "")) for img in rule_data["detection"]["selection_exec"]["Image|endswith"])
    cmd_matches = any(term in event["CommandLine"] for term in rule_data["detection"]["selection_exec"]["CommandLine|contains"])
    
    # Assert attack is flagged
    assert image_matches and cmd_matches, "Adversary execution was not matched by detection selection logic!"

def test_synthetic_benign_suppression(rule_data):
    with open("tests/telemetry/benign_telemetry.json", "r") as f:
        event = json.load(f)

    # Check suppression filter
    filter_applied = any(term in event["CommandLine"] for term in rule_data["detection"]["filter_ansible"]["CommandLine|contains"])
    
    # Assert benign activity is filtered
    assert filter_applied, "False-positive filter failed to suppress benign automation account!"
EOF
