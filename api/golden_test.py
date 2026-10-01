import argparse
import json
import logging
import sys

sys.path.insert(0, '/app')

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)

from agent import analyze_incidents_with_llm

parser = argparse.ArgumentParser(description="LLM verdict golden test")
parser.add_argument("--persist", action="store_true",
                    help="write verdicts to incident_analysis (default: no)")
args = parser.parse_args()

GOLDEN = json.load(open('/app/golden_set.json'))

results = analyze_incidents_with_llm(GOLDEN, persist=args.persist)

passed = 0
for case in GOLDEN:
    username = case['username']
    expected = case['expected']
    got = results.get(username, {}).get('ai_verdict', 'not_analyzed')
    status = 'PASS' if got == expected else 'FAIL'
    if got == expected:
        passed += 1
    print(f"{status}: {username} - expected={expected}, got={got}")

print()
print(f"Score: {passed}/{len(GOLDEN)} ({100 * passed // len(GOLDEN)}%)")
if passed < len(GOLDEN):
    print(f"FAILED: {len(GOLDEN) - passed} cases")
    sys.exit(1)
print("ALL PASS")