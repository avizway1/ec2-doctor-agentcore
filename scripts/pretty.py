"""Turn the agent's raw event stream into readable text.

Usage: agentcore invoke --runtime agent --payload '{"prompt":"..."}' | python3 scripts/pretty.py
"""
import json
import sys

for line in sys.stdin:
    if not line.startswith("data: "):
        continue
    try:
        event = json.loads(line[6:]).get("event", {})
    except (ValueError, AttributeError):
        continue
    tool = event.get("contentBlockStart", {}).get("start", {}).get("toolUse")
    if tool:
        print(f"\n[tool] {tool['name']}", flush=True)
    text = event.get("contentBlockDelta", {}).get("delta", {}).get("text")
    if text:
        print(text, end="", flush=True)
    if "messageStop" in event:
        print(flush=True)
