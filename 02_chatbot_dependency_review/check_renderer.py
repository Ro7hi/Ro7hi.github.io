"""Run ordinary, non-clinical message-rendering checks on the local Jinja installation."""
import json
from importlib.metadata import version
from pathlib import Path
import sys


def run():
    from jinja2 import Environment
    installed = version("Jinja2")
    template = Environment(autoescape=True).from_string("<p>{{ message }}</p>")
    cases = [
        ("plain text", "Hello team", "<p>Hello team</p>"),
        ("ampersand", "Tea & books", "<p>Tea &amp; books</p>"),
        ("literal brackets", "Read <draft>", "<p>Read &lt;draft&gt;</p>"),
    ]
    checks = []
    for label, text, expected in cases:
        observed = template.render(message=text)
        checks.append({"case": label, "expected": expected, "observed": observed, "passed": observed == expected})
    return {"scope": "Local reference renderer with a developer-authored template",
            "package": "Jinja2", "observed_version": installed, "checks": checks}


if __name__ == "__main__":
    try:
        result = run()
    except ImportError:
        sys.exit("Optional check requires Jinja2. See evidence/renderer.json for the recorded run.")
    print(json.dumps(result, indent=2))
    sys.exit(0 if all(item["passed"] for item in result["checks"]) else 1)
