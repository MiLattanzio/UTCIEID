#!/usr/bin/env python3
"""Prepare (never load) a UTCIEID-only AppArmor profile with Secret Service access."""
import argparse
import re
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("original", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
source = args.original.read_text()
profiles = re.findall(r'^profile "([^"]+)" ', source, re.MULTILINE)
if len(profiles) != 1 or not re.fullmatch(r'utcieid\.milattanzio_utcieid_\d+\.\d+\.\d+', profiles[0]) or not source.rstrip().endswith("}"):
    raise SystemExit("Unexpected profile: refusing to alter a different application's policy")
rules = (Path(__file__).resolve().parent.parent / "packaging/secret-service.apparmor.rules").read_text()
marker = "# UTCIEID optional Secret Service access"
if marker in source:
    raise SystemExit("Secret Service access already present")
source = source.rstrip()[:-1] + "\n" + marker + "\n" + rules + "\n}\n"
args.output.write_text(source)
print(args.output)
