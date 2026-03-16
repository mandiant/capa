# mapa html-map demo

*2026-03-16T17:05:38Z by Showboat 0.6.1*
<!-- showboat-id: 1cf46a16-c3d7-459d-8593-c23080cb12f6 -->

Generate a standalone HTML report for a sample binary and summarize the report contents.

```bash
tmp=$(mktemp /tmp/mapa-html-map-XXXXXX.html)
PYTHONWARNINGS=ignore ./.venv/bin/python -m mapa binaries/01/16/mpbindump.exe --output html-map --quiet > "$tmp"
PYTHONWARNINGS=ignore /usr/bin/python3 - "$tmp" <<"PY"
import json
import re
import sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
match = re.search(r"<script type=\"application/json\" id=\"mapa-data\">(.*?)</script>", text, re.S)
data = json.loads(match.group(1))
print("doctype", text.splitlines()[0])
print("functions", len(data["functions"]))
print("tags", len(data["tags"]))
print("strings", len(data["strings"]))
PY
rm "$tmp"
```

```output
doctype <!doctype html>
functions 1406
tags 12
strings 81
```

To open the report directly in your browser, use `python -m mapa <sample> --output html-map --open`.
