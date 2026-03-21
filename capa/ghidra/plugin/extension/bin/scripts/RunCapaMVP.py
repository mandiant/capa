import json
import logging
import os
import pathlib
import sys
import traceback

logger = logging.getLogger("capa_explorer")

def find_config():
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, "Library", "ghidra", "ghidra_12.0.3_PUBLIC", "capa_cache", "config.json"),
        os.path.join(home, ".ghidra", ".ghidra_12.0.3_PUBLIC", "capa_cache", "config.json"),
    ]
    env_dir = os.environ.get("GHIDRA_USER_SETTINGS_DIR")
    if env_dir:
        candidates.insert(0, os.path.join(env_dir, "capa_cache", "config.json"))

    for path in candidates:
        if os.path.isfile(path):
            with open(path, "r") as f:
                return json.load(f)
    raise RuntimeError("capa config.json not found")

def main():
    logging.basicConfig(level=logging.INFO)
    print("[RunCapaMVP] Starting capa analysis via PyGhidra...")

    # --- STEP 1: Initialize GhidraContext with the correct 3 arguments ---
    from capa.features.extractors.ghidra import context as ghidra_ctx_module
    from ghidra.program.flatapi import FlatProgramAPI  # pylint: disable=import-error

    flat_api = FlatProgramAPI(currentProgram, monitor)
    
    # Set the module-level singleton using set_context()
    ghidra_ctx_module.set_context(currentProgram, flat_api, monitor)

    # --- STEP 2: Load config ---
    config = find_config()
    rules_dir = config.get("rulesDirectory") or config.get("rules_directory")
    output_path = config.get("outputPath")

    print("[RunCapaMVP] Rules :", rules_dir)
    print("[RunCapaMVP] Output:", output_path)

    # --- STEP 3: Import Capa modules ---
    import capa.rules
    import capa.rules.cache
    import capa.ghidra.helpers
    import capa.capabilities.common
    import capa.render.json as capa_render_json
    import capa.features.extractors.ghidra.extractor

    # --- STEP 4: Run checks ---
    print("[RunCapaMVP] Detected file format:", currentProgram.getExecutableFormat())
    print("[RunCapaMVP] Detected language:", currentProgram.getLanguageID())
    
    if not capa.ghidra.helpers.is_supported_ghidra_version():
        raise RuntimeError("Unsupported Ghidra version")
    if not capa.ghidra.helpers.is_supported_file_type():
        raise RuntimeError("Unsupported file type")
    if not capa.ghidra.helpers.is_supported_arch_type():
        raise RuntimeError("Unsupported architecture")

    # --- STEP 5: Load rules and run analysis ---
    rules_path = pathlib.Path(rules_dir)
    print("[RunCapaMVP] Loading rules...")
    rules = capa.rules.get_rules([rules_path], cache_dir=None)
    meta = capa.ghidra.helpers.collect_metadata([rules_path])

    print("[RunCapaMVP] Creating GhidraFeatureExtractor...")
    extractor = capa.features.extractors.ghidra.extractor.GhidraFeatureExtractor()

    print("[RunCapaMVP] Running capability detection...")
    capabilities = capa.capabilities.common.find_capabilities(rules, extractor, False)

    meta.analysis.feature_counts = capabilities.feature_counts
    meta.analysis.library_functions = capabilities.library_functions

    print("[RunCapaMVP] Rendering results...")
    result_json = capa_render_json.render(meta, rules, capabilities.matches)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(result_json)

    print("[RunCapaMVP] Done — results written to:", output_path)
    
try:
    main()
except Exception as e:
    # Safe error printing
    sys.stderr.write(f"[RunCapaMVP] FATAL: {e}\n")
    traceback.print_exc()
    raise
