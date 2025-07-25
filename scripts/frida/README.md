# Frida Dynamic Analysis

This guide shows how to generate Frida hooks and analyze Android app API calls with capa.

## Prerequisites

- **Rooted Android emulator with Frida server running**  
[Frida Server + Rooted Emulator](https://docs.google.com/document/d/1WpPRcdtnPYdOn4n7Wl3aghbZUv2wmefiuaf2WDIR5Pw/edit?tab=t.0#heading=h.sqgvzr4xgg42)

- **Python virtual environment with capa installed**  
[capa install page](https://github.com/mandiant/capa/blob/master/doc/installation.md)

- **Target app installed on emulator**  
Example: RootBeer sample app from Google Play Store, or build from  Or [Rootbeer Github](https://github.com/scottyab/rootbeer?tab=readme-ov-file) (Rootbeer GitHub version is newer)

## Complete Workflow

### Step 1: Generate Frida Monitoring Script

```bash
# Activate your capa environment
source ~/capa-env/bin/activate 

# Navigate to the frida dir
cd scripts/frida/

# Generate monitoring script
python hook_builder.py

python hook_builder.py --apis frida_apis.json --script frida_monitor.js --output api_calls.jsonl
# Options:
# --apis: JSON filename containing APIs (default: frida_apis.json)
# --script: Output script filename (default: frida_monitor.js)  
# --output: JSONL output filename in emulator that you wanna create after monitoring (default: api_calls.jsonl)
```

### Step 2: Run Dynamic Analysis

```bash
# Launch Rootbeer app with Frida monitoring
frida -U -f com.scottyab.rootbeer.sample -l frida_scripts/frida_monitor.js

# For other apps, use their package name:
# frida -U -f com.example.app -l frida_scripts/frida_monitor.js

# Let the app run and perform the behaviors you want to analyze
# Type `exit` and Press `Ctrl+C` to stop monitoring
```

**Notes:**
- File Permission Conflicts
Root Cause: Android apps create files with their UID ownership. App A cannot overwrite files created by App B.
- Solution 1: Delete this file before next analysis
- Solution 2: Change to a new filename for {jsonl_filename} in frida_monitor.js, you can directly use --output command line:
var filePath = "/data/local/tmp/frida_outputs/{{jsonl_filename}}";

### Step 3: Retrieve Analysis Data

```bash
# (Check if file exits)
adb shell su -c "ls -la /data/local/tmp/frida_outputs/"

# Method 1: Using adb pull
# If you get "Permission denied", try:
adb root

adb pull /data/local/tmp/frida_outputs/api_calls.jsonl ./frida_outputs/api_calls.jsonl

# OR Method 2: Using cat with root permissions
adb shell su -c "cat /data/local/tmp/frida_outputs/api_calls.jsonl" > api_calls.jsonl
```

### Step 4: Analyze with capa
```bash
# Navigate back to capa root directory
cd ../../

# Using your custom Frida rules (for development/testing)
python capa/main.py -r scripts/frida/test_rules/ -d scripts/frida/frida_outputs/api_calls.jsonl

# Using this after integrated
capa api_calls.jsonl
```

### Folder Components

- **hook_builder.py**: Generates complete Frida script from API JSON
- **frida_api_models.py**: Pydantic models for API validation
- **/frida_apis/*.json**: Contains API JSON files
- **/frida_templates/**: Jinja2 templates for script generation
- **/frida_scripts/*.js**: Generated executable scripts (output)
