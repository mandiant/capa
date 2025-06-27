# Frida Dynamic Analysis

## Usage

**Environment Setup Guide:** [Frida Server + Rooted Emulator + Python Analysis Environment](https://docs.google.com/document/d/1fFf9Wu5y1q6OLojCpL4nPGvQ-Ne8ZpMeEBjdLe6Ef8c/edit?tab=t.t3e2ha7p49lk)

### Device Preparation

```bash
# Create output directory with full permissions
adb shell su -c "mkdir -p /data/local/tmp/frida_output"
adb shell su -c "chmod -R 777 /data/local/tmp/frida_output"

# Disable SELinux enforcement (resets on reboot)
adb shell su -c "setenforce 0"

# Start Frida server on device
adb shell su -c "/data/local/tmp/frida-server &"
```

### Step 0: Get all APIs from rules, and then get all hooks through template

```bash
# This python script does everything in step 0, run it  
python hook_builder.py test_rules hook_templates

# Push this hook script into the virtual machine
adb push extracted_apis/generated_api_hooks.js /data/local/tmp/frida_output/
```

### Step 1: Capture API calls with Frida

```bash
# Attach Frida to the target app and log Java API calls
frida -U -f com.example.app -l java_monitor.js
frida -U -f com.scottyab.rootbeer.sample -l java_monitor.js
```

**Notes:**
- File Permission Conflicts
Root Cause: Android apps create files with their UID ownership. App A cannot overwrite files created by App B.
- Solution 1: Delete this file before next analysis
- Solution 2: Change to a new filename in java_monitor.js:
  var filePath = "/data/local/tmp/frida_output/api_calls_02.jsonl"

### Step 2: Retrieve Analysis Data

```bash
# Check if file exits
adb shell su -c "ls -la /data/local/tmp/frida_output/"

# Method 1: Using cat with root permissions
adb shell su -c "cat /data/local/tmp/frida_output/api_calls.jsonl" > api_calls.jsonl

# OR Method 2: Using adb pull
adb pull /data/local/tmp/frida_output/api_calls.jsonl ./frida_reports/api_calls.jsonl
```

### Step 3: Analyze with capa
```bash
# Using custom Frida rules (for development/testing)
python capa/main.py -r scripts/frida/test_rules/ -d scripts/frida/frida_reports/api_calls.jsonl

# Using this after integrated
capa api_calls.jsonl
```

## Architecture
Android App → Frida Script → FridaExtractor → Capa Engine

- **java_monitor.js**: Frida script for Java API monitoring, output JSON compatible with capa.
- **extractor.py**: Contains `FridaExtractor` class implementing capa’s dynamic analysis interface
- **models.py**: Defines data models for API calls and process info
- **api_calls.jsonl**: Current JSON Lines output example
