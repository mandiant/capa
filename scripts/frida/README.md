# Frida Dynamic Analysis

## Usage

### Step 1: Capture API calls with Frida
```bash
# Attach Frida to the target app and log Java API calls
frida -U -f com.example.app -l java_monitor.js --no-pause > frida_output.log
```

### Step 2: Convert logs to capa format
```bash
# Convert raw Frida logs to capa-compatible JSON
python log_converter.py frida_output.log com.example.app output.json
```

### Step 3: Analyze with capa
```bash
# Run capa on the converted log file
capa output.json
```

## Architecture
Android App → Frida Script → Log Converter → FridaExtractor → Capa Engine

- **java_monitor.js**: Frida script for Java API monitoring
- **log_converter.py**: Converts raw Frida logs to structured JSON
- **extractor.py**: Contains `FridaExtractor` class implementing capa’s dynamic analysis interface
- **models.py**: Defines data models for API calls and process info
