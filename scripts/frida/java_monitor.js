/**
 * Capa Frida Java API Monitor
 * This script monitors Java API calls and outputs data in JSON format
 * 
 * How to use it:
 * frida -U -f com.example.app -l java_monitor.js --no-pause > output.log
 */

// TODO: Add Thread.backtrace to get position to ensure api call happens on target place
// TODO: Auto create script with api list
// TODO: Selective api list get from rules

Java.perform(function() {
    console.log("[+] Capa Frida Java Monitor started");
    
    function JsonFormat(apiName, args, returnValue) {
        var logEntry = {
            "type": "api",
            "name": apiName,
            "args": args || {},
            "return_value": returnValue,
            "timestamp": Date.now(),
            "thread_id": Process.getCurrentThreadId(),
            "method": "Unknown"    
        };
        console.log("FRIDA_JSON:" + JSON.stringify(logEntry));
    }
    
    // Monitor java.io.File
    try {
        var File = Java.use("java.io.File");
        
        File.$init.overload('java.lang.String').implementation = function(path) {
            JsonFormat("java.io.File.<init>", {"path": path});
            return this.$init(path);
        };
        
        File.delete.implementation = function() {
            var path = this.getAbsolutePath();
            var result = this.delete();
            JsonFormat("java.io.File.delete", {"path": path}, result);
            return result;
        };
        
        console.log("[+] File operations hooked");
        
    } catch(e) {
        console.log("[ERROR] File hook failed: " + e);
    }

    // Monitor FileInputStream
    try {
        var FileInputStream = Java.use("java.io.FileInputStream");
        
        FileInputStream.$init.overload('java.io.File').implementation = function(file) {
            var path = file.getAbsolutePath();
            JsonFormat("java.io.FileInputStream.<init>", {"path": path});
            return this.$init(file);
        };
        
        FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
            JsonFormat("java.io.FileInputStream.<init>", {"path": path});
            return this.$init(path);
        };
        
        console.log("[+] FileInputStream hooked");
        
    } catch(e) {
        console.log("[ERROR] FileInputStream hook failed: " + e);
    }

    // Monitor FileOutputStream
    try {
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        
        FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
            JsonFormat("java.io.FileOutputStream.<init>", {"path": path});
            return this.$init(path);
        };
        
        FileOutputStream.write.overload('[B').implementation = function(bytes) {
            JsonFormat("java.io.FileOutputStream.write", {"bytes": bytes.length});
            return this.write(bytes);
        };
        
        console.log("[+] FileOutputStream hooked");
        
    } catch(e) {
        console.log("[ERROR] FileOutputStream hook failed: " + e);
    }

});