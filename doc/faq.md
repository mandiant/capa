# Frequently Asked Questions
## Why does capa trigger my Antivirus? Is the tool safe to use?
capa's purpose is to analyse the capabilities of a potentially malicious application or file. In order to do that, it needs to contain parts of the data it's designed to detect as a basis of comparison.
The release version of capa is packaged with embedded rules to detect common malware functionality. These rules contain similar features to malware and may cause alerts.
Additionally, Antivirus and Endpoint Detection and Response (EDR) products may alert on the way capa is packaged using PyInstaller.

## How can I ensure that capa is a benign program?
We recommedn you only download releases from this repository's Release page. Alternatively, you can build capa yourself or use the other Python installation methods. This project is open source so that everyone can be certain of the project's transparency.
For additinal peace of mind you can use VirusTotal to analyze unknown files against many Antivirus products, sandboxes, and other analysis tools (capa itself runs in VirusTotal).

### Understanding VirusTotal output
VirusTotal tests files against a large number of Antivirus engines and sandboxes. There's often little insight into Antivirus detections, but you can further inspect dynamic analysis results produced by sandboxes.
These details can be used to double-check alerts and understand detections.
