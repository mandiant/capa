import re
import json
import argparse

from datetime import datetime

class VMrayParser:

    def read_vmray_log(self):
        with open(self.filename, 'r') as f:
            lines = f.readlines()
        return lines

    def __init__(self, filename, output_filename):
        self.filename = filename
        self.output_filename = output_filename
        self.data = {}
        self.processes = []  
        self.current_process = None  
        self.threads = []  

    #Parse info section of VMray output
    def parse_info(self, lines):
        info_data = {}
        for line in lines:
            if line.startswith("# Analyzer Version:"):
                info_data["analyzer_version"] = int(line.split(":")[1].strip().replace(".", ""))
            elif line.startswith("# Analyzer Build Date:" ):
                info_data["analyzer_build_date"] = datetime.strptime(line.split(":",1)[1].strip(),"%b %d %Y %H:%M:%S").isoformat()
            elif line.startswith("# Log Creation Date:"):
                info_data["log_create_date"] = datetime.strptime(line.split(":",1)[1].strip(), "%d.%m.%Y %H:%M:%S.%f").isoformat()
        self.data["info"] = info_data

    #Parse process data 
    def parse_process(self, lines):

        process_data = {}
        

        for line in lines:

            #Match key:value format for the process section
            ####Maybe since the process section puts ints in quotations, we can filter by that? Thread section doesn't.
            
            matches = re.findall(r"\s+(.+?) = \"(.*?)\"", line) #old r"\s+(.+?) = (.*)"
            
            
            for match in matches:
                key = match[0]
                
                if match[1]:
                    value = match[1]
                elif match[2]:
                    value = match[2]

                process_data[key.strip()] = value.strip()
            

        self.processes.append(process_data)  # Append to the list of processes
    

    def parse_thread(self, lines):
        thread_data = {}
        thread_calls = []
        current_thread_id = None

        #Start parsing thread section for id, os_id, and api calls

        for line in lines:
            if line.startswith("\tid ="):
                    current_thread_id = int(line.split("=")[1].strip().strip('"'))
                    thread_data["id"] = current_thread_id

            elif line.startswith("\tos_tid ="):
                    thread_data["os_tid"] = line.split("=")[1].strip()

            elif current_thread_id is not None and line.startswith("\t["):
                #Check if line contains timestamp bracket 
            
            
                    thread_calls.append(line.strip())

                      # Append call_data to the list
                

        # Assign the call_data dictionary with the thread_calls list?
        thread_data["calls"] = thread_calls 
        
        # Append thread_data to the list of threads
        self.threads.append(thread_data) 
        return thread_data
        
    def write_json_file(self):
                
        self.data["process"] = self.processes  # Add the list of processes to the main dictionary
        self.data["threads"] = self.threads  # Add the list of threads to the main dictionary
        with open(self.output_filename, 'w') as file:
                    json.dump(self.data, file, indent=4)

    def convert(self):
        lines = self.read_vmray_log()
        self.parse_info(lines)

        self.current_process = None  # Set current_process to None at the start of convert
        current_section = None
        current_section_lines = []
        for line in lines:
            if line.startswith("Process:"):
                current_section = "process"
                # Parse the process data immediately
                self.parse_process(current_section_lines)  # Parse process data when encountering "Process"
                current_section_lines = [line]
            elif line.startswith("Thread:"):
                current_section = "thread"
                if current_section_lines:
                    self.parse_thread(current_section_lines)  # Parse thread when encountering "Thread"
                current_section_lines = [line]
            else:
                current_section_lines.append(line)

        if current_section_lines:
            if current_section == "process":
                self.parse_process(current_section_lines)
            elif current_section == "thread":
                self.parse_thread(current_section_lines)
        self.write_json_file()
        print(json.dumps(self.data, indent=4)) 

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert VMray log files to JSON.")
    parser.add_argument("input_file", help="The path to the VMray log file")
    parser.add_argument("-o", "--output_file", default="vmray_output.json", help="The path to the output JSON file")

    args = parser.parse_args()

    vmray_parser = VMrayParser(args.input_file, args.output_file)
    vmray_parser.convert()
    print(f"Your VMray flog file '{args.input_file}' was converted to JSON and saved to '{args.output_file}'.")