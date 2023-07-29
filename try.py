import os , subprocess, pickle, tqdm
import pandas as pd

def get_files_with_extensions(directory, extensions):
    files = []
    for filename in os.listdir(directory):
        if os.path.isfile(os.path.join(directory, filename)):
            _, ext = os.path.splitext(filename)
            if ext.lower() in extensions:
                files.append(os.path.join(directory, filename))
    return files

extensions = ['.exe_', '.dll_', '.sys_', '.elf_', '.raw32', '.raw64', '.cs_', '.aspx_', '.py_']
directory = r"C:\Users\HP\Documents\GitHub\capa\tests\data"

all_paths = get_files_with_extensions(directory, extensions)
print("Total number of files to be processed ", len(all_paths))

pickle_path = "./all_rules_entropy.pickle"
write_path = "./rules_entropy.txt"
pbar = tqdm.tqdm
entropy = {}

for file_path in pbar(all_paths):
    cmd = ["capa", file_path]

    with open(write_path, 'w') as file:
            file.write('')

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print("Error running capa on " + file_path + " : " + str(e))

    with open(write_path, "r") as f:
        for line in f.readlines():
            line.strip()
            entropy[line] = entropy.get(line, 0) + 1

    with open(pickle_path, 'wb') as pickle_file:
        pickle.dump(entropy, pickle_file)

with open(pickle_path, 'wb') as pickle_file:
    pickle.dump(entropy, pickle_file)

def save_dict_to_excel(data_dict, excel_file_path):
    # Convert the dictionary to a pandas DataFrame
    df = pd.DataFrame(data_dict.items())

    # Save the DataFrame to an Excel file
    df.to_excel(excel_file_path, index=False, header=["Rule", "Number of Matches"])

excel_file_path = "./entropy.xlsx"
save_dict_to_excel(entropy, excel_file_path)
