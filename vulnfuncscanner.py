import sys
from termcolor import colored
import yaml

def scan_file(file_path, file_type):
    try:
        with open("vulnerable_functions.yaml", 'r') as f:
            vulnerable_functions = yaml.safe_load(f)
    except FileNotFoundError:
        print(f'vulnerable_functions.yaml not found')
        return
    if file_type not in vulnerable_functions:
        print(f'File type not supported: {file_type}')
        return
    try:
        with open(file_path, 'r') as file:
            data = file.read().lower()
            lines = data.split("\n")
    except FileNotFoundError:
        print(f'File not found: {file_path}')
        return
    functions = vulnerable_functions[file_type]
    functions = [f.lower() for f in functions]
    found_vulnerable_functions = []
    for function in functions:
        for i, line in enumerate(lines):
            if function in line:
                found_vulnerable_functions.append((function, i+1))
    if found_vulnerable_functions:
        print(colored(f'Vulnerable functions found in {file_path}', 'red'))
        for function, line_number in found_vulnerable_functions:
            print(f'{function} found at line {line_number}')
    else:
        print(colored(f'No vulnerable functions found in {file_path}', 'green'))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Please provide the file path and file extension as arguments')
        print('For example to scan a php file: python3 vulnfuncscanner.py file.php php')
        sys.exit(1)
    file_path = sys.argv[1]
    file_ext = file_path.split('.')[-1]
    scan_file(file_path, file_ext)
