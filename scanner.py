import re
import sys
import os

# Define regex patterns for different vulnerabilities
vulnerabilities = {
    'Plaintext Password Storage': r'\$password\s*=\s*".*"',
    'Missing Input Sanitization': r'\$_POST\[\s*["\'].*["\']\s*\]',
    'Improper Error Handling': r'(error_log|var_dump|print_r|die|exit)'
}

def check_vulnerabilities(file_content):
    results = {}
    for vuln_name, pattern in vulnerabilities.items():
        matches = re.findall(pattern, file_content)
        if matches:
            results[vuln_name] = matches
    return results

def scan_directory(directory):
    all_results = {}
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.php'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r') as f:
                        file_content = f.read()
                except Exception as e:
                    print(f"Error reading file {file_path}: {e}")
                    continue

                results = check_vulnerabilities(file_content)
                if results:
                    all_results[file_path] = results
    return all_results

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 check_vulnerabilities.py <path_to_directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    
    if not os.path.isdir(directory):
        print(f"Error: '{directory}' is not a directory or does not exist.")
        sys.exit(1)

    all_results = scan_directory(directory)

    if all_results:
        for file_path, results in all_results.items():
            print(f"\nVulnerabilities found in {file_path}:")
            for vuln_name, matches in results.items():
                print(f"  {vuln_name}:")
                for match in matches:
                    print(f"    - {match}")
    else:
        print("No vulnerabilities found.")

if __name__ == "__main__":
    main()

