import os
import sys

def scan_vulnerabilities(folder):ter
    vulnerabilities = {
        'anti_clickjacking': [],
        'x_content_type_options_header': [],
        'brute_force': []
    }

    for root, _, files in os.walk(folder):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith('.php'):
                with open(file_path, 'r') as f:
                    content = f.read()
                    #anti-clickjacking
                    if 'X-Frame-Options' not in content:
                        vulnerabilities['anti_clickjacking'].append(file_path)
                    #X-Content-Type-Options
                    if 'X-Content-Type-Options' not in content:
                        vulnerabilities['x_content_type_options_header'].append(file_path)
                    #brute force
                    if '<form' in content and 'password' in content:
                        if '$_SESSION[\'attempts\']' not in content or 'MAX_LOGIN_ATTEMPTS' not in content:
                            vulnerabilities['brute_force'].append(file_path)
    
    return vulnerabilities

#add anti-clickjacking
def resolve_anti_clickjacking(folder):
    for root, _, files in os.walk(folder):
        for file in files:
            if file.endswith('.php'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    content = f.read()

                if 'X-Frame-Options' not in content:
                    # Add the X-Frame-Options header
                    anti_clickjacking_header = """<?php
header("X-Frame-Options: DENY");
?>
"""
                    updated_content = anti_clickjacking_header + content
                    
                    with open(file_path, 'w') as f:
                        f.write(updated_content)
                    print(f"Anti-clickjacking header added to {file_path}")

#add X-Content-Type-Options
def resolve_x_content_type_options_header(folder):
    for root, _, files in os.walk(folder):
        for file in files:
            if file.endswith('.php'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    content = f.read()

                if 'X-Content-Type-Options' not in content:
                    # Add the X-Content-Type-Options header
                    x_content_type_options_header = """<?php
header("X-Content-Type-Options: nosniff");
?>
"""
                    updated_content = x_content_type_options_header + content
                    
                    with open(file_path, 'w') as f:
                        f.write(updated_content)
                    print(f"X-Content-Type-Options header added to {file_path}")

#add brute force
def resolve_brute_force(folder):
    login_file = os.path.join(folder, 'login.php')
    if os.path.exists(login_file):
        with open(login_file, 'r') as file:
            content = file.read()
        
        #brute force
        brute_force_protection = """<?php
session_start();

// Constants
define('MAX_LOGIN_ATTEMPTS', 5);  // Allow 5 attempts
define('LOCKOUT_TIME', 15 * 60); // 15 minutes lockout

$users_file = 'users.txt';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Input validation
    if (empty($username) || empty($password)) {
        echo "Username and password are required.";
        exit;
    }

    // Initialize session variables if not set
    if (!isset($_SESSION['attempts'])) {
        $_SESSION['attempts'] = [];
    }

    if (!isset($_SESSION['attempts'][$username])) {
        $_SESSION['attempts'][$username] = ['attempts' => 0, 'last_attempt' => 0];
    }

    // Check if user is locked out
    $attempt_data = $_SESSION['attempts'][$username];
    if ($attempt_data['attempts'] >= MAX_LOGIN_ATTEMPTS && time() - $attempt_data['last_attempt'] < LOCKOUT_TIME) {
        echo "Account locked due to too many failed login attempts. Please try again later.";
        exit;
    }

    // Load users
    $users = file_exists($users_file) ? file($users_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];

    // Check credentials
    $login_successful = false;
    foreach ($users as $user) {
        list($stored_username, $stored_password) = explode(':', $user);
        if ($stored_username === $username && $stored_password === $password) {
            $login_successful = true;
            break;
        }
    }

    if ($login_successful) {
        // Reset login attempts
        $_SESSION['attempts'][$username] = ['attempts' => 0, 'last_attempt' => time()];
        echo "Login successful!";
    } else {
        // Increment login attempts
        $attempt_data['attempts']++;
        $attempt_data['last_attempt'] = time();
        $_SESSION['attempts'][$username] = $attempt_data;
        echo "Invalid username or password.";
    }
}
?>
"""
        updated_content = brute_force_protection + content
        
        with open(login_file, 'w') as file:
            file.write(updated_content)
        
        print(f"Brute force protection added to {login_file}")

def resolve_vulnerability(option, folder):
    if option == '1':
        resolve_anti_clickjacking(folder)
    elif option == '2':
        resolve_x_content_type_options_header(folder)
    elif option == '3':
        resolve_brute_force(folder)

def display_menu():
    print("\nVulnerability Scanner and Resolver")
    print("1. Resolve Anti-Clickjacking Header")
    print("2. Resolve X-Content-Type-Options Header")
    print("3. Resolve Brute Force")
    print("4. Exit")

def main():
    if len(sys.argv) != 2:
        print("Usage: python vulnerability_resolver.py <directory>")
        sys.exit(1)

    folder = sys.argv[1]
    
    if not os.path.isdir(folder):
        print(f"The directory {folder} does not exist.")
        sys.exit(1)

    vulnerabilities = scan_vulnerabilities(folder)
    print("Vulnerabilities found:")
    for key, value in vulnerabilities.items():
        print(f"{key}: {value}")

    while True:
        display_menu()
        choice = input("Enter your choice: ")
        if choice == '4':
            break
        resolve_vulnerability(choice, folder)

if __name__ == '__main__':
    main()
