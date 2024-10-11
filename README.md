# Vuln-Scan-network-
This is a python script of a cybersecurity project focused on automating tasks for vulnerability scanning, integrating tools like Burp Suite, Nikto, and Trivy. The project demonstrates basic Python scripting and its applications in automating security tasks for efficiency in threat detection and analysis.





# Vulnerability Scanning Project

## Project Overview
This project contains a Python script designed to automate vulnerability scanning processes in a cybersecurity environment. The script is set up to run at system startup from the Zsh terminal on Kali Linux, integrating multiple vulnerability scanning tools, such as:

- **Burp Suite**: For web vulnerability testing and analysis.
- **Nikto**: A web server scanner for detecting vulnerabilities.
- **Trivy**: For container vulnerability and configuration scanning.

The primary goal of this project is to showcase how Python scripting can be used to automate routine security tasks, improving efficiency and allowing for early detection of potential threats.

## Features
- Automates the execution of vulnerability scanning tools.
- Starts automatically on system boot using the Zsh terminal.
- Easy-to-extend for additional cybersecurity tools and functionality.
- Lightweight and customizable for specific environments.

## Prerequisites
Ensure you have the following installed on your system:
- **Python 3.x**
- **Zsh** shell
- **Burp Suite**
- **Nikto**
- **Trivy**
- **Kali Linux**

## Installation

1. Clone this repository:
    ```bash
    git clone https://github.com/yourusername/vuln-scan-automation.git
    ```

2. Navigate to the project directory:
    ```bash
    cd vuln-scan-automation
    ```

3. Ensure you have all required tools installed:
    ```bash
    sudo apt-get install burpsuite nikto trivy
    ```

## How to Use
1. To enable the script at system startup, ensure the script is executable:
    ```bash
    chmod +x startup-script.py
    ```

2. Add the script to the `.zshrc` file to automatically run at startup:
    ```bash
    echo "/path/to/startup-script.py" >> ~/.zshrc
    ```

3. Reboot your system to test if the script runs automatically:
    ```bash
    sudo reboot
    ```

## Contributions
Contributions are welcome! If you wish to add more scanning tools or features, feel free to fork this repository and open a pull request.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

