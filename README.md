# Professional SQL Injection Testing Tool - 2025.1

## 🌟 Overview

This Professional SQL Injection Testing Tool is designed for educational purposes and authorized security testing. It provides a comprehensive, multi-threaded platform for learning about SQL injection vulnerabilities and testing the security of web applications with proper authorization.

Built with Python and Tkinter, it features a modern, intuitive user interface and a powerful detection engine to help users identify and understand SQLi vulnerabilities effectively.

## ✨ Key Features

-   **Advanced Detection Engine:**
    -   Error-based SQL injection detection
    -   Boolean-based blind SQL injection
    -   Time-based blind SQL injection
    -   Union-based SQL injection
    -   WAF (Web Application Firewall) bypass techniques and tampering scripts
    -   JSON-based injection testing

-   **Professional User Interface:**
    -   Modern dark theme design
    -   Real-time statistics and progress tracking
    -   Multi-threaded scanning for performance
    -   Live result monitoring
    -   Responsive layout for various screen sizes

-   **Flexible Scanning Options:**
    -   **Single Target Mode:** Perform a deep scan on a single URL.
    -   **Multiple Targets Mode:** Load a list of domains from a file for bulk scanning.
    -   Configurable request delay, timeout, and thread count.

-   **Payload & Tamper Management:**
    -   Comes with 500+ pre-built payloads for various injection types.
    -   Full system for creating, editing, deleting, and testing custom payloads.
    -   Import/export functionality for custom payload lists.

-   **Comprehensive Reporting:**
    -   View detailed results directly within the application.
    -   Export scan reports in multiple formats: **HTML**, **CSV**, and **JSON**.

## ⚙️ Installation

To get started with the SQL Injection Testing Tool, follow these steps:

1.  **Clone the Repository:**
    First, clone the repository to your local machine using Git.
    ```bash
    git clone https://github.com/VanessaEvo/sql-tester-tool.git
    cd sql-tester-tool
    ```

2.  **Install Dependencies:**
    The tool requires the `requests` library. Install all dependencies using the provided `requirements.txt` file. It is recommended to use a virtual environment.
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the Application:**
    Execute the `main.py` script to launch the tool.
    ```bash
    python main.py
    ```

## 🚀 How to Use

The tool is organized into several tabs, each with a specific purpose.

### 🎯 Single Target Tab
This tab is for performing an in-depth scan on a single URL.
1.  **Enter URL:** Input the full target URL, including parameters (e.g., `http://example.com/page.php?id=1`).
2.  **Parse Parameter:** Click "Parse URL Parameters" to automatically identify the parameter to test.
3.  **Select Injection Types:** Choose the types of SQL injection you want to test for.
4.  **Configure Settings:** Adjust the request delay, timeout, and number of threads as needed.
5.  **Start Scan:** Click "START SCAN" to begin the test. Results will appear in the "Live Scan Results" panel.

### 🌐 Multiple Targets Tab
This tab allows you to scan multiple domains in one go.
1.  **Load Domains:** Either paste a list of URLs (one per line) into the text box or click "Load File" to import a list from a `.txt` file.
2.  **Validate:** (Optional) Click "Validate Domains" to check the format of the URLs.
3.  **Start Scan:** Click "START" to begin scanning all domains. The results will show which domains are vulnerable.

### 📊 Results Tab
This tab aggregates all findings from your scans.
-   **View Summary:** See a high-level overview of total scans and vulnerabilities found.
-   **Detailed View:** The table shows detailed information for each vulnerability. Double-click any entry for more details.
-   **Export:** Use the buttons at the top right to export all results to an HTML, CSV, or JSON file for further analysis.

### 🔧 Payloads Tab
Here, you can manage the payloads used for testing.
-   **Browse:** Select a category on the left to view its associated payloads.
-   **Manage:** Add, edit, or delete custom payloads using the editor at the bottom.
-   **Save/Load:** Save your custom payload sets to a file or load them for future use.

## ⚠️ Ethical and Legal Disclaimer

🚨 **IMPORTANT: This tool is designed exclusively for educational purposes and authorized security testing. Unauthorized use of this tool against systems for which you do not have explicit, written permission is illegal and unethical.**

### Authorized Use Only
-   You must only test systems you **own** or have **explicit, written permission** to test.
-   You must obtain proper authorization before conducting any security assessments.
-   You must respect the terms of service of all target systems.
-   You must follow responsible disclosure practices for any vulnerabilities you find.

### Prohibited Activities
-   Testing systems without authorization.
-   Attempting to gain unauthorized access or cause damage to systems.
-   Violating any applicable computer crime laws or regulations.

The developers and distributors of this tool are not responsible for any misuse or damage caused by this program. **By using this tool, you agree to take full responsibility for your actions.**
