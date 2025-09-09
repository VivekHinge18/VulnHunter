# 🛡️ VulnHunter - Asynchronous Web Vulnerability Scanner

VulnHunter is a comprehensive and high-performance web application vulnerability scanner developed to automate the detection of common security flaws. It features a powerful asynchronous engine, built with Python's `asyncio` and `aiohttp`, allowing it to perform hundreds of concurrent non-blocking requests, which dramatically reduces scan times compared to traditional sequential scanners.

The process begins with an intelligent recursive crawler that maps out the target application, followed by a modular testing phase that probes for Reflected Cross-Site Scripting (XSS), SQL Injection (SQLi), and Local File Inclusion (LFI). All findings are managed through a clean, interactive web dashboard built with Flask, where users can initiate scans, monitor their status, view detailed results, and export reports to CSV format for analysis.



---
## ✨ Key Features

-   **High-Speed Asynchronous Engine:** Utilizes `asyncio` and `aiohttp` to perform hundreds of non-blocking HTTP requests concurrently, resulting in dramatically faster scan times.
-   **Multi-Vulnerability Scanning:** Includes modular scanners for:
    -   Reflected Cross-Site Scripting (XSS)
    -   SQL Injection (SQLi)
    -   Local File Inclusion (LFI)
-   **Intelligent Recursive Crawler:** Discovers all same-domain links on a target website to ensure comprehensive scan coverage.
-   **Interactive Web Dashboard:** A modern UI built with Flask and Tailwind CSS to manage scans and view results.
-   **Real-time Scan Status:** The dashboard displays the status of scans as "Scanning..." or "Completed".
-   **Detailed Reporting:** View detailed vulnerability reports on the web and export results to a downloadable CSV file.
-   **Database Storage:** All scan sessions and findings are stored in a local SQLite database using SQLAlchemy.

---
## 🛠️ Tech Stack

-   **Backend:** Python, Flask, SQLAlchemy
-   **Scanning Engine:** `asyncio`, `aiohttp`, BeautifulSoup
-   **Database:** SQLite
-   **Frontend:** HTML, Tailwind CSS

---
## 🚀 Setup and Installation

1.  **Clone the Repository**
    ```bash
    git clone <your-github-repo-url>
    cd VulnHunter
    ```

2.  **Create and Activate Virtual Environment**
    ```bash
    # For Windows
    python -m venv VulnHunter
    .\VulnHunter\Scripts\activate
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Initialize the Database**
    ```bash
    python
    >>> from app import app, db
    >>> app.app_context().push()
    >>> db.create_all()
    >>> exit()
    ```

5.  **Run the Application**
    ```bash
    python app.py
    ```
    Navigate to `http://127.0.0.1:5000` in your web browser.
