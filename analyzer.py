import requests
import os
from datetime import datetime

# ----------------------------
# Helper Functions
# ----------------------------

def check_read_access(url):
    """Check if bucket content is publicly readable (directory listing or object access)."""
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200 and ("<ListBucketResult" in response.text or "<Blob" in response.text):
            return True
    except:
        pass
    return False

def check_write_access(url):
    """Check if we can upload a test file (only works if bucket exposes PUT/POST)."""
    test_file_content = b"Security test file - harmless"
    try:
        test_url = os.path.join(url.rstrip("/"), "test_upload.txt")
        response = requests.put(test_url, data=test_file_content, timeout=5)
        if response.status_code in [200, 201]:
            return True
    except:
        pass
    return False

def classify_vulnerability(readable, writable):
    """Classify severity based on permissions."""
    if readable and writable:
        return "HIGH"
    elif readable:
        return "MEDIUM"
    elif writable:
        return "MEDIUM"
    else:
        return "LOW"

def scan_bucket(url):
    """Scan a single bucket and return vulnerability info."""
    readable = check_read_access(url)
    writable = check_write_access(url)
    severity = classify_vulnerability(readable, writable)
    return {
        "URL": url,
        "Readable": readable,
        "Writable": writable,
        "Severity": severity
    }

def generate_html_report(results, filename="report.html"):
    """Generate an HTML report with vulnerability classification."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""
    <html>
    <head>
        <title>Cloud Bucket Security Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ccc; padding: 8px; text-align: center; }}
            th {{ background-color: #f4f4f4; }}
            .HIGH {{ background-color: #f44336; color: white; }}
            .MEDIUM {{ background-color: #ff9800; color: white; }}
            .LOW {{ background-color: #4caf50; color: white; }}
        </style>
    </head>
    <body>
        <h2>Cloud Bucket Security Report</h2>
        <p>Generated on: {now}</p>
        <table>
            <tr>
                <th>Bucket URL</th>
                <th>Readable</th>
                <th>Writable</th>
                <th>Severity</th>
            </tr>
    """

    for r in results:
        html += f"""
        <tr>
            <td>{r['URL']}</td>
            <td>{'✔' if r['Readable'] else '✘'}</td>
            <td>{'✔' if r['Writable'] else '✘'}</td>
            <td class="{r['Severity']}">{r['Severity']}</td>
        </tr>
        """

    html += """
        </table>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[✔] Report saved as {filename}")


# ----------------------------
# Main Program
# ----------------------------
if __name__ == "__main__":
    print("🔍 Cloud Bucket Vulnerability Analyzer\n")

    with open("buckets.txt", "r") as f:
        urls = [line.strip() for line in f.readlines() if line.strip()]

    results = []
    for url in urls:
        print(f"Scanning {url} ...")
        results.append(scan_bucket(url))

    generate_html_report(results)
    print("✅ Scan completed. Open 'report.html' to view results.")
