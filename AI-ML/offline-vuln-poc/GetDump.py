import requests
import csv

# NVD API URL
url = "https://services.nvd.nist.gov/rest/json/cves/1.0"

# Optional API key (if required)
api_key = "YOUR_API_KEY_HERE"
headers = {"apiKey": api_key} if api_key else {}

# Request CVE data from API
response = requests.get(url, headers=headers)

# Check if API response is successful
if response.status_code == 200:
    try:
        data = response.json()
    except requests.exceptions.JSONDecodeError:
        print("Error: Invalid JSON response from API.")
        exit()
else:
    print(f"Error: API request failed (Status Code: {response.status_code})")
    exit()

# Prepare CSV file
csv_filename = "vulnerability_dump.csv"
fields = ["CVE ID", "Description", "Severity", "Published Date"]

# Write data to CSV
with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
    csv_writer = csv.writer(csvfile)
    csv_writer.writerow(fields)

    for item in data["result"]["CVE_Items"]:
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        description = item["cve"]["description"]["description_data"][0]["value"]
        severity = item.get("impact", {}).get("baseMetricV2", {}).get("severity", "Unknown")
        pub_date = item["publishedDate"]

        csv_writer.writerow([cve_id, description, severity, pub_date])

print(f"CSV successfully created: {csv_filename}")