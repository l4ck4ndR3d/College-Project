# Description : 
 - Webscrapping tool is used for scrape the website in a specific pattern by using the Python's library (BeautifulSoup and request).After the scraping analyze and filter for required information.
 - After scraping the scraped information is stored in CSV file for future use of vulnerability details.
 - After storing in the file we taske a copy of the information and send it to the user's email itself.

# Detailed Architecture Flow

    1. Trigger - A scheduled job (cron or task scheduler) runs the script daily.
    2. Data Fetching - The script makes a GET request to the CVE feed (NVD or CVE.org).
    3. Raw JSON Storage - The fetched JSON is saved as new_cves.json
    4. Load Previous Database - The script loads new_cves.json for comparison.
    5. Comparison Logic - 
        ◦ If a CVE ID exists today but not yesterday → New CVE
        ◦ If CVE exists but fields changed → Updated CVE
    6. Field Change Detection
        The system checks changes in:
            ◦ CVSS score
            ◦ Severity
            ◦ Description
            ◦ CWE list
            ◦ Affected products
            ◦ References
        ◦ Exploit status
    7. Extraction of CVSS & Severity
        For updated CVEs, the system extracts:
            ◦ cvssMetricV31.baseScore
            ◦ cvssMetricV31.baseSeverity
            ◦ If missing, checks CVSSv2 fallback.
    8. Email Content Creation
        Emails contain sections for:
            ◦ New CVEs
            ◦ Updated CVEs
            ◦ Severity level
            ◦ Scores
            ◦ CWE mappings
            ◦ CISA links

#### Requirements : 

For sending the email to ourself we need 

    1.Email (example@gmail.com)
    2.App password  (XXXX XXXX XXXX XXXX)

Setting up App password: 

    1.Setup the 2-Step Verification
    2.Search 
          * Type "App Password"
          * Type "App Name" 
          * Click "Generate" Button.
          * Shows 12 digit letters (XXXX XXXX XXXX XXXX)
    3.Update the APP PASSWORD to the "sender_password" variable.
    
  
- Docker setup of code : attached in the Docker_running_methods.md
- Full script : script2.py
- Dockerfile : Dockerfile

Author : Bala 

 
