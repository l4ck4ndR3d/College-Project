# working extraction code snippet

import requests
import json
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime as dt

DELTA_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json"
SAVE_DIR = '/app/data'
os.makedirs(SAVE_DIR, exist_ok=True)

# -- Email config --

sender_email = os.getenv("SENDER_EMAIL")
sender_password = os.getenv("SENDER_PASSWORD")  # Use an app password if 2FA
recipient_email = os.getenv("RECIPIENT_EMAIL")

header = f"""
NOTE : \n
1. New CVEs are updated without CVSS Scores and Affected Products details, will be updated in updated CVEs.\n
2. New CVEs are just informational purpose, please verify from NVD site before taking any actions.\n
3. Updated CVEs will have complete information including CVSS Scores and Affected Products details.\n

"""
new_body_text = ""
update_body_text = ""
# --------------
#| Email Config |
# --------------

def send_email(sender_email, sender_password, recipient_email, subject, body):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)  
        server.starttls()  
        server.login(sender_email, sender_password)  
        server.send_message(msg)
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")
    finally:
        server.quit()

def fmt_affected(affected):
    """Pretty print affected products."""
    if not affected or affected == "N/A":
        return "N/A"

    out = ""
    for item in affected:
        out += f"- Vendor: {item.get('vendor','N/A')}\n"
        out += f"  Product: {item.get('product','N/A')}\n"
        out += f"  Versions:\n"
        for v in item.get("versions", []):
            out += f"    • {v.get('version')} ({v.get('status')})\n"
        if item.get("platforms"):
            out += f"  Platforms: {', '.join(item.get('platforms'))}\n"
        out += "\n"
    return out.strip()


def fmt_date(d):
    """Convert ISO date → readable format."""
    if not d or d == "N/A":
        return "N/A"
    try:
        return dt.fromisoformat(d.replace("Z", "")).strftime("%d %b %Y %H:%M:%S")
    except:
        return d


def fmt_refs(refs):
    """Pretty print references list."""
    if not refs or refs == "N/A":
        return "N/A"
    return "\n".join([f"• {r}" for r in refs])


def extract_cvss_from_metrics(metrics):
    """
    Supports:
    - CVSSv3.1 (cvssV3_1)
    - CVSSv3.0 (cvssV3_0)
    - CVSSv4 (cvssV4)
    Returns severity, score, vector
    """
    severity = "N/A"
    score = "N/A"
    vector = "N/A"

    for m in metrics:

        # CVSS v3.1
        v31 = m.get("cvssV3_1")
        if v31:
            severity = v31.get("baseSeverity", severity)
            score = v31.get("baseScore", score)
            vector = v31.get("vectorString", vector)

        # CVSS v3.0
        v30 = m.get("cvssV3_0")
        if v30:
            severity = v30.get("baseSeverity", severity)
            score = v30.get("baseScore", score)
            vector = v30.get("vectorString", vector)

        # CVSS v4
        v4 = m.get("cvssV4")
        if v4:
            score = v4.get("baseScore", score)
            # CVSSv4 may not have severity
            severity = v4.get("baseSeverity", severity) or severity

    return severity, score, vector



#--------------
# Email config 
#--------------
def body(extracted_fields,cvetype):
    cwe_id = (
        extracted_fields['cwe'][0]['cweId']
        if extracted_fields.get('cwe') and len(extracted_fields['cwe']) > 0
        else 'N/A'
    )
    if cvetype == "new":
        published = fmt_date(extracted_fields.get('published', 'N/A'))
        updated = fmt_date(extracted_fields.get('updated', 'N/A'))
        reference = fmt_refs(extracted_fields.get('references', 'N/A'))
        affected = fmt_affected(extracted_fields.get('affected', []))
        body = f"""
---- NEW CVE DETAILS ----
📌 NEW CVEs in the CVE Project repository.
1. CVE ID: {extracted_fields.get('cveId')}
2. Description: {extracted_fields.get('description', 'N/A')}
3. Published Date: {published}
4. Updated Date: {updated}
5. CWE: {cwe_id}
6. Affected Products: {affected}
7. References: {reference}
8. CVE org Link: {extracted_fields.get('cveOrgLink', 'Will updated Soon')}\n
"""
    else:
        affected = fmt_affected(extracted_fields.get('affected', []))
        published = fmt_date(extracted_fields.get('published', 'N/A'))
        updated = fmt_date(extracted_fields.get('updated', 'N/A'))
        reference = fmt_refs(extracted_fields.get('references', 'N/A'))
        body = f"""
---- UPDATED CVE DETAILS ----
📌 UPDATED CVEs in the CVE Project repository.
1. CVE ID: {extracted_fields.get('cveId')}
2. Severity Score: {extracted_fields.get('severity', 'N/A')}
3. CVSSv3 Score: {extracted_fields.get('cvssV3_score', 'N/A')}
4. Description: {extracted_fields.get('description', 'N/A')}
5. Published Date: {published}
6. Updated Date: {updated}
7. CWE: {cwe_id}
8. Affected Products: {affected}\n
9. References: {reference}
10. CVE org Link: {extracted_fields.get('cveOrgLink', 'N/A')}\n
"""
    return body




#  -----
# | ETL | 
#  -----
def load_json_list(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r") as f:
            return json.load(f)
    except:
        return []

def save_json_list(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def fix_multi_json(raw):
    objects = []
    buffer = ""

    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("{"):
            if buffer:
                try:
                    objects.append(json.loads(buffer))
                except:
                    pass
                buffer = ""
        buffer += line

    # last object
    try:
        objects.append(json.loads(buffer))
    except:
        pass

    # merge all objects into one dict
    final = {}
    for obj in objects:
        final.update(obj)

    return final

def extract_important_fields(data,cveOrgLink=None):
    cve = {}

    # --- CVE Metadata ---
    meta = data.get("cveMetadata", {})
    cve["cveId"] = meta.get("cveId")
    cve["assignerOrgId"] = meta.get("assignerOrgId")
    cve["published"] = meta.get("datePublished")
    cve["updated"] = meta.get("dateUpdated")
    cve["cveOrgLink"] = cveOrgLink
    # --- CNA Container ---
    cna = data.get("containers", {}).get("cna", {})

    # Description
    desc = cna.get("descriptions", [])
    if desc:
        cve["description"] = desc[0].get("value")

    # CWE
    cve_list = []
    for p in cna.get("problemTypes", []):
        for d in p.get("descriptions", []):
            cve_list.append({
                "cweId": d.get("cweId"),
                "cweName": d.get("description")
            })
    cve["cwe"] = cve_list

    # Affected products
    affected = []
    for a in cna.get("affected", []):
        entry = {
            "vendor": a.get("vendor"),
            "product": a.get("product"),
            "versions": []
        }
        for v in a.get("versions", []):
            entry["versions"].append({
                "version": v.get("version"),
                "status": v.get("status")
            })
        entry["platforms"] = a.get("platforms", [])
        affected.append(entry)

    cve["affected"] = affected

    # CVSS metrics
    metrics = cna.get("metrics", [])
    severity, cvss3_score, cvss3_vector = extract_cvss_from_metrics(metrics)

    cve["severity"] = severity
    cve["cvssV3_score"] = cvss3_score
    cve["cvssV3_vector"] = cvss3_vector

    # References
    refs = cna.get("references", [])
    cve["references"] = [r.get("url") for r in refs if "url" in r]

    # Exploit status
    cve["exploitStatus"] = cna.get("exploitStatus")
    cve["source"] = cna.get("source")

    return cve

#-------------
#| delta.json |
#-------------

print("[+] Downloading delta.json...")
delta = requests.get(DELTA_URL).json()

# ------------
#|  NEW CVEs |
# ------------
NEW_FILE = os.path.join(SAVE_DIR, "new_cves.json")
new_cves = delta.get("new", [])
new_list = load_json_list(NEW_FILE)
existing_ids = {item["cveId"] for item in new_list if "cveId" in item}

print("[+] Processing NEW CVEs:")
added_count = 0
for cve in new_cves:
    cveOrgLink  = cve.get("cveOrgLink")
    url = cve.get("githubLink")

    if not url: continue

    raw = requests.get(url).text

    try:
        data = json.loads(raw)
    except:
        data = fix_multi_json(raw)

    extracted = extract_important_fields(data,cveOrgLink)
    cve_id = extracted.get("cveId")

    body(extracted,"new")

    if not cve_id or cve_id in existing_ids: continue

    new_body_text += body(extracted,"new") + "\n"

    new_list.append(extracted)

    existing_ids.add(cve_id)
    added_count += 1
    print(f"    [+] Added: {cve_id}")

save_json_list(NEW_FILE, new_list)
print("[+] Saved:", NEW_FILE)
print(f"[+] Total NEW CVEs added: {added_count}")


# --------------
#| UPDATED CVEs |
# --------------

UPDATE_FILE = os.path.join(SAVE_DIR, "updated_cves.json")
updated_cves = delta.get("updated", [])
update_list = load_json_list(UPDATE_FILE)
existing_updated_ids = {item['cveId'] for item in update_list if 'cveId' in item}

print("[+] Processing UPDATED CVEs:")
updated_count = 0

for cve in updated_cves:
    cveOrgLink  = cve.get("cveOrgLink")
    url = cve.get("githubLink")
    if not url:
        continue

    raw = requests.get(url).text

    try:
        data = json.loads(raw)
    except:
        data = fix_multi_json(raw)

    extracted = extract_important_fields(data,cveOrgLink)
    cve_id = extracted.get("cveId")
    
    if not cve_id or cve_id in existing_updated_ids: continue
    
    update_body_text += body(extracted,"updated") + "\n\n"

    update_list.append(extracted)
    existing_updated_ids.add(cve_id)
    updated_count += 1
    print(f"    [+] Updated: {cve_id}")

save_json_list(UPDATE_FILE, update_list)
print("[+] Saved:", UPDATE_FILE)
print(f"[+] Total UPDATED CVEs added: {updated_count}")



#----------
#|  MAIN  |
#----------
if __name__ == "__main__":    
    try:
        if added_count == 0 and updated_count ==0:
            print("[*] No new or updated CVEs to send.")
            exit(0)

        final_body = header
        if added_count> 0:
            final_body +=  new_body_text

        if updated_count>0:
            final_body +=  update_body_text
            
        subject = f"{dt.now().year}-{dt.now().month}-{dt.now().day} | CVE Updates Notification"
        send_email(sender_email, sender_password, recipient_email, subject, final_body)
    except Exception as e:
        pass
