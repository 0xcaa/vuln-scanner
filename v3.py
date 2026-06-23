import requests
from datetime import datetime, timedelta

# Configuration
URL = "https://euvdservices.enisa.europa.eu/api/search"
# Hardcoded keywords to search
KEYWORDS = ["rancher", "kubernetes", "harvester"]

def main():
    # Calculate date range (last 7 days)
    end_date = datetime.now().strftime("%Y-%m-%d")
    start_date = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
    
    all_vulns = {} # Use dict to store unique EUVD IDs

    for kw in KEYWORDS:
        print(f"Searching for: {kw}...")
        page = 0
        while True:
            params = {
                "text": kw,
                "fromDate": start_date,
                "toDate": end_date,
                "size": 100,
                "page": page
            }
            try:
                resp = requests.get(URL, params=params)
                data = resp.json()
                
                if not isinstance(data, dict) or 'items' not in data:
                    break
                    
                items = data['items']
                if not items: break
                
                for v in items:
                    euvd_id = v.get("id")
                    # Only add if we haven't seen this EUVD ID before
                    if euvd_id and euvd_id not in all_vulns:
                        all_vulns[euvd_id] = v
                        all_vulns[keyword] = kw
                
                # Stop if we got fewer than 100 items (last page)
                if len(items) < 100: break
                page += 1
                
            except Exception as e:
                print(f"Error: {e}")
                break

    # Output Results
    print(f"\nFound {len(all_vulns)} unique vulnerability(ies):\n")
    for euvd_id, v in all_vulns.items():
        # Extract fields
        aliases = v.get("aliases", "")
        cve = "N/A"
        if isinstance(aliases, str):
            for line in aliases.split('\n'):
                if line.strip().startswith("CVE-"):
                    cve = line.strip()
                    break
        elif isinstance(aliases, list) and aliases:
            cve = next((a for a in aliases if str(a).startswith("CVE-")), "N/A")
        
        print(f"EUVD: {euvd_id} | CVE: {cve} | Score: {v.get('baseScore', 'N/A')}")
        print(f"Date: {v.get('datePublished', 'N/A')}")
        print(f"Desc: {v.get('description', '')[:200]}...")
        print("-" * 50)

if __name__ == "__main__":
    main()

