import requests
from datetime import datetime, timedelta

# Configuration
BASE_URL = "https://euvdservices.enisa.europa.eu"
SEARCH_ENDPOINT = f"{BASE_URL}/api/search"
MAX_PAGE_SIZE = 100

# --- HARDCODED LIST OF KEYWORDS ---
# Add, remove, or modify keywords here
KEYWORDS_LIST = [
    "rancher",
    "kubernetes",
    "traefik"
]

def get_last_7_days_date():
    """Returns the date 7 days ago in YYYY-MM-DD format."""
    today = datetime.now()
    seven_days_ago = today - timedelta(days=7)
    return seven_days_ago.strftime("%Y-%m-%d")

def search_euvd_by_keyword(keyword, start_date, end_date):
    """
    Searches EUVD for a single keyword within a date range.
    Returns a list of vulnerability dictionaries.
    """
    results = []
    page = 0
    
    while True:
        params = {
            "text": keyword,
            "fromDate": start_date,
            "toDate": end_date,
            "size": MAX_PAGE_SIZE,
            "page": page
        }
        
        try:
            response = requests.get(SEARCH_ENDPOINT, params=params)
            response.raise_for_status()
            data = response.json()
            
            # Handle paginated structure {'items': [...], 'total': N}
            if isinstance(data, dict) and 'items' in data:
                items = data.get('items', [])
                if not items:
                    break
                
                results.extend(items)
                
                # If we got fewer items than max page size, we're at the end
                if len(items) < MAX_PAGE_SIZE:
                    break
                
                page += 1
            else:
                break
                
        except requests.exceptions.RequestException as e:
            print(f"Error fetching data for keyword '{keyword}': {e}")
            break
            
    return results

def parse_vulnerability(vuln):
    """
    Extracts clean variables from a vulnerability dictionary.
    """
    euvd_id = vuln.get("id", "N/A")
    
    # Extract CVE ID from aliases
    aliases = vuln.get("aliases", "")
    cve_id = "N/A"
    if aliases:
        if isinstance(aliases, list):
            for alias in aliases:
                if str(alias).startswith("CVE-"):
                    cve_id = str(alias)
                    break
        elif isinstance(aliases, str):
            for line in aliases.split('\n'):
                line = line.strip()
                if line.startswith("CVE-"):
                    cve_id = line
                    break
    
    base_score = vuln.get("baseScore", "N/A")
    date_published = vuln.get("datePublished", "N/A")
    assigner = vuln.get("assigner", "N/A")
    
    # Extract Product/Vendor info
    products = []
    for prod in vuln.get("enisaIdProduct", []):
        p_name = prod.get('product', {}).get('name', 'Unknown')
        vendor = prod.get('product', {}).get('vendor', {}).get('name', 'Unknown')
        version = prod.get('product_version', 'N/A')
        products.append(f"{vendor} {p_name} ({version})")
    
    # Clean description for display
    description = vuln.get("description", "No description")
    clean_desc = " ".join(description.split())
    title_preview = clean_desc[:100] + "..." if len(clean_desc) > 100 else clean_desc

    return {
        "euvd_id": euvd_id,
        "cve_id": cve_id,
        "score": base_score,
        "date": date_published,
        "assigner": assigner,
        "products": products,
        "description": title_preview
    }

def main():
    print(f"Searching EUVD with keywords: {KEYWORDS_LIST}")
    print("-" * 50)

    # Calculate date range
    end_date = datetime.now().strftime("%Y-%m-%d")
    start_date = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
    
    # Dictionary to store unique results keyed by EUVD ID
    unique_results = {}

    # Loop through each keyword and search
    for kw in KEYWORDS_LIST:
        print(f"Searching for keyword: '{kw}'...")
        raw_results = search_euvd_by_keyword(kw, start_date, end_date)
        
        for vuln in raw_results:
            parsed = parse_vulnerability(vuln)
            euvd_id = parsed["euvd_id"]
            
            # Add to unique results if not already present
            if euvd_id not in unique_results:
                unique_results[euvd_id] = parsed
            else:
                # Optional: You could log which keyword found the duplicate
                pass

    # Display final aggregated results
    if not unique_results:
        print("No vulnerabilities found matching the criteria.")
    else:
        sorted_results = sorted(unique_results.values(), key=lambda x: x["date"], reverse=True)
        print(f"\nTotal Unique Vulnerabilities Found: {len(sorted_results)}\n")
        
        for i, vuln in enumerate(sorted_results, 1):
            print(f"[{i}] EUVD ID: {vuln['euvd_id']}")
            print(f"    CVE ID:  {vuln['cve_id']}")
            print(f"    Score:   {vuln['score']}")
            print(f"    Date:    {vuln['date']}")
            print(f"    Assigner:{vuln['assigner']}")
            print(f"    Products:{vuln['products']}")
            print(f"    Desc:    {vuln['description']}")
            print("-" * 50)

if __name__ == "__main__":
    main()

