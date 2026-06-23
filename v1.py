import requests
from datetime import datetime, timedelta

# Configuration
BASE_URL = "https://euvdservices.enisa.europa.eu"
SEARCH_ENDPOINT = f"{BASE_URL}/api/search"
MAX_PAGE_SIZE = 100  # The API allows max 100 records per request

def get_last_7_days_date():
    """Returns the date 7 days ago in YYYY-MM-DD format."""
    today = datetime.now()
    seven_days_ago = today - timedelta(days=7)
    return seven_days_ago.strftime("%Y-%m-%d")

def search_euvd_keywords(keywords, days=7):
    """
    Searches EUVD for vulnerabilities containing specific keywords 
    within the last 'days' days.
    """
    # Calculate the date range
    # Note: The API uses 'toDate' as inclusive. We use today's date.
    end_date = datetime.now().strftime("%Y-%m-%d")
    start_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    
    print(f"Searching EUVD for keywords: '{keywords}'")
    print(f"Date range: {start_date} to {end_date}")
    print("-" * 50)

    all_vulnerabilities = []
    page = 0
    
    while True:
        # Build the query parameters
        params = {
            "text": keywords,
            "fromDate": start_date,
            "toDate": end_date,
            "size": MAX_PAGE_SIZE,
            "page": page
        }
        
        try:
            # Make the GET request
            response = requests.get(SEARCH_ENDPOINT, params=params)
            response.raise_for_status()  # Raise an error for bad status codes
            
            data = response.json()
            
            # FIX: Handle the paginated structure {'items': [...], 'total': N}
            if isinstance(data, dict) and 'items' in data:
                items = data.get('items', [])
                
                if not items:
                    break  # No more results
                
                all_vulnerabilities.extend(items)
                
                # Check if we've fetched all results or just the next page
                total = data.get('total', 0)
                
                # If we got fewer items than the max page size, it's the last page
                if len(items) < MAX_PAGE_SIZE:
                    break
                
                # Move to the next page
                page += 1
            else:
                print(f"Unexpected response format: {data}")
                break
                
        except requests.exceptions.RequestException as e:
            print(f"Error fetching data: {e}")
            break

    # Parse and Display results
    if not all_vulnerabilities:
        print("No vulnerabilities found matching the criteria.")
    else:
        print(f"Found {len(all_vulnerabilities)} vulnerability(ies):\n")
        
        for i, vuln in enumerate(all_vulnerabilities, 1):
            # --- PARSING VARIABLES ---
            
            # 1. EUVD ID
            euvd_id = vuln.get("id", "N/A")
            
            # 2. CVE ID (located in 'aliases' list, usually first item)
            aliases = vuln.get("aliases", "")
            cve_id = "N/A"
            if aliases and isinstance(aliases, str):
                # Aliases might be newline-separated or a single string
                # Clean up whitespace and check for CVE pattern
                lines = [a.strip() for a in aliases.split('\n') if a.strip()]
                for alias in lines:
                    if alias.startswith("CVE-"):
                        cve_id = alias
                        break
            elif aliases and isinstance(aliases, list) and aliases:
                for alias in aliases:
                    if alias.startswith("CVE-"):
                        cve_id = alias
                        break
            
            # 3. Base Score (CVSS)
            base_score = vuln.get("baseScore", "N/A")
            
            # 4. Title/Description (Using first 100 chars of description as a preview)
            description = vuln.get("description", "No description")
            # Clean newlines for display
            clean_desc = " ".join(description.split())
            title_preview = clean_desc[:100] + "..." if len(clean_desc) > 100 else clean_desc
            
            # 5. Date Published
            date_published = vuln.get("datePublished", "N/A")
            
            # 6. Assigner/Vendor
            assigner = vuln.get("assigner", "N/A")
            
            # 7. Product Versions (from enisaIdProduct)
            products = vuln.get("enisaIdProduct", [])
            product_versions = []
            for prod in products:
                p_name = prod.get('product', {}).get('name', 'Unknown')
                vendor = prod.get('product', {}).get('vendor', {}).get('name', 'Unknown')
                version = prod.get('product_version', 'N/A')
                product_versions.append(f"{vendor} {p_name} ({version})")
            
            # --- PRINTING ---
            print(f"[{i}] EUVD ID: {euvd_id}")
            print(f"    CVE ID:  {cve_id}")
            print(f"    Score:   {base_score} (CVSS {vuln.get('baseScoreVersion', 'N/A')})")
            print(f"    Date:    {date_published}")
            print(f"    Assigner:{assigner}")
            print(f"    Products:{product_versions}")
            print(f"    Desc:    {title_preview}")
            print("-" * 50)

def main():
    # Example: Search for keywords like "log4j" or "authentication"
    # You can modify this list or input via command line
    user_keywords = input("Enter keywords to search (e.g., 'log4j authentication'): ")
    
    if not user_keywords.strip():
        print("No keywords provided. Exiting.")
        return
        
    search_euvd_keywords(keywords=user_keywords, days=7)

if __name__ == "__main__":
    main()

