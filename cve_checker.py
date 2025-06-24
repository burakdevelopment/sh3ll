import aiohttp
import asyncio
import logging


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
async def search_cve_for_product(product_name: str, api_key: str, session: aiohttp.ClientSession):

    if not api_key or api_key == "d5f47432-e658-465b-83c2-3fe7bec8c3f1":   #free api key enjoy it :) (ofc, u can change with ur new NVD API key)
        logging.warning("The NVD API key is not configured. Skipping the CVE scan.")
        return []

    cleaned_product = product_name.split('/')[0].split(' ')[0].strip()
    if not cleaned_product:
        return []
    
    params = {
        "keywordSearch": cleaned_product,
        "resultsPerPage": 20 
    }
    headers = {"apiKey": api_key}
    
    try:
        async with session.get(NVD_API_URL, params=params, headers=headers, timeout=15) as response:
            if response.status == 200:
                data = await response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                found_cves = []
                for item in vulnerabilities:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id")
                    description = "No explanation was found."
                    
                    for desc in cve.get("descriptions", []):
                        if desc.get("lang") == "en":
                            description = desc.get("value")
                            break
                    
                    
                    cvss_score = "N/A"
                    metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
                    if metrics:
                        cvss_score = metrics[0].get("cvssData", {}).get("baseScore")

                    found_cves.append({
                        "id": cve_id,
                        "score": cvss_score,
                        "description": description
                    })
                logging.info(f"'{cleaned_product}' for {len(found_cves)} CVE found.")
                return found_cves
            else:
                logging.error(f"NVD API Error: {response.status} - {await response.text()}")
                return []
    except asyncio.TimeoutError:
        logging.error(f"The NVD API request has expired ({product_name}).")
        return []
    except Exception as e:
        logging.error(f"Error when connecting to the NVD API: {e}")
        return []
