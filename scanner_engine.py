import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# --- ASYNCHRONOUS RECURSIVE CRAWLER ---
# --- ASYNCHRONOUS RECURSIVE CRAWLER (Upgraded & More Robust) ---
async def recursive_crawler(session, target_url, max_links=50):
    """
    Recursively crawls a website starting from the target_url to find all unique,
    same-domain, HTML links, up to a maximum limit.
    """
    urls_to_visit = [target_url]
    visited_urls = set()

    while urls_to_visit and len(visited_urls) < max_links:
        current_url = urls_to_visit.pop(0)
        
        if current_url in visited_urls:
            continue
            
        visited_urls.add(current_url)
        
        try:
            async with session.get(current_url, timeout=10) as response:
                # --- THIS IS THE FIX ---
                # 1. Check if the request was successful
                if response.status != 200:
                    continue
                # 2. Check if the content is HTML before trying to read it
                content_type = response.headers.get('Content-Type', '').lower()
                if 'text/html' not in content_type:
                    print(f"  [Info] Skipping non-HTML content at: {current_url}")
                    continue
                # 3. If it is HTML, read the content
                content = await response.text()
                # ---------------------

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            print(f"  [Error] Could not fetch {current_url}: {e}")
            continue

        soup = BeautifulSoup(content, 'html.parser')
        domain_name = urlparse(target_url).netloc

        for a_tag in soup.find_all("a", href=True):
            href = a_tag.attrs.get("href")
            if not href:
                continue

            full_url = urljoin(target_url, href).split('#')[0]

            if urlparse(full_url).netloc == domain_name and full_url not in visited_urls:
                if len(visited_urls) + len(urls_to_visit) < max_links:
                     urls_to_visit.append(full_url)
    
    return list(visited_urls)

# --- ASYNCHRONOUS SCANNERS ---
async def scan_url(session, url):
    """A wrapper function to run all vulnerability scans on a single URL."""
    tasks = [
        scan_for_xss(session, url),
        scan_for_sqli(session, url),
        scan_for_lfi(session, url)
    ]
    results = await asyncio.gather(*tasks)
    # Flatten the list of results (filter out None values)
    return [result for result in results if result]

async def scan_for_xss(session, url):
    xss_payloads = ["<script>alert('xss')</script>", "<img src=x onerror=alert('xss')>"]
    if '?' not in url: return None
    
    parsed_url = urlparse(url)
    try:
        params = parsed_url.query.split('&')
    except AttributeError:
        return None

    for param in params:
        if '=' not in param: continue
        param_name = param.split('=')[0]
        
        for payload in xss_payloads:
            test_params = list(params)
            for i, p in enumerate(test_params):
                if p.startswith(param_name + '='):
                    test_params[i] = f"{param_name}={payload}"
                    break
            
            test_query = '&'.join(test_params)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{test_query}"

            try:
                async with session.get(test_url, timeout=10) as response:
                    content = await response.text()
                    if payload.lower() in content.lower():
                        print(f"[+] XSS Found: {test_url}")
                        return {'url': test_url, 'vuln_type': 'Reflected XSS', 'payload': payload}
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
    return None

async def scan_for_sqli(session, url):
    sqli_payload = "'" 
    if '?' not in url: return None
    
    parsed_url = urlparse(url)
    try:
        params = parsed_url.query.split('&')
    except AttributeError:
        return None
        
    for param in params:
        if '=' not in param: continue
        param_name = param.split('=')[0]
        original_value = param.split('=', 1)[1]
        
        test_url = url.replace(f"{param_name}={original_value}", f"{param_name}={original_value}{sqli_payload}")

        try:
            async with session.get(test_url, timeout=10) as response:
                content = await response.text()
                db_errors = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark"]
                for error in db_errors:
                    if error in content.lower():
                        print(f"[+] SQLi Found: {test_url}")
                        return {'url': test_url, 'vuln_type': 'SQL Injection', 'payload': sqli_payload}
        except (aiohttp.ClientError, asyncio.TimeoutError):
            continue
    return None

async def scan_for_lfi(session, url):
    lfi_payload = "../../../../etc/passwd"
    if '?' not in url: return None
    
    parsed_url = urlparse(url)
    try:
        params = parsed_url.query.split('&')
    except AttributeError:
        return None

    for param in params:
        if '=' not in param: continue
        param_name = param.split('=')[0]
        
        test_params = list(params)
        for i, p in enumerate(test_params):
            if p.startswith(param_name + '='):
                test_params[i] = f"{param_name}={lfi_payload}"
                break
        
        test_query = '&'.join(test_params)
        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{test_query}"

        try:
            async with session.get(test_url, timeout=10) as response:
                content = await response.text()
                if "root:x:0:0" in content:
                    print(f"[+] LFI Found: {test_url}")
                    return {'url': test_url, 'vuln_type': 'Local File Inclusion', 'payload': lfi_payload}
        except (aiohttp.ClientError, asyncio.TimeoutError):
            continue
    return None