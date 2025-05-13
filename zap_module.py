import time
import requests
import logging
import os
from zapv2 import ZAPv2
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Config
API_KEY = '126gp7bpv1rfgf5aqbious8cpb'
PROXY = 'http://localhost:8080'
RESULTS_DIR = 'scan_results'

zap = ZAPv2(apikey=API_KEY, proxies={'http': PROXY, 'https': PROXY})

def get_dvwa_session(target_url, username, password):
    """Get authenticated DVWA session with CSRF token handling"""
    logger.info(f"Attempting to get authenticated session directly from {target_url}")
    
    # Ensure URL has protocol
    if not target_url.startswith('http'):
        target_url = 'http://' + target_url
    
    # Construct login URL
    login_url = f"{target_url.rstrip('/')}/login.php"
    logger.info(f"Using login URL: {login_url}")
    
    session = requests.Session()
    
    # Get login page to extract CSRF token
    try:
        r1 = session.get(login_url)
        r1.raise_for_status()
        
        soup = BeautifulSoup(r1.text, "html.parser")
        token_input = soup.find("input", {"name": "user_token"})
        
        if not token_input:
            logger.error("Could not find CSRF token in login page")
            return None
            
        token = token_input["value"]
        logger.info(f"Found CSRF token: {token}")
        
        # Submit login with credentials and token
        payload = {
            "username": username,
            "password": password,
            "user_token": token,
            "Login": "Login"
        }
        
        r2 = session.post(login_url, data=payload)
        r2.raise_for_status()
        
        if "Login failed" in r2.text:
            logger.error("DVWA login failed - check credentials")
            return None
        
        cookies = session.cookies.get_dict()
        logger.info(f"Login successful! Cookies: {cookies}")
        return cookies
        
    except Exception as e:
        logger.error(f"Error in get_dvwa_session: {e}")
        return None

def verify_dvwa_authentication(cookies, target_url):
    """Verify DVWA authentication by checking available pages"""
    logger.info("Verifying DVWA authentication...")
    
    # Ensure URL has protocol
    if not target_url.startswith('http'):
        target_url = 'http://' + target_url
    
    # Try different possible paths for protected content
    paths_to_try = [
        "/vulnerabilities/csrf/",
        "/security.php",
        "/index.php",
        "/"
    ]
    
    for path in paths_to_try:
        url = f"{target_url.rstrip('/')}{path}"
        logger.info(f"Trying URL: {url}")
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(url, cookies=cookies, headers=headers)
            
            logger.info(f"Status: {response.status_code}, Content-Type: {response.headers.get('Content-Type')}")
            
            # Check for logged-in indicators
            if response.status_code == 200:
                # Look for common DVWA authenticated page elements
                if "Logout" in response.text and "DVWA Security" in response.text:
                    logger.info(f"✓ Authentication verified at {url}")
                    return url
                elif "Welcome to Damn Vulnerable Web Application" in response.text and "Logout" in response.text:
                    logger.info(f"✓ Authentication verified at {url}")
                    return url
                elif "DVWA" in response.text and "Logout" in response.text:
                    logger.info(f"✓ Authentication verified at {url}")
                    return url
                else:
                    logger.info(f"Page at {url} doesn't appear to be authenticated (no Logout link)")
        except Exception as e:
            logger.error(f"Error requesting {url}: {e}")
    
    logger.error("All authentication verification attempts failed")
    return False

def extract_domain(url):
    """Extract domain from URL more reliably"""
    if not url.startswith('http'):
        url = 'http://' + url
        
    from urllib.parse import urlparse
    parsed_url = urlparse(url)
    return parsed_url.netloc

def configure_zap_session(session_cookies, target_url):
    """Configure ZAP to use our authenticated session"""
    try:
        # Extract domain properly
        domain = extract_domain(target_url)
        logger.info(f"Using domain: {domain}")
        
        # First access the target URL through ZAP
        logger.info(f"Accessing {target_url} through ZAP...")
        zap.core.access_url(target_url)
        time.sleep(2)
        
        # Get ZAP's site representation
        sites = zap.httpsessions.sites
        logger.info(f"Available sites: {sites}")
        
        # Look for site match
        site = None
        for s in sites:
            if domain in s:
                site = s
                logger.info(f"Found matching site: {site}")
                break
                
        if not site:
            logger.error(f"Could not find site {domain} in ZAP")
            return False
            
        # Add the session tokens (cookies) to ZAP
        for cookie_name in session_cookies.keys():
            logger.info(f"Adding session token: {cookie_name}")
            zap.httpsessions.add_session_token(site, cookie_name)
            
        # Create a new empty session
        session_name = "authenticated-session"
        logger.info(f"Creating new session: {session_name}")
        zap.httpsessions.create_empty_session(site, session_name)
        
        # Set the values for each session token
        for cookie_name, cookie_value in session_cookies.items():
            logger.info(f"Setting token {cookie_name}={cookie_value}")
            zap.httpsessions.set_session_token_value(
                site=site,
                session=session_name,
                sessiontoken=cookie_name,
                tokenvalue=cookie_value
            )
            
        # Set our session as active
        logger.info(f"Setting {session_name} as active session")
        zap.httpsessions.set_active_session(site, session_name)
        
        # Verify authentication works through ZAP
        logger.info("Verifying authentication through ZAP...")
        
        # Use the index.php page for verification
        protected_url = f"{target_url.rstrip('/')}/index.php"
        zap.core.access_url(protected_url)
        time.sleep(2)
        
        # Check if access was successful
        messages = zap.core.messages()
        auth_success = False
        
        for message in reversed(messages):
            if 'requestHeader' in message and protected_url in message['requestHeader']:
                response_header = message.get('responseHeader', '')
                status_code = response_header.split(' ')[1] if ' ' in response_header else 'unknown'
                
                logger.info(f"Response code for protected page through ZAP: {status_code}")
                
                if status_code == '200':
                    # Check for successful authentication indicators
                    response_body = message.get('responseBody', '')
                    if "Logout" in response_body:
                        auth_success = True
                        logger.info("Authentication through ZAP verified!")
                        break
                        
        if not auth_success:
            logger.error("Authentication verification through ZAP failed")
            return False
            
        return True
        
    except Exception as e:
        logger.error(f"Error configuring ZAP session: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

def spider_scan(target_url):
    """Run spider scan"""
    logger.info(f"Starting Spider scan on {target_url}")
    scan_id = zap.spider.scan(target_url)
    time.sleep(2)

    # Poll the status until the scan completes
    while int(zap.spider.status(scan_id)) < 100:
        progress = zap.spider.status(scan_id)
        logger.info(f"Spider progress: {progress}%")
        time.sleep(2)
    logger.info("Spider scan completed.")

def active_scan(target_url):
    """Run active scan"""
    logger.info(f"Starting Active scan on {target_url}")
    scan_id = zap.ascan.scan(target_url)
    time.sleep(2)

    # Poll the status until the scan completes
    while True:
        status_str = zap.ascan.status(scan_id)
        try:
            status = int(status_str)
        except ValueError:
            logger.error(f"Active scan status returned an unexpected value: '{status_str}'. Exiting scan loop.")
            break
        if status >= 100:
            break
        logger.info(f"Active scan progress: {status}%")
        time.sleep(5)
    logger.info("Active scan completed.")

def save_report(id):
    """Save ZAP scan report"""
    logger.info("Generating XML report...")
    xml = zap.core.xmlreport(apikey=API_KEY)
    out_dir = os.path.join(RESULTS_DIR, str(id))
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"zap.xml")
    with open(path, 'w', encoding='utf-8') as f:
        f.write(xml)
    logger.info(f"Saved ZAP XML report to {path}")
    return path

def run_authenticated_scan(target, username, password, id, session_cookies=None):
    """Run scan with authentication"""
    try:
        logger.info(f"Starting authenticated scan for {target}")
        
        # Ensure URL has protocol
        if not target.startswith('http'):
            target_url = 'http://' + target
        else:
            target_url = target
        
        # First try with provided cookies
        if session_cookies:
            logger.info(f"Using provided session cookies: {list(session_cookies.keys())}")
            
            # Verify authentication with the provided cookies
            auth_verified = verify_dvwa_authentication(session_cookies, target_url)
            
            if auth_verified:
                logger.info("External cookies verified successfully")
                
                # Configure ZAP session
                if configure_zap_session(session_cookies, target_url):
                    # Run authenticated scan
                    spider_scan(target_url)
                    active_scan(target_url)
                    return save_report(id)
                else:
                    logger.error("Failed to configure ZAP with external cookies")
            else:
                logger.warning("Provided cookies failed verification")
        
        # If we're here, either:
        # 1. No cookies were provided, or
        # 2. Provided cookies failed verification, or
        # 3. ZAP configuration failed
        
        # Try direct authentication
        if username and password:
            logger.info(f"Attempting direct authentication with username '{username}'")
            direct_cookies = get_dvwa_session(target_url, username, password)
            
            if direct_cookies and verify_dvwa_authentication(direct_cookies, target_url):
                logger.info("Direct authentication successful")
                
                # Configure ZAP
                if configure_zap_session(direct_cookies, target_url):
                    # Run authenticated scan
                    spider_scan(target_url)
                    active_scan(target_url)
                    return save_report(id)
                else:
                    logger.error("Failed to configure ZAP with direct authentication cookies")
        
        # If all authentication attempts failed, fall back to unauthenticated scan
        logger.warning("All authentication attempts failed. Falling back to unauthenticated scan.")
        return run_full_scan(target, id)
        
    except Exception as e:
        logger.error(f"Error during authenticated scan: {e}")
        import traceback
        logger.error(traceback.format_exc())
        logger.warning("Falling back to unauthenticated scan")
        return run_full_scan(target, id)

def run_full_scan(target, id):
    """Run unauthenticated scan (previous functionality)"""
    if target.startswith('http://') or target.startswith('https://'):
        target_url = target
    else:
        target_url = 'http://' + target
        
    logger.info(f"Starting unauthenticated scan for {target_url}")
    spider_scan(target_url)
    active_scan(target_url)
    report_path = save_report(id)
    return report_path