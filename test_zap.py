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

# Initialize ZAP
zap = ZAPv2(apikey=API_KEY, proxies={'http': PROXY, 'https': PROXY})

def get_dvwa_session(login_url, username, password):
    """Get authenticated DVWA session with CSRF token handling"""
    logger.info(f"Getting authenticated session for {login_url}")
    
    session = requests.Session()
    
    # Get login page to extract CSRF token
    r1 = session.get(login_url)
    r1.raise_for_status()
    
    soup = BeautifulSoup(r1.text, "html.parser")
    token = soup.find("input", {"name": "user_token"})["value"]
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

def verify_csrf_page_with_curl(cookies, target_url):
    """Verify we can access the CSRF page with a curl-like approach"""
    logger.info("Verifying protected page access with direct request...")
    protected_url = f"{target_url}/vulnerabilities/csrf/"
    
    logger.info(f"Sending GET request to: {protected_url}")
    logger.info("With cookies:")
    for name, value in cookies.items():
        logger.info(f"  {name}: {value}")
    
    try:
        # Use requests to directly access the page
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(protected_url, cookies=cookies, headers=headers)
        
        # Log response details
        logger.info(f"Status Code: {response.status_code}")
        
        # Check content
        content_sample = response.text[:200] + ('...' if len(response.text) > 200 else '')
        logger.info(f"Response preview: {content_sample}")
        
        # Verify authentication status
        if response.status_code == 200:
            if "Logout" in response.text and "CSRF" in response.text:
                logger.info("✓ AUTHENTICATION VERIFIED: Successfully accessed protected content")
                return True
            else:
                logger.info("✗ VERIFICATION FAILED: Got 200 response but content doesn't appear to be protected page")
                return False
        else:
            logger.info(f"✗ VERIFICATION FAILED: Got unexpected status code {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"Error during curl verification: {e}")
        return False

def configure_zap_session(session_cookies, target_host, target_url):
    """Configure ZAP to use our authenticated session"""
    try:
        # First access the target URL through ZAP
        logger.info(f"Accessing {target_url} through ZAP...")
        zap.core.access_url(target_url)
        time.sleep(2)
        
        # Get ZAP's site representation
        sites = zap.httpsessions.sites
        logger.info(f"Available sites: {sites}")
        
        site = None
        for s in sites:
            if target_host in s:
                site = s
                logger.info(f"Found matching site: {site}")
                break
                
        if not site:
            logger.error(f"Could not find site {target_host} in ZAP")
            return False
            
        # Add the session tokens (cookies) to ZAP
        for cookie_name in session_cookies.keys():
            logger.info(f"Adding session token: {cookie_name}")
            zap.httpsessions.add_session_token(site, cookie_name)
            
        # Create a new empty session
        session_name = "dvwa-auth-session"
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
        protected_url = f"{target_url}/vulnerabilities/csrf/"
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
                    # Additional check to see if there's a redirect or login form
                    response_body = message.get('responseBody', '')
                    if "Logout" in response_body and "CSRF" in response_body:
                        auth_success = True
                        logger.info("Authentication through ZAP verified! Protected content accessible.")
                        break
                    else:
                        logger.warning("Got 200 status but content verification failed - may be redirected to login")
                        
        if not auth_success:
            logger.error("Authentication verification through ZAP failed")
            return False
            
        return True
        
    except Exception as e:
        logger.error(f"Error configuring ZAP session: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

def save_report(id):
    """Save ZAP scan report"""
    logger.info("Generating XML report...")
    xml = zap.core.xmlreport()
    out_dir = os.path.join(RESULTS_DIR, str(id))
    os.makedirs(out_dir, exist_ok=True)
    report_path = os.path.join(out_dir, "zap.xml")
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(xml)
        
    logger.info(f"Report saved to {report_path}")
    return report_path

def run_authenticated_scan(target, username, password, id, session_cookies=None):
    """Run scan with authentication"""
    try:
        # Ensure URL has protocol
        if not target.startswith('http'):
            target_url = 'http://' + target
        else:
            target_url = target
            
        # Extract hostname from target URL
        if '://' in target_url:
            target_host = target_url.split('://', 1)[1]
        else:
            target_host = target_url
            
        # Remove path if any
        if '/' in target_host:
            target_host = target_host.split('/', 1)[0]
            
        logger.info(f"Starting authenticated scan for {target_url} (host: {target_host})")
        
        # First verify we can access protected pages with the session cookies
        if not session_cookies:
            logger.warning("No session cookies provided, running unauthenticated scan")
            return run_full_scan(target, id)
            
        logger.info(f"Using provided session cookies: {list(session_cookies.keys())}")
        curl_verification = verify_csrf_page_with_curl(session_cookies, target_url)
        
        if not curl_verification:
            logger.error("Direct curl verification failed - check credentials or site accessibility")
            logger.warning("Falling back to unauthenticated scan")
            return run_full_scan(target, id)
            
        # Configure ZAP with the session
        if not configure_zap_session(session_cookies, target_host, target_url):
            logger.error("Failed to configure ZAP session")
            logger.warning("Falling back to unauthenticated scan")
            return run_full_scan(target, id)
            
        # Run spider scan
        logger.info(f"Starting spider scan on {target_url}")
        scan_id = zap.spider.scan(target_url)
        
        # Wait for spider to complete
        while int(zap.spider.status(scan_id)) < 100:
            logger.info(f"Spider progress: {zap.spider.status(scan_id)}%")
            time.sleep(2)
        logger.info("Spider scan completed")
        
        # Run active scan
        logger.info(f"Starting active scan on {target_url}")
        scan_id = zap.ascan.scan(target_url)
        
        # Wait for active scan to complete
        progress = 0
        while progress < 100:
            status = zap.ascan.status(scan_id)
            try:
                progress = int(status)
            except ValueError:
                logger.error(f"Invalid status value: {status}")
                break
                
            logger.info(f"Active scan progress: {progress}%")
            time.sleep(5)
            
        logger.info("Active scan completed")
        
        # Generate and save report
        return save_report(id)
        
    except Exception as e:
        logger.error(f"Error running authenticated scan: {e}")
        import traceback
        logger.error(traceback.format_exc())
        logger.warning("Falling back to unauthenticated scan due to error")
        return run_full_scan(target, id)

def run_full_scan(target, id):
    """Run unauthenticated scan"""
    if target.startswith('http://') or target.startswith('https://'):
        target_url = target
    else:
        target_url = 'http://' + target
        
    logger.info(f"Starting unauthenticated scan for {target_url}")
    
    # Run spider scan
    logger.info(f"Starting spider scan on {target_url}")
    scan_id = zap.spider.scan(target_url)
    
    # Wait for spider to complete
    while int(zap.spider.status(scan_id)) < 100:
        logger.info(f"Spider progress: {zap.spider.status(scan_id)}%")
        time.sleep(2)
    logger.info("Spider scan completed")
    
    # Run active scan
    logger.info(f"Starting active scan on {target_url}")
    scan_id = zap.ascan.scan(target_url)
    
    # Wait for active scan to complete
    progress = 0
    while progress < 100:
        status = zap.ascan.status(scan_id)
        try:
            progress = int(status)
        except ValueError:
            logger.error(f"Invalid status value: {status}")
            break
            
        logger.info(f"Active scan progress: {progress}%")
        time.sleep(5)
        
    logger.info("Active scan completed")
    
    # Generate and save report
    return save_report(id)

# Test function to run the script directly
def test_authenticated_scan():
    """Test function to directly run an authenticated scan"""
    # Test configuration
    target = "vuln.stenaeke.org"
    username = "admin"
    password = "password"
    test_id = "test-" + str(int(time.time()))
    
    # Get authenticated session
    logger.info("=== Starting Test: Authenticated Scan ===")
    
    # Step 1: Get session cookies
    login_url = f"http://{target}/login.php"
    session_cookies = get_dvwa_session(login_url, username, password)
    
    if not session_cookies:
        logger.error("Test failed: Could not get authenticated session")
        return False
    
    logger.info(f"Got session cookies: {session_cookies}")
    
    # Step 2: Run authenticated scan
    report_path = run_authenticated_scan(target, username, password, test_id, session_cookies)
    
    if report_path:
        logger.info(f"Test successful! Report saved to: {report_path}")
        return True
    else:
        logger.error("Test failed: Could not complete scan")
        return False

# Only run the test when this script is executed directly
if __name__ == "__main__":
    print("=== ZAP Authenticated Scan Module Test ===")
    success = test_authenticated_scan()
    print(f"Test {'completed successfully' if success else 'failed'}")