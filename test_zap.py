import time
import requests
from zapv2 import ZAPv2
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Config
API_KEY = '126gp7bpv1rfgf5aqbious8cpb'
PROXY = 'http://localhost:8080'
TARGET_DOMAIN = 'vuln.stenaeke.org'  # Base domain without protocol
USERNAME = 'admin'  # Replace with actual username
PASSWORD = 'password'  # Replace with actual password

# Initialize ZAP
zap = ZAPv2(apikey=API_KEY, proxies={'http': PROXY, 'https': PROXY})

def test_direct_login():
    """Test login directly without ZAP to verify credentials"""
    login_url = f"http://{TARGET_DOMAIN}/login.php"
    logger.info(f"Testing direct login to {login_url}")
    
    try:
        session = requests.Session()
        credentials = {
            "username": USERNAME,
            "password": PASSWORD
        }
        
        response = session.post(login_url, data=credentials)
        response.raise_for_status()
        
        cookies = session.cookies.get_dict()
        logger.info(f"Login response status: {response.status_code}")
        logger.info(f"Cookies received: {cookies}")
        
        if "PHPSESSID" in cookies:
            logger.info("Login appears successful based on cookies")
            return cookies
        else:
            logger.warning("Login might have failed - no session cookie found")
            logger.debug(f"Response content: {response.text[:500]}...")
            return None
    except Exception as e:
        logger.error(f"Login failed with error: {e}")
        return None

def configure_zap_authentication(session_cookies):
    """Configure ZAP to use the authenticated session"""
    if not session_cookies:
        logger.error("No session cookies available to configure ZAP")
        return False
    
    try:
        # Access the target site through ZAP proxy first
        target_url = f"http://{TARGET_DOMAIN}"
        logger.info(f"Accessing {target_url} through ZAP proxy")
        zap.core.access_url(target_url)
        time.sleep(2)
        
        # Set the session cookies in ZAP using the correct parameter names
        for cookie_name, cookie_value in session_cookies.items():
            logger.info(f"Setting cookie in ZAP: {cookie_name}={cookie_value} for domain {TARGET_DOMAIN}")
            zap.httpsessions.set_session_token_value(
                site=target_url,
                session="Default Context", 
                sessiontoken=cookie_name,  # Changed from 'token' to 'sessiontoken'
                tokenvalue=cookie_value,   # Changed from 'value' to 'tokenvalue'
                apikey=API_KEY
            )
        
        # Verify the authentication worked
        logger.info("Verifying authentication in ZAP")
        
        # Access a protected page
        protected_url = f"http://{TARGET_DOMAIN}/vulnerabilities/csrf/"  # Let's try a specific DVWA page
        zap.core.access_url(protected_url)
        time.sleep(2)
        
        # Check for authentication success
        # For DVWA, being logged in means we can access pages without being redirected to login
        try:
            # Get the last few messages
            messages = zap.core.messages(baseurl=target_url)
            authenticated = False
            
            # Print some debug info about the messages
            if messages:
                logger.info(f"Found {len(messages)} messages")
                for idx, message in enumerate(messages[-3:]):  # Look at last 3 messages
                    logger.info(f"Message {idx}: URL={message.get('requestHeader', '').split(' ')[1] if 'requestHeader' in message else 'unknown'}")
                    logger.info(f"Response code: {message.get('responseHeader', '').split(' ')[1] if 'responseHeader' in message else 'unknown'}")
                    
                    # If we see a 200 response to a protected page, we're likely authenticated
                    if '/vulnerabilities/' in message.get('requestHeader', '') and '200 OK' in message.get('responseHeader', ''):
                        authenticated = True
            else:
                logger.warning("No messages found in ZAP history")
            
            if authenticated:
                logger.info("Authentication verification successful")
                return True
            else:
                logger.error("Authentication verification failed - couldn't access protected content")
                return False
                
        except Exception as e:
            logger.error(f"Error checking authentication status: {e}")
            return False
            
    except Exception as e:
        logger.error(f"Error configuring ZAP authentication: {e}")
        return False

def test_zap_login():
    """Main function to test ZAP login functionality"""
    logger.info("=== Starting ZAP Login Test ===")
    
    # Test direct login first
    logger.info("Step 1: Testing direct login")
    session_cookies = test_direct_login()
    
    if not session_cookies:
        logger.error("Direct login failed. Cannot proceed with ZAP testing.")
        return False
    
    # Configure ZAP with the session
    logger.info("Step 2: Configuring ZAP with authenticated session")
    auth_success = configure_zap_authentication(session_cookies)
    
    if auth_success:
        logger.info("ZAP login test PASSED - Authentication working")
        return True
    else:
        logger.error("ZAP login test FAILED - Authentication not working")
        return False

if __name__ == "__main__":
    success = test_zap_login()
    print(f"Login test {'successful' if success else 'failed'}")