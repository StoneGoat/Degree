import requests
from bs4 import BeautifulSoup

def get_session(login_url, username, password):
    session = requests.Session()
    
    # Fix URL construction to avoid double http://
    if not login_url.startswith('http'):
        full_url = "http://" + login_url
    else:
        full_url = login_url
    
    r1 = session.get(full_url)
    r1.raise_for_status()

    soup = BeautifulSoup(r1.text, "html.parser")
    token = soup.find("input", {"name": "user_token"})["value"]

    payload = {
        "username": username,
        "password": password,
        "user_token": token,
        "Login": "Login"
    }
    
    # Use the same URL for POST
    r2 = session.post(full_url, data=payload)
    r2.raise_for_status()

    if "Login failed" in r2.text:
        raise Exception("login failed")

    return session.cookies.get_dict()

# Only run this test code when directly executing this module
if __name__ == "__main__":
    print(get_dvwa_session(
        "http://vuln.stenaeke.org/login.php",
        "admin",
        "password"
    ))