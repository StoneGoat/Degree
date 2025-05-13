import requests
from bs4 import BeautifulSoup

def get_session(login_url, username, password):
    session = requests.Session()

    r1 = session.get(login_url)
    r1.raise_for_status()

    soup = BeautifulSoup(r1.text, "html.parser")
    token = soup.find("input", {"name": "user_token"})["value"]

    payload = {
        "username":    username,
        "password":    password,
        "user_token":  token,
        "Login":       "Login"
    }
    r2 = session.post(login_url, data=payload)
    r2.raise_for_status()

    if "Login failed" in r2.text:
        raise Exception("login failed")

    return session.cookies.get_dict()