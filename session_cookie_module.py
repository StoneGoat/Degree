import requests
import nikto_module

def get_session_cookie(login_url, username, password):
    credentials = {
    "username": username,
    "password": password
    }
    session = requests.Session()
    resp = session.post(login_url, data=credentials)
    resp.raise_for_status()

    return session.cookies.get_dict()
