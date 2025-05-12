import requests

def get_session_cookie(login_url, payload):
    session = requests.Session()
    resp = session.post(login_url, data=payload)
    resp.raise_for_status()

    return session.cookies.get_dict()
