import requests
import urllib.request

KEV_URL = "https://example.invalid/kev.json"


def fetch_kev():
    # ruleid: requests-without-timeout
    return requests.get(KEV_URL)


def post_epss(payload):
    # ruleid: requests-without-timeout
    return requests.post(KEV_URL, json=payload)


def fetch_via_session(session):
    # ruleid: requests-without-timeout
    return session.get(KEV_URL)


def fetch_urllib():
    # ruleid: requests-without-timeout
    return urllib.request.urlopen(KEV_URL)


# --- must NOT fire ----------------------------------------------------------

def fetch_kev_bounded():
    # ok: requests-without-timeout
    return requests.get(KEV_URL, timeout=(3.05, 27))


def post_bounded(payload):
    # ok: requests-without-timeout
    return requests.post(KEV_URL, json=payload, timeout=10)


def session_bounded(session):
    # ok: requests-without-timeout
    return session.get(KEV_URL, timeout=5)
