import hashlib
import json
import logging

log = logging.getLogger(__name__)


def sha256_hex(text):
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def report_leak(result):
    secret = result["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
    # ruleid: secret-reaches-sink
    log.info("found secret %s", secret)


def dump_finding(result, out):
    api_key = result["snippet"]["text"]
    # ruleid: secret-reaches-sink
    out.write(api_key)


def print_token(response):
    access_token = response["snippet"]
    # ruleid: secret-reaches-sink
    print(access_token)


def persist(result, path):
    password = result["snippet"]["text"]
    # ruleid: secret-reaches-sink
    path.write_text(password)


# --- must NOT fire: hashed or redacted at the boundary ----------------------

def report_hashed(result):
    secret = result["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
    # ok: secret-reaches-sink
    log.info("found secret %s", sha256_hex(secret))


def dump_digest(result, out):
    api_key = result["snippet"]["text"]
    # ok: secret-reaches-sink
    out.write(hashlib.sha256(api_key.encode()).hexdigest())


def dump_non_secret(result, out):
    rule_id = result["ruleId"]
    # ok: secret-reaches-sink
    out.write(rule_id)
