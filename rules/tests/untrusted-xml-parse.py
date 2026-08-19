import xml.etree.ElementTree as ET
import defusedxml.ElementTree
import sys, os


def parse_nessus_xml(path):
    # ruleid: untrusted-xml-parse
    tree = ET.parse(path)
    return tree.getroot()


def parse_from_argv():
    # ruleid: untrusted-xml-parse
    return ET.parse(sys.argv[1])


def parse_from_env():
    # ruleid: untrusted-xml-parse
    return ET.parse(os.environ["SCAN_EXPORT"])


def parse_scanner_body(body):
    # ruleid: untrusted-xml-parse
    return ET.fromstring(body)


# --- must NOT fire: this is the difference from bandit's B314 ---------------

def parse_bundled_constant():
    # ok: untrusted-xml-parse
    return ET.parse("schemas/builtin.xml")


def parse_safely(path):
    # ok: untrusted-xml-parse
    return defusedxml.ElementTree.parse(path)
