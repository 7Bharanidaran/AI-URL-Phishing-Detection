import re

def extract_features(url):

    length = len(url)

    dots = url.count('.')
    hyphens = url.count('-')
    slashes = url.count('/')
    digits = sum(c.isdigit() for c in url)
    questions = url.count('?')
    equals = url.count('=')
    at_symbol = url.count('@')

    ip_pattern = re.compile(r'\d+\.\d+\.\d+\.\d+')
    has_ip = 1 if ip_pattern.search(url) else 0

    https = 1 if "https" in url else 0

    contains_login = 1 if "login" in url.lower() else 0
    contains_verify = 1 if "verify" in url.lower() else 0
    contains_account = 1 if "account" in url.lower() else 0
    contains_bank = 1 if "bank" in url.lower() else 0
    contains_secure = 1 if "secure" in url.lower() else 0
    contains_update = 1 if "update" in url.lower() else 0
    contains_paypal = 1 if "paypal" in url.lower() else 0

    return [
        length,
        dots,
        hyphens,
        slashes,
        digits,
        questions,
        equals,
        at_symbol,
        has_ip,
        https,
        contains_login,
        contains_verify,
        contains_account,
        contains_bank,
        contains_secure,
        contains_update,
        contains_paypal
    ]
