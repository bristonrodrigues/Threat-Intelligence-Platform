from urllib.parse import urlparse
import re


def extract_features(url):

    parsed = urlparse(url)

    features = {

        "url_length": len(url),

        "valid_url": 1 if parsed.scheme else 0,

        "at_symbol": 1 if "@" in url else 0,

        "sensitive_words_count": sum(
            word in url.lower()
            for word in ["login", "secure", "bank", "verify", "account", "update"]
        ),

        "path_length": len(parsed.path),

        "isHttps": 1 if parsed.scheme == "https" else 0,

        "nb_dots": url.count("."),

        "nb_hyphens": url.count("-"),

        "nb_and": url.count("&"),

        "nb_or": url.count("|"),

        "nb_www": url.lower().count("www"),

        "nb_com": url.lower().count(".com"),

        "nb_underscore": url.count("_"),

        # 🔥 ADD THESE (VERY IMPORTANT)
        "nb_digits": sum(c.isdigit() for c in url),

        "nb_slash": url.count("/"),

        "nb_question": url.count("?"),

        "nb_equal": url.count("="),

        "hostname_length": len(parsed.netloc),

        "has_ip": 1 if re.match(r"\d+\.\d+\.\d+\.\d+", parsed.netloc) else 0
    }

    return features