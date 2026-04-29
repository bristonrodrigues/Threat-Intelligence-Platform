from urllib.parse import urlparse


def extract_features(url):

    parsed = urlparse(url)

    features = {

        "url_length": len(url),

        "valid_url": 1 if parsed.scheme and parsed.netloc else 0,

        "at_symbol": 1 if "@" in url else 0,

        "sensitive_words_count": sum(
            word in url.lower()
            for word in [
                "login",
                "secure",
                "account",
                "bank",
                "verify",
                "update"
            ]
        ),

        "path_length": len(parsed.path),

        "isHttps": 1 if parsed.scheme == "https" else 0,

        "nb_dots": url.count("."),

        "nb_hyphens": url.count("-"),

        "nb_and": url.count("&"),

        "nb_or": url.count("|"),

        "nb_www": 1 if "www" in url else 0,

        "nb_com": 1 if ".com" in url else 0,

        "nb_underscore": url.count("_")
    }

    return features