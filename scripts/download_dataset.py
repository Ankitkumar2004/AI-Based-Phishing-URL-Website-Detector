import os
import sys
import random
import urllib.request
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DATA_DIR = os.path.join(BASE_DIR, "data", "raw")
DATASET_PATH = os.path.join(RAW_DATA_DIR, "urls_dataset.csv")

OPENPHISH_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"


def fetch_openphish_urls():
    print("[*] Fetching OpenPhish feed...")
    phish_urls = []
    try:
        req = urllib.request.Request(OPENPHISH_URL, headers={"User-Agent": "PhishingDetector/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            lines = resp.read().decode("utf-8", errors="ignore").strip().splitlines()
            for line in lines:
                u = line.strip()
                if u.startswith("http://") or u.startswith("https://"):
                    phish_urls.append(u)
        print(f"[+] Got {len(phish_urls)} URLs from OpenPhish feed")
    except Exception as e:
        print(f"[-] OpenPhish feed unavailable ({e}), using benchmark dataset")
    return phish_urls


def generate_curated_benchmark():
    random.seed(42)

    legit_domains = [
        "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
        "yahoo.com", "reddit.com", "netflix.com", "linkedin.com", "microsoft.com",
        "apple.com", "twitter.com", "instagram.com", "github.com", "stackoverflow.com",
        "bing.com", "adobe.com", "wordpress.org", "mozilla.org", "cloudflare.com",
        "dropbox.com", "slack.com", "spotify.com", "cnn.com", "nytimes.com",
        "bbc.co.uk", "theguardian.com", "nih.gov", "cdc.gov", "europa.eu",
        "medium.com", "salesforce.com", "zoom.us", "quora.com", "vimeo.com",
        "imdb.com", "pinterest.com", "shopify.com", "ebay.com", "walmart.com",
        "target.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
        "paypal.com", "stripe.com", "intuit.com", "irs.gov", "usps.com",
        "ups.com", "fedex.com", "oracle.com", "ibm.com", "cisco.com",
        "intel.com", "amd.com", "nvidia.com", "samsung.com", "sony.com",
        "gitlab.com", "bitbucket.org", "apache.org", "python.org", "nodejs.org",
        "docker.com", "kubernetes.io", "linux.org", "ubuntu.com", "debian.org",
        "mit.edu", "stanford.edu", "harvard.edu", "ox.ac.uk", "cam.ac.uk",
        "berkeley.edu", "columbia.edu", "cmu.edu", "princeton.edu", "cornell.edu",
        "booking.com", "tripadvisor.com", "airbnb.com", "expedia.com", "uber.com",
        "weather.com", "accuweather.com", "espn.com", "nba.com", "fifa.com"
    ]

    legit_paths = [
        "", "index.html", "about-us", "contact", "support", "help/center", "faq",
        "products", "solutions/cloud", "enterprise", "docs/api/v2", "documentation/guide",
        "blog/2024/02/release-notes", "news/security-bulletin", "articles/overview",
        "press-release", "terms", "privacy", "careers", "investor-relations",
        "community", "explore", "downloads", "status", "developers",
        "learn/tutorials/quickstart", "catalog/view", "search?q=machine+learning+models",
        "search?q=cybersecurity+training&page=2", "item/detail?id=928471&source=home",
        "gallery/view?cat=tech", "portal/public/resource", "whitepapers/cloud-security.pdf"
    ]

    legit_urls = set()
    while len(legit_urls) < 5000:
        domain = random.choice(legit_domains)
        path = random.choice(legit_paths)
        scheme = "https" if random.random() > 0.05 else "http"
        sub = ""
        if random.random() < 0.40:
            sub = random.choice(["www.", "app.", "api.", "m.", "blog.", "docs.", "dev.", "support.", "portal."])
        url = f"{scheme}://{sub}{domain}/{path}" if path else f"{scheme}://{sub}{domain}/"
        if random.random() < 0.25 and "?" not in url:
            k = random.choice(["ref", "source", "lang", "tab", "filter", "view"])
            v = random.choice(["dashboard", "en-us", "popular", "grid", "main", "nav"])
            url = f"{url}?{k}={v}"
        legit_urls.add(url)

    phishing_brands = [
        "paypal", "appleid", "microsoft365", "netflix-login", "chase-bank",
        "wellsfargo-verify", "bankofamerica-online", "google-drive-share", "amazon-security",
        "instagram-help", "facebook-security", "whatsapp-verify", "dhl-tracking-express",
        "fedex-package", "usps-redelivery", "irs-refund", "metamask-wallet",
        "coinbase-auth", "binance-security", "icloud-findmy", "office365-login",
        "docusign-document", "dropbox-share", "yahoo-mail-verify", "steam-community-login"
    ]

    suspicious_tlds = [
        ".xyz", ".top", ".club", ".work", ".click", ".link", ".online", ".site",
        ".buzz", ".loan", ".date", ".bid", ".win", ".stream", ".gq", ".ml", ".cf", ".tk"
    ]

    phishing_keywords = [
        "login", "signin", "verify", "verification", "account", "secure",
        "update", "password", "bank", "wallet", "confirm", "authentication",
        "free", "bonus", "claim", "billing", "recovery", "unlock", "alert"
    ]

    shorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy"]

    phish_urls = set()

    # Incorporate live OpenPhish URLs first if available
    live_openphish = fetch_openphish_urls()
    for u in live_openphish:
        phish_urls.add(u)

    while len(phish_urls) < 5000:
        attack_type = random.choices(
            ["brand_subdomain", "raw_ip", "tld_abuse", "shortener_redirect", "keyword_stuffing", "punycode_typo", "path_credential_harvest"],
            weights=[30, 15, 20, 10, 15, 5, 5],
            k=1
        )[0]

        brand = random.choice(phishing_brands)
        kw1 = random.choice(phishing_keywords)
        kw2 = random.choice(phishing_keywords)
        scheme = "https" if random.random() < 0.6 else "http"

        if attack_type == "brand_subdomain":
            random_host = f"{brand}-session{random.randint(10,999)}"
            tld = random.choice(suspicious_tlds + [".com", ".net", ".info"])
            sub = random.choice(["login.", "secure.", "accounts.", "myaccount.", "support-team.", "auth."])
            url = f"{scheme}://{sub}{random_host}{tld}/{kw1}-portal/{kw2}.php?session={random.randint(100000, 9999999)}&client=secure"

        elif attack_type == "raw_ip":
            ip = f"{random.randint(11,210)}.{random.randint(10,250)}.{random.randint(1,250)}.{random.randint(1,254)}"
            port = f":{random.choice([8080, 8888, 8000, 4443, 3000])}" if random.random() < 0.35 else ""
            url = f"http://{ip}{port}/{brand}/{kw1}.html?id={random.randint(1000,9999)}"

        elif attack_type == "tld_abuse":
            tld = random.choice(suspicious_tlds)
            host = f"{brand}-{kw1}{random.randint(1,99)}{tld}"
            url = f"{scheme}://{host}/customer-service/{kw2}.php"

        elif attack_type == "shortener_redirect":
            short = random.choice(shorteners)
            slug = f"{brand[:4]}{random.randint(1000,99999)}"
            url = f"https://{short}/{slug}"

        elif attack_type == "keyword_stuffing":
            hyphen_domain = f"{brand}-{kw1}-service{random.choice(suspicious_tlds)}"
            url = f"{scheme}://{hyphen_domain}/user/{kw2}/confirm-identity?auth_token={random.randint(10000,99999)}&redirect=bank&user=active"

        elif attack_type == "punycode_typo":
            puny = f"xn--{brand[:5]}-{random.randint(10,99)}a.com"
            url = f"http://{puny}/login/checkpoint.html"

        else:
            domain = f"{brand}-verification.org"
            url = f"{scheme}://{domain}/webscr?cmd=_login-run&dispatch={random.randint(10000,99999)}&email=user{random.randint(1,500)}@mail.com"

        phish_urls.add(url)

    records = []
    for u in list(legit_urls)[:5000]:
        records.append({"url": u, "label": 0})
    for u in list(phish_urls)[:5000]:
        records.append({"url": u, "label": 1})

    random.shuffle(records)
    df = pd.DataFrame(records)
    os.makedirs(RAW_DATA_DIR, exist_ok=True)
    df.to_csv(DATASET_PATH, index=False)
    print(f"[+] Saved {len(df)} URLs to {DATASET_PATH}")
    print(f"    Legitimate: {len(df[df['label'] == 0])}")
    print(f"    Phishing:   {len(df[df['label'] == 1])}")


def main():
    os.makedirs(RAW_DATA_DIR, exist_ok=True)
    generate_curated_benchmark()


if __name__ == "__main__":
    main()
