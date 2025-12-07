import os, requests, time, pandas as pd, json
from tranco import Tranco

DATA_DIR = "data"
PHISHTANK_API = "https://data.phishtank.com/data/online-valid.json"


def save_json(df, path):
    """Save dataframe to JSON without escaping slashes."""
    os.makedirs(os.path.dirnamae(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(df.to_dict(orient="records"), f, indent=2, ensure_ascii=False)


def fetch_tranco_legit(limit=500):
    print("🌐 Fetching Tranco legitimate sites...")
    t = Tranco(cache=True)
    top_sites = list(t.list().top(limit))

    # ✅ Include https:// prefix for realism
    full_urls = [f"https://{site}" for site in top_sites]
    df = pd.DataFrame(full_urls, columns=["domain"])
    df["label"] = 0

    save_json(df, os.path.join(DATA_DIR, "legit_data.json"))
    print(f"✅ Saved {len(df)} legitimate URLs.")
    return df


def fetch_phishtank_phish(limit=500, max_retries=5):
    print("⚠️ Fetching live phishing URLs from PhishTank...")
    os.makedirs(DATA_DIR, exist_ok=True)

    for attempt in range(1, max_retries + 1):
        try:
            print(f"Attempt {attempt} of {max_retries}...")
            r = requests.get(PHISHTANK_API, timeout=60)
            r.raise_for_status()
            data = r.json()
            urls = []

            for item in data:
                url = item.get("url")
                if not url:
                    continue
                if not url.startswith(("http://", "https://")):
                    url = "http://" + url
                urls.append(url.lower())

            df = pd.DataFrame({"domain": sorted(list(set(urls)))[:limit]})
            df["label"] = 1

            save_json(df, os.path.join(DATA_DIR, "phishing_data.json"))
            print(f"✅ Successfully fetched {len(df)} phishing URLs.")
            return df

        except requests.exceptions.HTTPError as e:
            print(f"❌ HTTP Error: {e}")
        except requests.exceptions.RequestException as e:
            print(f"❌ Network Error: {e}")
        except Exception as e:
            print(f"❌ Unexpected Error: {e}")

        if attempt < max_retries:
            print("⏳ Retrying in 5 seconds...")
            time.sleep(5)
        else:
            print("❌ All retry attempts failed.")
            return None  # ✅ Return None instead of raising

