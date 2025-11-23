from random import shuffle

import requests

from src.services.neural_net.models import DomainDataset
from src.services.neural_net.utils import (
    filter_unknown_chars_from_domain,
)

TIMEOUT = 30
YOYO_ADSERVERS_URL = "https://pgl.yoyo.org/adservers/serverlist.php"


def generate_training_dataset(
    blacklist: set[str], whitelist: set[str], allowed_chars: str
) -> DomainDataset:
    """Generate a labeled training dataset from domain whitelists and blacklists.

    Args:
        blacklist (set[str]): Malicious/suspicious domains. Will be labeled as 1.
        whitelist (set[str]): Safe domains. Will be labeled as 0.
        allowed_chars (str): Characters to keep in domain names.

    Returns:
        DomainDataset: A shuffled dataset with domains and labels.

    """
    if not isinstance(whitelist, set) or not all(
        isinstance(_domain_whitelist, str) for _domain_whitelist in whitelist
    ):
        raise TypeError("whitelist must be a set of strings")
    if not isinstance(blacklist, set) or not all(
        isinstance(_domain_blacklist, str) for _domain_blacklist in blacklist
    ):
        raise TypeError("blacklist must be a set of strings")
    if not isinstance(allowed_chars, str):
        raise TypeError("allowed_chars must be a string")
    if not allowed_chars:
        raise ValueError("allowed_chars must not be empty")

    _whitelist_filtered = [
        filter_unknown_chars_from_domain(d, allowed_chars) for d in whitelist
    ]
    _blacklist_filtered = [
        filter_unknown_chars_from_domain(d, allowed_chars) for d in blacklist
    ]
    dataset = [{"domain": d, "label": 0} for d in _whitelist_filtered]
    dataset.extend([{"domain": d, "label": 1} for d in _blacklist_filtered])
    shuffle(dataset)
    domains, labels = zip(*[(item["domain"], item["label"]) for item in dataset])

    return DomainDataset(domains=list(domains), labels=list(labels))


def generate_testing_dataset() -> DomainDataset:
    _testing_datasets = [
        {"domain": "github.com", "label": 0},
        {"domain": "stackoverflow.com", "label": 0},
        {"domain": "wikipedia.org", "label": 0},
        {"domain": "netflix.com", "label": 0},
        {"domain": "apple.com", "label": 0},
        {"domain": "api.fitbit.com", "label": 0},
        {"domain": "signal.org", "label": 0},
        {"domain": "reddit.com", "label": 0},
        {"domain": "linkedin.com", "label": 0},
        {"domain": "nytimes.com", "label": 0},
        {"domain": "weather.apple.com", "label": 0},
        {"domain": "openai.com", "label": 0},
        {"domain": "python.org", "label": 0},
        {"domain": "mozilla.org", "label": 0},
        {"domain": "cnn.com", "label": 0},
        {"domain": "theverge.com", "label": 0},
        {"domain": "medium.com", "label": 0},
        {"domain": "spotify.com", "label": 0},
        {"domain": "dropbox.com", "label": 0},
        {"domain": "slack.com", "label": 0},
        {"domain": "zoom.us", "label": 0},
        {"domain": "microsoft.com", "label": 0},
        {"domain": "aws.amazon.com", "label": 0},
        {"domain": "docs.google.com", "label": 0},
        {"domain": "calendar.google.com", "label": 0},
        {"domain": "connect.facebook.net", "label": 0},
        {
            "domain": "firebaseinstallations.googleapis.com",
            "label": 0,
        },
        {"domain": "push-service.push.apple.com", "label": 0},
        {"domain": "static.addtoany.com", "label": 1},
        {"domain": "cdn.doubleclick.net", "label": 1},
        {"domain": "ads.pubmatic.com", "label": 1},
        {"domain": "track.adform.net", "label": 1},
        {"domain": "ad.centrum.cz", "label": 1},
        {"domain": "ad4mat.com", "label": 1},
        {"domain": "30ads.com", "label": 1},
        {"domain": "ads.yahoo.com", "label": 1},
        {"domain": "ads.twitter.com", "label": 1},
        {"domain": "marketing.microsoft.com", "label": 1},
        {"domain": "adnami.io", "label": 1},
        {"domain": "adnet.de", "label": 1},
        {"domain": "app-measurement.com", "label": 1},
    ]
    return DomainDataset(
        domains=[_item["domain"] for _item in _testing_datasets],
        labels=[_item["label"] for _item in _testing_datasets],
    )


def get_latest_adservers(
    url: str = YOYO_ADSERVERS_URL,
) -> set:
    """Fetch the latest adserver domains from YoYo's Peter Lowe blocklist.
    Returns a set of domains.
    """
    adservers = set()
    try:
        response = requests.get(url, timeout=TIMEOUT)
        response.raise_for_status()
        for _line in response.text.splitlines():
            _line = _line.strip()
            if _line.startswith("127.0.0.1"):
                parts = _line.split()
                if len(parts) == 2:
                    adservers.add(parts[1])
    finally:
        return adservers
