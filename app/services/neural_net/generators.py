from random import shuffle

from app.services.neural_net.models import DomainDataset
from app.services.neural_net.utils import filter_unknown_chars_from_domain


def generate_training_dataset(
    blacklist: set[str], whitelist: set[str], allowed_chars: str
) -> DomainDataset:
    """
    Generate a labeled training dataset from domain whitelists and blacklists.
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
        {"domain": "brave.com", "label": 0},
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
        {"domain": "ads.example.net", "label": 1},
        {"domain": "tracker.example.com", "label": 1},
        {"domain": "clickbait.site", "label": 1},
        {"domain": "popups.badsite.org", "label": 1},
        {"domain": "adserver.malicious.com", "label": 1},
        {"domain": "promo.example.net", "label": 1},
        {"domain": "analytics.spam.com", "label": 1},
        {"domain": "offer.scam.net", "label": 1},
        {"domain": "banner.ads.org", "label": 1},
        {"domain": "malware.example.com", "label": 1},
        {"domain": "push.example.net", "label": 1},
        {"domain": "suspicious.api.com", "label": 1},
        {"domain": "affiliate.tracker.com", "label": 1},
        {"domain": "ads.badexample.org", "label": 1},
        {"domain": "adclick.example.com", "label": 1},
        {"domain": "adredirect.net", "label": 1},
        {"domain": "popunder.site", "label": 1},
        {"domain": "marketing.spam.net", "label": 1},
        {"domain": "trackingpixel.example.org", "label": 1},
        {"domain": "pushnotification.bad.com", "label": 1},
        {"domain": "promoapi.example.net", "label": 1},
        {"domain": "adtrack.example.org", "label": 1},
        {"domain": "badapi.example.com", "label": 1},
        {"domain": "adnetwork.example.net", "label": 1},
        {"domain": "offers.example.org", "label": 1},
    ]
    return DomainDataset(
        domains=[_item["domain"] for _item in _testing_datasets],
        labels=[_item["label"] for _item in _testing_datasets],
    )


def generate_bad_urls() -> set:
    return {
        "doubleclick.net",
        "adnxs.com",
        "adsrvr.org",
        "rubiconproject.com",
        "openx.net",
        "pubmatic.com",
        "criteo.com",
        "appnexus.com",
        "adroll.com",
        "outbrain.com",
        "taboola.com",
        "revcontent.com",
        "advertising.com",
        "moatads.com",
        "mixpanel.com",
        "matomo.org",
        "amplitude.com",
        "heap.io",
        "kissmetrics.com",
        "optimizely.com",
        "adsafeprotected.com",
        "adform.net",
        "truste.com",
        "crwdcntrl.net",
        "securepubads.g.doubleclick.net",
        "ad.doubleclick-x23.net",
        "track.adnxs-89.com",
        "analytics.adsrvr-7.org",
        "pubmatic-qwe12.com",
        "criteo-srv001.com",
        "appnexus-xyz.net",
        "adroll-9876.com",
        "outbrain-ads.abc.com",
        "taboola-feed-34.com",
        "revcontent-track-01.com",
        "moatads-xyz123.net",
        "mixpanel-analytics-99.com",
        "amplitude-001.io",
        "heap-tracking-777.io",
        "ssbsync.smartadserver.co",
        "optimizely-beta-55.com",
        "adform-tracker-42.net",
        "crwdcntrl-pixel-12.net",
        "config.ads.vungle.com",
        "config.aps.amazon-adsystem.com",
        "aax.amazon-adsystem.com",
        "enduser.adsrvr.org",
    }
