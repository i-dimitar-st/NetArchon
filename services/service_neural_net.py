
import os
import sys
import math
import fnmatch
import sqlite3
from pathlib import Path
import json
from collections import Counter
from typing import List, Tuple
# fmt: off
sys.path.append('/projects/gitlab/netarchon/venv/lib/python3.12/site-packages')
import torch                   # type: ignore
import torch.nn as neural_net  # type: ignore
import torch.optim as optim    # type: ignore
from torch.optim import AdamW  # type: ignore
# fmt: on

ROOT_PATH = Path(__file__).resolve().parents[1]
DNS_CONTROL_LISTS_PATH = ROOT_PATH / 'config' / 'dns_control_list.json'
DB_FULLPATH = ROOT_PATH / 'db' / 'dns.sqlite3'


def get_dns_history() -> set:

    try:
        with sqlite3.connect(DB_FULLPATH) as conn:

            cursor = conn.cursor()

            cursor.execute("PRAGMA table_info(history)")
            columns: list[str] = [column[1] for column in cursor.fetchall()]

            cursor.execute("SELECT * FROM history")
            query_result: list[tuple] = cursor.fetchall()

            history_record = []
            for each in query_result:
                history_record.append(dict(zip(columns, each)))

            return {each["query"] for each in history_record}

    except Exception as e:
        print(f"Error: Failed to read {DB_FULLPATH} - {e}")
        return []


# --- FEATURE ENGINEERING ---


def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    probs = [count / total for count in counts.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)


def extract_features(domain: str) -> List[float]:
    # Split the domain into parts (by ".")
    parts = domain.split(".")

    # Count of dots
    dot_count = domain.count(".")

    # Count of hyphens
    hyphen_count = domain.count("-")

    # Keyword matching (case-insensitive check for variations)
    keywords = ['ads', 'ad', 'tracking', 'track', 'measure']
    keyword_hits = sum(1 for keyword in keywords if keyword in domain.lower())

    # Calculate entropy (this function should be implemented)
    entropy = calculate_entropy(domain)

    # Digit ratio (percentage of digits in the domain)
    digit_ratio = sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0

    # Special character ratio (percentage of hyphens or underscores in the domain)
    special_ratio = sum(c in "-_" for c in domain) / len(domain) if len(domain) > 0 else 0

    # Letter ratio (percentage of alphabetic characters in the domain)
    letter_ratio = sum(c.isalpha() for c in domain) / len(domain) if len(domain) > 0 else 0

    return [
        dot_count,        # Count of dots
        hyphen_count,     # Count of hyphens
        keyword_hits,     # Keyword hits (for specific variations)
        entropy,          # Entropy of the domain
        digit_ratio,      # Ratio of digits in the domain
        special_ratio,    # Ratio of special characters in the domain
        letter_ratio      # Ratio of alphabetic characters in the domain
    ]


# --- MODEL DEFINITION ---

class DNSQueryClassifier(neural_net.Module):
    def __init__(self, input_size: int):
        super().__init__()

        # First fully connected layer
        self.fc1 = neural_net.Linear(input_size, 64)  # Increased number of neurons to 64
        self.dropout = neural_net.Dropout(0.3)
        # Second fully connected layer
        self.fc2 = neural_net.Linear(64, 32)  # Increased number of neurons to 32
        self.dropout = neural_net.Dropout(0.3)
        # Third fully connected layer
        self.fc3 = neural_net.Linear(32, 16)  # Reduced neurons to 16 (can be adjusted as needed)
        self.dropout = neural_net.Dropout(0.3)
        # Fourth fully connected layer (new)
        self.fc4 = neural_net.Linear(16, 8)   # New layer with 8 neurons
        self.dropout = neural_net.Dropout(0.3)

        # Output layer
        self.fc5 = neural_net.Linear(8, 1)    # Output layer with a single neuron for binary classification
        self.relu = neural_net.ReLU()
        # Sigmoid activation function for final output
        self.sigmoid = neural_net.Sigmoid()

    def forward(self, x):
        # Apply ReLU activations on hidden layers (except the output)
        x = self.relu(self.fc1(x))
        x = self.relu(self.fc2(x))
        x = self.relu(self.fc3(x))
        x = self.relu(self.fc4(x))  # Activation for the new layer
        x = self.sigmoid(self.fc5(x))   # Final output layer
        return x


# --- TRAINING FUNCTION ---

def incremental_train(model, features, labels, num_epochs=10):
    X = torch.tensor(features, dtype=torch.float32)
    y = torch.tensor(labels, dtype=torch.float32).view(-1, 1)

    # optimizer = optim.Adam(model.parameters(), lr=0.001)
    optimizer = AdamW(model.parameters(), lr=5e-3, weight_decay=0.01)
    criterion = neural_net.BCELoss()

    for epoch in range(num_epochs):
        model.train()
        outputs = model(X)
        loss = criterion(outputs, y)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        print(f"[Epoch {epoch+1}/{num_epochs}] Loss: {loss.item():.4f}")


# --- EVALUATION ---

def evaluate(model, features, labels):
    model.eval()
    with torch.no_grad():
        X = torch.tensor(features, dtype=torch.float32)
        y = torch.tensor(labels, dtype=torch.float32).view(-1, 1)
        predictions = (model(X) > 0.5).float()
        accuracy = (predictions == y).float().mean().item()
        print(f"[Evaluation] Accuracy: {accuracy * 100:.2f}%")


# --- TEST AND PRINT FUNCTION ---

def encode_domain(domain: str) -> torch.Tensor:
    """
    Convert a domain name to a tensor of extracted features.
    """
    features = extract_features(domain)
    return torch.tensor(features, dtype=torch.float32)


def test_and_print_results(domains: List[str], model: torch.nn.Module):
    """
    Tests the model on a list of domains and prints predictions.
    """
    model.eval()
    with torch.no_grad():
        for domain in domains:
            encoded = encode_domain(domain).unsqueeze(0)
            output = model(encoded)
            probability = torch.sigmoid(output).item()
            print(f"{domain:<40} | Malicious Probability: {100*probability:.5f}")


# --- MODEL SAVE/LOAD ---

def save_model(model, path: str):
    torch.save(model.state_dict(), path)
    print(f"[Saved] Model saved to {path}")


def load_model(path: str, input_size: int) -> DNSQueryClassifier:
    model = DNSQueryClassifier(input_size)
    model.load_state_dict(torch.load(path))
    model.eval()
    print(f"[Loaded] Model loaded from {path}")
    return model


# --- DEMO DATASET ---

def generate_dataset() -> Tuple[List[List[float]], List[int]]:
    # try:
    #     with open(DNS_CONTROL_LISTS_PATH, 'r') as f:
    #         control_data = json.load(f)
    #         known_patterns = control_data.get("blacklist", [])
    #     if not isinstance(known_patterns, list):
    #         raise ValueError("Expected 'blacklist' to be a list")
    # except Exception as e:
    #     print(f"[Error] Failed to load control list: {e}")
    #     known_patterns = []
    domains_with_labels = {
        "ads.google.com": 1,
        "track.analytics.com": 1,
        "click.trap.biz": 1,
        "metrics.spam.org": 1,
        "ad-host.amazonaws.com": 1,
        "netseer-ipaddr-assoc.xy.fbcdn.net": 1,
        "stickyadstv.com": 1,
        "sg2-bid.adsrvr.org": 1,
        "rtb.mfadsrvr.com": 1,
        "rtb-usw.mfadsrvr.com": 1,
        "match.adsrvr.org": 1,
        "jadserve.postrelease.com": 1,
        "enduser.adsrvr.org": 1,
        "ad.360yield.com": 1,
        "api.ad.intl.xiaomi.com": 1,
        "venetia.iad.appboy.com": 1,
        "mybank.secure-login.com": 1,
        "news.bbc.co.uk": 0,
        "github.com": 0,
        "stackoverflow.com": 0,
        "google.com": 0,
        "microsoft.com": 0,
        "apple.com": 0,
        "chromesyncpasswords-pa.googleapis.com":0,
        "amazon.com": 0,
        "facebook.com": 0,
        "youtube.com": 0,
        "wikipedia.org": 0,
        "reddit.com": 0,
        "linkedin.com": 0,
        "github.com": 0,
        "twitter.com": 0,
        "bbc.com": 0,
        "nytimes.com": 0,
        "cloudflare.com": 0,
        "stackexchange.com": 0,
        "paypal.com": 0,
        "dropbox.com": 0,
        "adobe.com": 0,
        "cnn.com": 0,
        "mozilla.org": 0
    }

    features = [extract_features(domain) for domain in domains_with_labels.keys()]
    return features, list(domains_with_labels.values())


# --- MAIN EXECUTION ---

if __name__ == "__main__":
    print("[Start] DNS Query Classifier")

    # Step 1: Generate dataset
    features, labels = generate_dataset()
    input_size = len(features[0])

    # Step 2: Create model
    model = DNSQueryClassifier(input_size=input_size)

    # Step 3: Train model
    print("[Training] Starting training...")
    incremental_train(model, features, labels, num_epochs=100)

    # Step 4: Evaluate model
    print("[Evaluation] Running evaluation...")
    evaluate(model, features, labels)

    # Step 5: Save model
    os.makedirs("models", exist_ok=True)
    save_model(model, "models/dns_model.pt")

    # Step 6: Test and print results on new domains
    test_domains = [
        "b1sync.outbrain.com",
        "b1sync.zemanta.com",
        "beacons.gcp.gvt2.com",
        "c.mgid.com",
        "chromesyncpasswords-pa.googleapis.com",
        "cl.imghosts.com",
        "clients2.google.com",
        "clients4.google.com",
        "d0.eu-4-id5-sync.com",
        "d2.eu-4-id5-sync.com",
        "www.google-analytics.com",
        "www.google.com",
        "www.google.com.au",
        "www.googleapis.com",
        "www.googletagmanager.com",
        "www.gstatic.com",
        "www.slobodenpecat.mk",
        "ad.360yield.com"
    ]
    print("[Testing] Testing model on new domains...")
    test_and_print_results(test_domains, model)
    exit(0)
