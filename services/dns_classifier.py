import os
import sys
import numpy as np
import sqlite3
from pathlib import Path


# fmt: off
sys.path.append('/projects/gitlab/netarchon/venv/lib/python3.12/site-packages')
import torch # type: ignore
from torch.utils.data import DataLoader, Dataset # type: ignore
import torch.optim as optim # type: ignore
import torch.nn as nn # type: ignore
import torch.nn.functional as F # type: ignore
# fmt: on

ROOT_PATH = Path(__file__).resolve().parents[1]
DNS_CONTROL_LISTS_PATH = ROOT_PATH / 'config' / 'dns_control_list.json'
DB_FULLPATH = ROOT_PATH / 'db' / 'dns.sqlite3'
ALLOWED_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=%."
MAX_LENGTH = 80

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

            return sorted({each["query"] for each in history_record})

    except Exception as e:
        print(f"Error: Failed to read {DB_FULLPATH} - {e}")
        return []


class DomainClassifier(nn.Module):
    def __init__(self, vocab_size, embed_dim=128, output_dim=1, dropout_rate=0.35):
        super(DomainClassifier, self).__init__()

        print(vocab_size)
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.lstm1 = nn.LSTM(embed_dim, 128, batch_first=True, dropout=dropout_rate)
        self.lstm2 = nn.LSTM(128, 128, batch_first=True, dropout=dropout_rate)
        self.lstm3 = nn.LSTM(128, 128, batch_first=True, dropout=dropout_rate)
        self.fc = nn.Linear(128, output_dim)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        x = self.embedding(x)
        out, (h_n, c_n) = self.lstm1(x)
        out, (h_n, c_n) = self.lstm2(out)
        out, (h_n, c_n) = self.lstm3(out)
        out = out[:, -1, :] 
        out = self.fc(out)
        out = self.sigmoid(out)

        return out

class DomainDataset(Dataset):
    def __init__(self, data, labels, known_chars):
        self.data = data
        self.labels = labels
        self.known_chars = known_chars

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        # Convert domain to indices based on known_chars
        domain = self.data[idx]
        indices = [self.known_chars.get(char, 0) for char in domain]  # Default to padding (0) if char not found
        label = self.labels[idx]
        return torch.tensor(indices), torch.tensor(label)


def collate_fn(batch):
    # Pad the sequences to the maximum length in the batch
    max_len = max(len(x[0]) for x in batch)
    padded_inputs = [F.pad(x[0], (0, max_len - len(x[0]))) for x in batch]
    labels = [x[1] for x in batch]
    return torch.stack(padded_inputs, 0), torch.tensor(labels)

def generate_training_dataset():
    # Example dataset (replace with your actual data generation process)
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
        "x.blueduckredapple.com":1,
        "x.everestop.io":1,
        "x.thecatmachine.com":1,
        "api.ad.intl.xiaomi.com":1,
        "adxbid.info":1,
        "news.bbc.co.uk": 0,
        ".googlevideo.com":0,
        "google-analytics.com":0,
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
        "mozilla.org": 0,
        "mtalk.google.com":0,
        "apple.com":0,
        "yahoo.com":0,
        "googlevideo.com":0,
        "vidaahub.com":0,
        "netflix.com":0,
        "netflix.net":0,
        "clients.google.com":0,
        "googleapis.com":0,
        "temu.com":0,
        "ads.io":1,
        "30f97533-7ee1-488c-9942-ffaf4a9657c6-netseer-ipaddr-assoc.xz.fbcdn.net":1,
        "5529f505-9e16-44b5-a4aa-bef8e56e98cf.goliath.atlas.bi.miniclippt.com":1,
        "adexp.liftoff.io":1,
        "h6dw19vmgf8p4dpzpidtfedwqcyam1746882909.darnuid.imrworldwide.com":1,
        "_dns.resolver.arpa":0,
        "android.clients.google.com":0,
        "chat.signal.org ":0,
        "chat.google.com":1,
        "yandex.ru":1,
        "brave.com":0,
        "weather-data.apple.com":0,
        "web.facebook.com":0,
        "www.turkishairlines.com":0,
        "weather-data.apple.com":0

    }
    return list(domains_with_labels.keys()), list(domains_with_labels.values())

def train(model, train_loader, criterion, optimizer, num_epochs=50):
    model.train()
    for epoch in range(num_epochs):
        running_loss = 0.0
        for inputs, labels in train_loader:
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, labels.float().unsqueeze(1))  # Binary classification, need .unsqueeze(1)
            loss.backward()
            optimizer.step()
            running_loss += loss.item()
        
        print(f"Epoch {epoch+1}/{num_epochs}, Loss: {running_loss/len(train_loader):.4f}")

def evaluate(model, test_loader):
    model.eval()
    correct = 0
    total = 0
    with torch.no_grad():
        for inputs, labels in test_loader:
            outputs = model(inputs)
            predicted = (outputs >= 0.5).float()  # Predict 1 if output >= 0.5, else 0
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
    
    accuracy = correct / total
    print(f"Accuracy: {accuracy * 100:.2f}%")
    return accuracy

def save_model(model, path):
    torch.save(model.state_dict(), path)
    print(f"Model saved to {path}")

def test_and_print_results(domains, model, known_chars):
    for domain in domains:
        indices = [known_chars.get(char, 0) for char in domain]
        indices = torch.tensor([indices])
        output = model(indices)
        print(f"{domain:>50} => {output.item()*100:8.3f} %")

def extract_chars_from_domain_list(domains:list[str]) -> dict:
    return {char: idx + 1 for idx, char in enumerate(set("".join(domains)))}

def extract_chars_from_string(string:str) -> dict:
    return {char: idx + 1 for idx, char in string}

def process_string(input_string: str) -> str:
    adjusted_input = [char.lower() for char in input_string if char.lower() in ALLOWED_CHARS]
    return ''.join(adjusted_input)

if __name__ == "__main__":
    print("DNS Query Classifier")

    # Step 1: Generate dataset
    training_domains_normalized = []
    training_domains, training_labels = generate_training_dataset()
    for each in training_domains:
        training_domains_normalized.append(process_string(each))

    known_chars:dict = {char: idx + 1 for idx, char in enumerate(set("".join(training_domains)))}
    known_chars['<PAD>'] = 0  
    input_size = len(known_chars)

    # known_chars = {char: idx+1 for idx, char in enumerate(ALLOWED_CHARS)}
    # known_chars['<PAD>'] = 0
    # input_size = len(known_chars)

    # Step 2: Create model
    dnsClassifier = DomainClassifier(vocab_size=input_size)

    # Step 3: Manually split the data into train and test
    split_idx = int(len(training_domains_normalized) * 0.8)
    train_domains = training_domains_normalized[:split_idx]
    test_domains = training_domains_normalized[split_idx:]
    train_labels = training_labels[:split_idx]
    test_labels = training_labels[split_idx:]

    # Step 4: Create dataset and dataloaders
    train_dataset = DomainDataset(train_domains, train_labels, known_chars)
    test_dataset = DomainDataset(test_domains, test_labels, known_chars)

    train_loader = DataLoader(train_dataset, batch_size=2, shuffle=True, collate_fn=collate_fn)
    test_loader = DataLoader(test_dataset, batch_size=2, shuffle=False, collate_fn=collate_fn)

    # Step 5: Train model
    print("Stage 5 - Training")
    criterion = nn.BCELoss()  # Binary Cross-Entropy loss
    # optimizer = optim.Adam(model.parameters(), lr=0.001)
    optimizer = optim.AdamW(dnsClassifier.parameters(), lr=1e-4, weight_decay=0.01)
    train(dnsClassifier, train_loader, criterion, optimizer, num_epochs=50)

    # Step 6: Evaluate model
    print("Eval ...")
    evaluate(dnsClassifier, test_loader)

    # Step 7: Save model
    os.makedirs("models", exist_ok=True)
    save_model(dnsClassifier, "models/domain_classifier_model.pt")

    # Step 8: Test and print results on new domains
    print("Testing model on new domains...")
    test_and_print_results(get_dns_history(), dnsClassifier, known_chars)

    exit(0)