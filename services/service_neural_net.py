
import sys
import fnmatch
# fmt: off
sys.path.append('/projects/gitlab/netarchon/venv/lib/python3.12/site-packages')
import torch                   # type: ignore
import torch.nn as neural_net  # type: ignore
import torch.optim as optim    # type: ignore
# fmt: on


class DNSQueryClassifier(neural_net.Module):
    def __init__(self, input_size):
        super(DNSQueryClassifier, self).__init__()
        self.fc1 = neural_net.Linear(input_size, 32)  # First hidden layer with 32 neurons
        self.fc2 = neural_net.Linear(32, 16)          # Second hidden layer with 16 neurons
        self.fc3 = neural_net.Linear(16, 1)           # Output layer (binary classification)
        self.sigmoid = neural_net.Sigmoid()           # Sigmoid activation for output between 0 and 1

    def forward(self, x):
        x = torch.relu(self.fc1(x))  # ReLU activation after first layer
        x = torch.relu(self.fc2(x))  # ReLU activation after second layer
        x = self.sigmoid(self.fc3(x))  # Sigmoid for binary classification
        return x


def incremental_train(model, new_features, new_labels, num_epochs=5):
    # Convert new data to tensors
    new_features_tensor = torch.tensor(new_features, dtype=torch.float32)
    new_labels_tensor = torch.tensor(new_labels, dtype=torch.float32).view(-1, 1)

    # Optimizer and loss function for incremental training
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    criterion = neural_net.BCELoss()

    # Incremental training loop
    for epoch in range(num_epochs):
        model.train()  # Set the model to training mode

        # Forward pass
        outputs = model(new_features_tensor)

        # Calculate loss
        loss = criterion(outputs, new_labels_tensor)

        # Backward pass and optimization
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        print(f'Incremental Epoch [{epoch+1}/{num_epochs}], Loss: {loss.item():.4f}')


def extract_features(domain: str, known_patterns: List[str] = []) -> List[float]:
    parts = domain.split(".")
    length = len(domain)
    num_parts = len(parts)
    keyword_hits = sum(1 for word in ['ads', 'track', 'click', 'metrics'] if word in domain)

    # Match against wildcards using fnmatch
    wildcard_match = any(fnmatch.fnmatch(domain, pattern) for pattern in known_patterns)
    suffix_depth = max(
        [len(pattern.split('.')) for pattern in known_patterns if fnmatch.fnmatch(domain, pattern)],
        default=0
    )

    return [length, num_parts, keyword_hits, int(wildcard_match), suffix_depth]


def generate_synthetic_domains(base: str) -> List[str]:
    base_no_wild = base.replace("*", "")
    return [
        f"{prefix}.{base_no_wild}" for prefix in ['ads', 'video', 'mobile', 'click', 'track']
    ]
