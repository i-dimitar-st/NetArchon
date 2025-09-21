import json
import sqlite3
from collections import deque
from pathlib import Path
from statistics import mean

from torch import (
    Tensor,
    cuda,
    float as torchFloat,
    load as torchLoad,
    no_grad,
    save as torchSave,
    tensor as torchTensor,
)
from torch.nn import BCELoss
from torch.optim import AdamW

from app.services.neural_net.models import DomainClassifier, DomainDataset


def filter_unknown_chars_from_domain(domain: str, allowed_chars: str) -> str:
    """
    filter unallowed chars in domain.
    Args:
        domain (str): The input string (e.g., a domain name).
        allowed_chars (str): Characters to keep.
    Returns:
        str: The filtered string.
    """
    if not isinstance(domain, str):
        raise TypeError("domain must be a str")
    if not domain:
        raise ValueError("domain must not be empty")
    if not isinstance(allowed_chars, str):
        raise TypeError("allowed_chars must be a str")
    if not allowed_chars:
        raise ValueError("allowed_chars must not be empty")
    return "".join(_char for _char in domain if _char in allowed_chars)


def get_dns_history(file_path: Path) -> list:
    if not isinstance(file_path, Path):
        raise TypeError("file_path must be a pathlib.Path object")
    if not file_path.exists():
        raise FileNotFoundError(f"{file_path} does not exist")
    if not file_path.is_file():
        raise ValueError(f"{file_path} is not a file")
    try:
        with sqlite3.connect(file_path) as conn:
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
        print(f"Error: Failed to read {file_path} - {e}")
        return []


def get_device() -> str:
    return "cuda" if cuda.is_available() else "cpu"


def get_local_file(file_path: Path) -> set:
    if not isinstance(file_path, Path):
        raise TypeError("file_path must be a pathlib.Path object")
    if not file_path.exists():
        raise FileNotFoundError(f"{file_path} does not exist")
    if not file_path.is_file():
        raise ValueError(f"{file_path} is not a file")
    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return set(data.get("payload", {}).get("urls", []))


def train_model(
    model: DomainClassifier,
    train_dataset: DomainDataset,
    criterion: BCELoss,
    optimizer: AdamW,
    epochs: int,
    device: str,
    batch_size: int,
    min_loss_epoch_qty: int,
    training_loss_delta: float,
):
    if not isinstance(model, DomainClassifier):
        raise TypeError("model must be a DomainClassifier")
    if not isinstance(train_dataset, DomainDataset):
        raise TypeError("train_dataset must be a DomainDataset")
    if not isinstance(criterion, BCELoss):
        raise TypeError("criterion must BCELoss loss criterion")
    if not isinstance(optimizer, AdamW):
        raise TypeError("optimizer must be an AdamW instance")
    if not isinstance(epochs, int) or epochs <= 0:
        raise ValueError("epochs must be a positive integer")
    if not isinstance(device, str) or device not in ["cpu", "cuda"]:
        raise ValueError("device must be 'cpu' or 'cuda'")
    if not isinstance(batch_size, int) or batch_size <= 0:
        raise ValueError("batch_size must be a positive integer")
    if not isinstance(min_loss_epoch_qty, int) or min_loss_epoch_qty <= 0:
        raise ValueError("min_loss_epoch_qty must be a positive integer")
    if not isinstance(training_loss_delta, (int, float)) or training_loss_delta < 0:
        raise ValueError("training_loss_delta must be a non-negative number")
    model.set_and_move_to_device(device)
    _recent_losses = deque(maxlen=min_loss_epoch_qty)
    model.train()
    for _epoch in range(epochs):
        _running_loss = 0.0

        # batch training
        for i in range(0, len(train_dataset), batch_size):

            _batch_domains, _batch_labels = train_dataset.get_items(i, i + batch_size)
            _batch_labels = torchTensor(
                _batch_labels, device=device, dtype=torchFloat
            ).unsqueeze(1)
            optimizer.zero_grad()
            _batch_domains_tensor: Tensor = model.convert_domains_to_tensor(
                _batch_domains
            ).to(device)
            _batch_domains_prediction = model(_batch_domains_tensor)
            _loss = criterion(_batch_domains_prediction, _batch_labels)
            _loss.backward()
            optimizer.step()
            _running_loss += _loss.item()

        avg_loss = _running_loss / (len(train_dataset) / batch_size)
        _recent_losses.append(avg_loss)
        print(f"Epoch {_epoch} - Train Loss: {avg_loss:.4f}")

        if len(_recent_losses) == min_loss_epoch_qty:
            _recent_losses_deltas = [
                abs(_recent_losses[i] - _recent_losses[i - 1])
                for i in range(1, len(_recent_losses))
            ]
            if mean(_recent_losses_deltas) <= training_loss_delta:
                print(f"Training stopped early at epoch {_epoch}")
                break


def save_model(model: DomainClassifier, file_path: Path):
    if not isinstance(model, DomainClassifier):
        raise ValueError("Invalid modeltype")
    if not isinstance(file_path, Path):
        raise TypeError("path must be a pathlib.Path object")
    torchSave({"state_dict": model.state_dict(), "config": model._config}, file_path)


def load_model(file_path: Path) -> DomainClassifier:
    """
    Load a DomainClassifier from disk, including its configuration and parameters.
    Args:
        path(Path): Location to load from
    """
    if not isinstance(file_path, Path):
        raise TypeError("file_path must be a pathlib.Path object")
    if not file_path.exists():
        raise FileNotFoundError(f"{file_path} does not exist")
    if not file_path.is_file():
        raise ValueError(f"{file_path} is not a file")

    _temp_data = torchLoad(file_path, map_location="cpu")
    _config = _temp_data["config"]
    model = DomainClassifier(**_config)
    model.load_state_dict(_temp_data["state_dict"])
    model.eval()
    model.set_and_move_to_device()
    return model


def evaluate_model(
    model: DomainClassifier,
    test_dataset: DomainDataset,
    batch_size: int,
) -> float:
    """
    Evaluate a DomainClassifier on a dataset of raw domains and labels.
    Args:
        model (DomainClassifier): The trained model.
        domains (list[str]): List of domain strings.
        labels (list[int]): Corresponding labels (0 or 1).
        batch_size (int): Batch size for evaluation.
    Returns:
        float: Accuracy over the dataset.
    """
    if not isinstance(model, DomainClassifier):
        raise TypeError("model must be a DomainClassifier")
    if not isinstance(test_dataset, DomainDataset):
        raise TypeError("test_dataset must be a DomainDataset")
    if not isinstance(batch_size, int) or batch_size <= 0:
        raise ValueError("batch_size must be a positive integer")

    model.eval()
    correct = 0
    _device = model._config["device"]

    with no_grad():
        for i in range(0, len(test_dataset), batch_size):
            _batch_domains, _batch_labels = test_dataset.get_items(i, i + batch_size)
            _batch_labels = torchTensor(_batch_labels, device=_device, dtype=torchFloat)
            if model._config["output_dim"] == 1:
                _batch_labels = _batch_labels.unsqueeze(1)

            _batch_domains_tensor = model.convert_domains_to_tensor(_batch_domains).to(
                _device
            )
            _batch_domains_predictions = model(_batch_domains_tensor)
            correct += (
                ((_batch_domains_predictions >= 0.5) == _batch_labels).sum().item()
            )
            for _domain, _probability, _label in zip(
                _batch_domains, _batch_domains_predictions, _batch_labels
            ):
                print(
                    f"Domain: {_domain:50} | Prob: {_probability.item():.6f} | True: {_label.item()}"
                )

    accuracy = correct / len(test_dataset)
    print(f"Accuracy: {accuracy:.5f}")
    return accuracy


def model_predict_results(domains: list[str], model: DomainClassifier) -> list:
    """
    Predict probabilities for a list of domains and print them sorted by probability.
    Args:
        domains (list[str]): List of domain strings to test.
        model (DomainClassifier): Trained DomainClassifier.
    """
    if (
        not isinstance(domains, list)
        or not domains
        or not all(isinstance(_domain, str) for _domain in domains)
    ):
        raise ValueError("domains must be a non-empty list of strings")
    if not isinstance(model, DomainClassifier):
        raise ValueError("Invalid modeltype")
    model.eval()
    predictions = []

    _predictions_model = model.predict(domains)
    for _domain, _probability in zip(domains, _predictions_model):
        predictions.append({"domain": _domain, "pred": _probability.item()})

    predictions.sort(key=lambda x: x["pred"], reverse=True)
    return predictions
