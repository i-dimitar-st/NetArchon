from collections import deque
from datetime import datetime, timezone
from logging import Logger
from pathlib import Path
from statistics import mean
from typing import Generator

from torch import (
    Tensor,
    float as torchFloat,
    load as torchLoad,
    save as torchSave,
    tensor as torchTensor,
)
from torch.nn import BCELoss
from torch.optim import AdamW

from app.services.neural_net.models import (
    DomainClassifier,
    DomainDataset,
    TrainingProgress,
)


def save_model_to_disk(model: DomainClassifier, file_path: Path):
    if not isinstance(model, DomainClassifier):
        raise ValueError("Invalid modeltype")
    if not isinstance(file_path, Path):
        raise TypeError("path must be a pathlib.Path object")
    torchSave(
        {
            "state_dict": model.state_dict(),
            "config": model._config,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        file_path,
    )


def load_model_from_disk(file_path: Path) -> DomainClassifier:
    """
    Load a DomainClassifier from disk, including its configuration and parameters.
    Args:
        file_path(Path): Location to load from
    """
    if not isinstance(file_path, Path):
        raise TypeError("file_path must be a pathlib.Path object")
    if not file_path.exists():
        raise FileNotFoundError(f"{file_path} does not exist")
    if not file_path.is_file():
        raise ValueError(f"{file_path} is not a file")

    _data_from_disk = torchLoad(file_path, map_location="cpu")
    model = DomainClassifier(**_data_from_disk["config"])
    model.load_state_dict(_data_from_disk["state_dict"])
    model.to(model.get_model_device())

    del _data_from_disk
    return model


def load_model_from_disk_timestamp(file_path: Path) -> str:
    """
    Load a DomainClassifier from disk, including its configuration and parameters.
    Args:
        file_path(Path): Location to load from
    """
    if not isinstance(file_path, Path):
        raise TypeError("file_path must be a pathlib.Path object")
    if not file_path.exists():
        raise FileNotFoundError(f"{file_path} does not exist")
    if not file_path.is_file():
        raise ValueError(f"{file_path} is not a file")

    return torchLoad(file_path, map_location="cpu")["timestamp"]


def train_model(
    logger: Logger,
    model: DomainClassifier,
    train_dataset: DomainDataset,
    criterion: BCELoss,
    optimizer: AdamW,
    epochs: int,
    device: str,
    batch_size: int,
    min_acceptable_epoch_loss: float,
    min_loss_epoch_qty: int,
    training_loss_delta: float,
) -> Generator[TrainingProgress, None, None]:
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
    if (
        not isinstance(min_acceptable_epoch_loss, float)
        or 0 > min_acceptable_epoch_loss
        or 1 < min_acceptable_epoch_loss
    ):
        raise ValueError(
            "min_acceptable_epoch_loss must be a non-negative float between 0 - 1"
        )

    yield TrainingProgress(status="starting", progress=0.0)

    model.set_and_move_to_device()
    model.train()

    _training_loss = deque(maxlen=min_loss_epoch_qty)
    for _epoch in range(epochs):
        _epoch_losses = []
        # batch training
        for _i in range(0, len(train_dataset), batch_size):

            _batch_domains, _batch_labels = train_dataset.get_items(_i, _i + batch_size)
            _batch_labels = torchTensor(
                _batch_labels, device=device, dtype=torchFloat
            ).unsqueeze(1)

            optimizer.zero_grad()
            _batch_domains_tensor: Tensor = model.convert_domains_to_tensor(
                _batch_domains
            ).to(device)
            _batch_domains_prediction: Tensor = model(_batch_domains_tensor)

            _loss: Tensor = criterion(_batch_domains_prediction, _batch_labels)
            _loss.backward()
            optimizer.step()

            _epoch_losses.append(_loss.item())

        _avg_epoch_loss = mean(_epoch_losses)
        logger.debug(f"Training @ Epoch:{_epoch} Loss: {_avg_epoch_loss:.4f}.")
        yield TrainingProgress(
            status="training",
            progress=_epoch / epochs,
            payload={"avg_loss": _avg_epoch_loss},
        )

        _training_loss.append(_avg_epoch_loss)
        if mean(_training_loss) <= min_acceptable_epoch_loss:
            _recent_losses_deltas = [
                abs(_training_loss[i] - _training_loss[i - 1])
                for i in range(1, len(_training_loss))
            ]
            if mean(_recent_losses_deltas) <= training_loss_delta:
                logger.debug(f"Training completed @ Epoch: {_epoch}.")
                break

    yield TrainingProgress(status="done", progress=1.0, payload={"model": model})


def evaluate_model(model: DomainClassifier, test_dataset: DomainDataset) -> float:
    """
    Evaluate a DomainClassifier on a dataset of raw domains and labels in one go.
    Args:
        model (DomainClassifier): The trained model.
        test_dataset (DomainDataset): Dataset of domains and labels.
    Returns:
        float: Accuracy over the dataset.
    """
    if not isinstance(model, DomainClassifier):
        raise TypeError("model must be a DomainClassifier")
    if not isinstance(test_dataset, DomainDataset):
        raise TypeError("test_dataset must be a DomainDataset")

    model.eval()
    _domains, _labels = test_dataset.get_items(0)
    _labels_tensor: Tensor = torchTensor(
        _labels, device=model.get_model_device(), dtype=torchFloat
    )
    _predictions: Tensor = model.predict(_domains)
    if model.get_model_output_dim() == 1:
        _labels_tensor = _labels_tensor.unsqueeze(1)
    correct = 0
    for _pred, _label in zip(_predictions, _labels_tensor):
        _binary_pred = 1 if _pred >= 0.5 else 0
        if _binary_pred == _label:
            correct += 1

    del _labels_tensor
    del _predictions

    return correct / len(test_dataset)


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
