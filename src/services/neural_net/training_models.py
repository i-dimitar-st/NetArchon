from logging import Logger
from pathlib import Path
from typing import Generator

from src.services.neural_net.model_utils import (
    evaluate_model,
    load_model_from_disk,
    save_model_to_disk,
    train_model,
)
from src.services.neural_net.models import (
    DomainClassifier,
    TrainingProgress,
)


class ModelTrainer:
    def train(self, *args, **kwargs) -> Generator[TrainingProgress, None, None]:
        return train_model(*args, **kwargs)

    def eval(self, *args, **kwargs) -> float:
        return evaluate_model(*args, **kwargs)

    def save(self, *args, **kwargs):
        save_model_to_disk(*args, **kwargs)


class ModelPredictor:
    def __init__(self, logger: Logger):
        self.logger = logger

    def prep_model(self, file_path: Path) -> DomainClassifier:
        model: DomainClassifier = load_model_from_disk(file_path=file_path)
        model.eval()
        model.set_and_move_to_device()
        return model

    def predict(
        self, model: DomainClassifier, domains: list[str]
    ) -> list[dict[str, float]]:
        if not all(isinstance(_domain, str) for _domain in domains):
            raise TypeError("All domains must be strings.")
        _predictions: list[float] = model.predict(domains).squeeze(-1).tolist()
        results = []
        for domain, probability in zip(domains, _predictions,strict=True):
            results.append(
                {
                    "domain": str(domain),
                    "probability": float(probability),
                }
            )
        del _predictions
        return sorted(
            results,
            key=lambda each: each["probability"],
            reverse=True,
        )
