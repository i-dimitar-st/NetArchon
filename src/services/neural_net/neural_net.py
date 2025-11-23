from datetime import datetime, timezone
from gc import collect
from logging import Logger
from pathlib import Path
from threading import RLock
from time import sleep, time
from typing import Generator

from torch.nn import BCELoss
from torch.optim import AdamW

from src.config.config import config
from src.services.logger.logger import MainLogger
from src.services.neural_net.generators import (
    generate_testing_dataset,
    generate_training_dataset,
    get_latest_adservers,
)
from src.services.neural_net.models import (
    DomainClassifier,
    TrainingProgress,
)
from src.services.neural_net.training_models import (
    ModelPredictor,
    ModelTrainer,
)
from src.services.neural_net.utils import (
    clean_device_cache,
    generate_char2idx,
    get_device,
    get_local_file,
    load_model_timestamp_from_disk,
)

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
BLACKLISTS_FILE = Path(
    ROOT_PATH / config.get("dns").get("blacklists_config").get("path")
)
WHITELISTS_FILE = Path(
    ROOT_PATH / config.get("dns").get("whitelists_config").get("path")
)

DNS_DB = config.get("database").get("dns")
DNS_DB_HISTORY = Path(ROOT_PATH / DNS_DB.get("history").get("path"))

NEURAL_NET = config.get("neural_net")
GENERAL_SPECS = NEURAL_NET.get("general_specs")
MODEL_PATH = Path(ROOT_PATH / GENERAL_SPECS.get("path"))
ALLOWED_CHARS = str(GENERAL_SPECS.get("allowed_chars"))
MAX_DOMAIN_LENGTH = int(GENERAL_SPECS.get("max_domain_length"))
PAD_CHAR = int(GENERAL_SPECS.get("pad_char"))
USE_ADSERVER_LIST = bool(GENERAL_SPECS.get("use_adserver_list"))

MODEL_SPECS = NEURAL_NET.get("model_specs")
EMBED_DIM = int(MODEL_SPECS.get("embed_dim"))
HIDDEN_SIZE = int(MODEL_SPECS.get("hidden_size"))
NUM_LAYERS = int(MODEL_SPECS.get("num_layers"))
OUTPUT_DIM = int(MODEL_SPECS.get("output_dim"))
DROPOUT_RATE = float(MODEL_SPECS.get("dropout_rate"))
EPOCHS = int(MODEL_SPECS.get("epochs"))
BIDIRECTIONAL = bool(MODEL_SPECS.get("bidirectional"))

NN_OPTIMIZER_SPECS = NEURAL_NET.get("optimizer_specs")
WEIGHT_DECAY = float(NN_OPTIMIZER_SPECS.get("weight_decay"))
LEARNING_RATE = float(NN_OPTIMIZER_SPECS.get("learning_rate"))

TRAINING_SPECS = NEURAL_NET.get("training_specs")
MIN_LOSS_EPOCH_QTY = int(TRAINING_SPECS.get("min_loss_epoch_qty"))
MIN_ACCEPTABLE_EPOCH_LOSS = float(TRAINING_SPECS.get("min_acceptable_epoch_loss"))
LOSS_DELTA = float(TRAINING_SPECS.get("loss_delta"))
BATCH_SIZE = int(TRAINING_SPECS.get("batch_size"))

DEVICE: str = get_device()
VOCAB_SIZE: int = len(ALLOWED_CHARS) + 1  # padding accounted in generate_char2idx


neural_net_logger: Logger = MainLogger.get_logger(
    service_name="NEURAL_NET", log_level="debug"
)


class NNDomainClassifierService:
    _lock = RLock()
    _initialised = False
    running = False
    busy = False
    timestamp: float

    @classmethod
    def init(cls):
        with cls._lock:
            if cls._initialised:
                raise RuntimeError("Already Init")
            cls._initialised = True
            neural_net_logger.info("Initialized.")

    @classmethod
    def start(cls):
        with cls._lock:
            if cls.running:
                raise RuntimeError("Service already running.")
            cls.running = True
            cls.timestamp = time()
            neural_net_logger.info("Started.")

    @classmethod
    def _get_whitelists(cls) -> set:
        return set(
            get_local_file(file_path=WHITELISTS_FILE).get("payload", {}).get("urls", [])
        )

    @classmethod
    def _get_blacklists(cls) -> set:
        _adserver_list = set(get_latest_adservers()) if USE_ADSERVER_LIST else set()
        return (
            set(
                get_local_file(file_path=BLACKLISTS_FILE)
                .get("payload", {})
                .get("urls", [])
            )
            | _adserver_list
        )

    @classmethod
    def get_model_timestamp(cls):
        neural_net_logger.debug("Got model timestamp.")
        return load_model_timestamp_from_disk(file_path=MODEL_PATH)

    @classmethod
    def get_model_age(cls) -> float:
        _timestamp = load_model_timestamp_from_disk(file_path=MODEL_PATH)
        if not _timestamp:
            neural_net_logger.warning("No model timestamp found.")
            return 0.0
        return (
            datetime.now(timezone.utc)
            - datetime.fromisoformat(_timestamp).replace(tzinfo=timezone.utc)
        ).total_seconds()

    @staticmethod
    def _get_optimizer(
        model,
        learning_rate: float = LEARNING_RATE,
        weigh_decay: float = WEIGHT_DECAY,
    ) -> AdamW:
        return AdamW(
            params=model.parameters(),
            lr=learning_rate,
            weight_decay=weigh_decay,
        )

    @staticmethod
    def _get_criterion() -> BCELoss:
        return BCELoss()

    @classmethod
    def train_new_model(
        cls,
    ) -> Generator[TrainingProgress, None, None]:
        """Train a new DomainClassifier and store it in the service.
        After training, the service will be marked as initialised.
        """
        with cls._lock:
            if cls.busy:
                raise RuntimeError("In Training")
            neural_net_logger.info("Training model ...")
            cls.running = True
            _model: DomainClassifier | None = None
            _trained_model: DomainClassifier | None = None
            _trainer: ModelTrainer | None = None
            _model_accuracy: float | None = None
            try:
                yield TrainingProgress(status="warming-up")
                _model = DomainClassifier(
                    allowed_chars=ALLOWED_CHARS,
                    char2idx=generate_char2idx(ALLOWED_CHARS),
                    max_domain_length=MAX_DOMAIN_LENGTH,
                    pad_char=PAD_CHAR,
                    vocab_size=VOCAB_SIZE,
                    embed_dim=EMBED_DIM,
                    output_dim=OUTPUT_DIM,
                    hidden_size=HIDDEN_SIZE,
                    num_layers=NUM_LAYERS,
                    dropout_rate=DROPOUT_RATE,
                    bidirectional=BIDIRECTIONAL,
                    device=DEVICE,
                )
                _trainer = ModelTrainer()
                for _training_status in _trainer.train(
                    logger=neural_net_logger,
                    model=_model,
                    optimizer=NNDomainClassifierService._get_optimizer(_model),
                    criterion=NNDomainClassifierService._get_criterion(),
                    train_dataset=generate_training_dataset(
                        blacklist=NNDomainClassifierService._get_blacklists(),
                        whitelist=NNDomainClassifierService._get_whitelists(),
                        allowed_chars=ALLOWED_CHARS,
                    ),
                    device=DEVICE,
                    epochs=EPOCHS,
                    min_loss_epoch_qty=MIN_LOSS_EPOCH_QTY,
                    training_loss_delta=LOSS_DELTA,
                    min_acceptable_epoch_loss=MIN_ACCEPTABLE_EPOCH_LOSS,
                    batch_size=BATCH_SIZE,
                ):
                    # {"status": "starting", "progress": 0.0, "payload": None}
                    if _training_status.status == "done":
                        _trained_model = _training_status.payload["model"]
                        break
                    yield _training_status
                neural_net_logger.debug("Training Done")

                yield TrainingProgress(status="evaluating")
                _model_accuracy = _trainer.eval(
                    test_dataset=generate_testing_dataset(),
                    model=_trained_model,
                )

                yield TrainingProgress(
                    status="eval-done",
                    progress=1.0,
                    payload={"accuracy": _model_accuracy},
                )
                neural_net_logger.debug(f"Eval done accuracy={_model_accuracy}")
                sleep(5)

                yield TrainingProgress(status="saving")
                _trainer.save(file_path=MODEL_PATH, model=_trained_model)
                neural_net_logger.info(f"Saved to disk {MODEL_PATH}")

                yield TrainingProgress(status="saving", progress=1.0)

            finally:
                del _model
                del _trained_model
                del _trainer
                del _model_accuracy
                clean_device_cache()
                collect()
                cls.busy = False
                neural_net_logger.info("Training completed")
                yield TrainingProgress(status="done", progress=1.0)

    @classmethod
    def predict_from_domains(cls, domains: list[str]) -> list[dict[str, float]]:
        """Predict probabilities for a list of domains using the loaded model.
        Returns a list of dicts: [{"domain": domain, "probability": probability}, ...]
        """
        if not cls._initialised:
            raise RuntimeError("Service not initialised. Call init() first.")
        if not domains:
            raise ValueError("domains empty")
        if not all(isinstance(_domain, str) for _domain in domains):
            raise TypeError("All items in 'domains' must be strings.")
        with cls._lock:
            if cls.busy:
                raise RuntimeError("Busy")
            cls.busy = True
            _model_predictor: ModelPredictor | None = None
            _model: DomainClassifier | None = None
            try:
                _model_predictor = ModelPredictor(logger=neural_net_logger)
                _model = _model_predictor.prep_model(file_path=MODEL_PATH)
                neural_net_logger.debug(f"Predicting for {len(domains)}")
                return _model_predictor.predict(domains=domains, model=_model)
            finally:
                del _model
                del _model_predictor
                clean_device_cache()
                collect()
                cls.busy = False
                neural_net_logger.info("Prediction completed")

    @classmethod
    def stop(cls):
        with cls._lock:
            if cls.running:
                neural_net_logger.debug("Still running.")
            cls.running = False
            neural_net_logger.info("Stopped.")
