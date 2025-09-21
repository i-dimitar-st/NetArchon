from logging import Logger
from pathlib import Path
from threading import RLock
from time import time

from torch.nn import BCELoss
from torch.optim import AdamW

from app.config.config import config

# from app.services.logger.logger import MainLogger
from app.services.neural_net.generators import (
    generate_bad_urls,
    generate_testing_dataset,
    generate_training_dataset,
)
from app.services.neural_net.models import DomainClassifier, DomainDataset
from app.services.neural_net.utils import (
    evaluate_model,
    get_device,
    get_dns_history,
    get_local_file,
    load_model,
    model_predict_results,
    save_model,
    train_model,
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

NEUTRAL_NET = config.get("neutral_net")
MODEL_PATH = Path(ROOT_PATH / NEUTRAL_NET.get("path"))
ALLOWED_CHARS = str(NEUTRAL_NET.get("allowed_chars"))
MAX_DOMAIN_LENGTH = int(NEUTRAL_NET.get("max_domain_length"))
PAD_CHAR = int(NEUTRAL_NET.get("pad_char"))

MODEL_SPECS = NEUTRAL_NET.get("model_specs")
EMBED_DIM = int(MODEL_SPECS.get("embed_dim"))
HIDDEN_SIZE = int(MODEL_SPECS.get("hidden_size"))
NUM_LAYERS = int(MODEL_SPECS.get("num_layers"))
OUTPUT_DIM = int(MODEL_SPECS.get("output_dim"))
DROPOUT_RATE = float(MODEL_SPECS.get("dropout_rate"))
EPOCHS = int(MODEL_SPECS.get("epochs"))
BIDIRECTIONAL = bool(MODEL_SPECS.get("bidirectional"))
NN_OPTIMIZER_SPECS = NEUTRAL_NET.get("optimizer_specs")
WEIGHT_DECAY = float(NN_OPTIMIZER_SPECS.get("weight_decay"))
LEARNING_RATE = float(NN_OPTIMIZER_SPECS.get("learning_rate"))

TRAINING_SPECS = NEUTRAL_NET.get("training_specs")
MIN_LOSS_EPOCH_QTY = int(TRAINING_SPECS.get("min_loss_epoch_qty"))
LOSS_DELTA = float(TRAINING_SPECS.get("loss_delta"))
BATCH_SIZE = int(TRAINING_SPECS.get("batch_size"))

DEVICE = get_device()
VOCAB_SIZE = len(ALLOWED_CHARS) + 1  # padding


# neural_net_logger: Logger = MainLogger.get_logger(
#     service_name="NEURAL_NET", log_level="debug"
# )


class NeuralNetworkDomainClassifierService:
    _lock = RLock()
    _initialised = False
    running = False
    timestamp: float

    @classmethod
    def init(cls):
        with cls._lock:
            if cls._initialised:
                raise RuntimeError("Already Init")
            cls._initialised = True

    @classmethod
    def start(cls):
        if cls.running:
            raise RuntimeError("Service already running.")
        with cls._lock:
            cls.running = True
            cls.timestamp = time()
            # neural_net_logger.info("NEURAL_NET service started.")

    @classmethod
    def stop(cls):
        if not cls.running:
            raise RuntimeError("Service not running.")
        with cls._lock:
            # neural_net_logger.info("Service stopped.")
            cls.running = False


if __name__ == "__main__":
    print("Running module training")

    _neuralNetModelDnsClassifier = DomainClassifier(
        allowed_chars=ALLOWED_CHARS,
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
    _criterion = BCELoss()
    _optimizer = AdamW(
        params=_neuralNetModelDnsClassifier.parameters(),
        lr=LEARNING_RATE,
        weight_decay=WEIGHT_DECAY,
    )
    _train_dataset: DomainDataset = generate_training_dataset(
        blacklist=get_local_file(file_path=BLACKLISTS_FILE) | generate_bad_urls(),
        whitelist=get_local_file(file_path=WHITELISTS_FILE),
        allowed_chars=ALLOWED_CHARS,
    )
    train_model(
        model=_neuralNetModelDnsClassifier,
        train_dataset=_train_dataset,
        criterion=_criterion,
        optimizer=_optimizer,
        epochs=EPOCHS,
        device=DEVICE,
        batch_size=BATCH_SIZE,
        min_loss_epoch_qty=MIN_LOSS_EPOCH_QTY,
        training_loss_delta=LOSS_DELTA,
    )
    evaluate_model(
        model=_neuralNetModelDnsClassifier,
        test_dataset=generate_testing_dataset(),
        batch_size=BATCH_SIZE,
    )
    save_model(model=_neuralNetModelDnsClassifier, file_path=MODEL_PATH)
    _predictions = model_predict_results(
        domains=get_dns_history(file_path=DNS_DB_HISTORY),
        model=_neuralNetModelDnsClassifier,
    )
    for _pred in _predictions:
        print(f"Domain: {_pred['domain']:50} | Probability: {_pred['pred']:.6f}")
