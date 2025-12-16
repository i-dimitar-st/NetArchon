from torch import (
    Tensor,
    cat,
    cuda,
    no_grad,
    sigmoid,
    tensor,
)
from torch import (
    long as torchLong,
)
from torch.cuda import device_count
from torch.nn import LSTM, Dropout, Embedding, Linear, Module
from torch.utils.data import Dataset

from src.services.neural_net.utils import get_allowed_devices


class TrainingProgress:
    """Class representing the training progress of a neural network model."""

    def __init__(
        self,
        status: str = "",
        progress: float = 0.0,
        payload: dict = {},
    ):
        self.status = status
        self.progress = progress
        self.payload = payload

    def __repr__(self) -> str:
        """Return a string representation of the TrainingProgress."""
        return (
            f"(status={self.status}, progress={self.progress}, payload={self.payload})"
        )

    def to_dict(self):
        """Return a dict representation for JSON serialization or yielding."""
        return {
            "status": self.status,
            "progress": self.progress,
            "payload": self.payload,
        }

    def __del__(self):
        try:
            for attr in list(self.__dict__.keys()):
                delattr(self, attr)
        except Exception:
            pass


class DomainDataset(Dataset):
    def __init__(self, domains: list[str], labels: list[int]):
        if not isinstance(domains, list) or not all(
            isinstance(_domain, str) for _domain in domains
        ):
            raise TypeError("domains must be a list of str")
        if not domains:
            raise ValueError("domains must not be empty")
        if not isinstance(labels, list) or not all(
            isinstance(_label, int) for _label in labels
        ):
            raise TypeError("labels must be a list of int")
        if len(domains) != len(labels):
            raise ValueError("domains and labels must have the same length")

        self.domains: list[str] = domains
        self.labels: list[int] = labels

    def __del__(self):
        try:
            for self_attribute in list(self.__dict__.keys()):
                delattr(self, self_attribute)
        except Exception:
            pass

    def __len__(self) -> int:
        return len(self.domains)

    def __getitem__(self, index: int) -> tuple[str, int]:
        return self.domains[index], self.labels[index]

    def get_items(
        self, start_index: int, end_index: int | None = None
    ) -> tuple[list[str], list[int]]:
        """Returns two lists: domains and labels from start_index to end_index.
        If end_index is None, returns till the end of the dataset.
        """
        if end_index is None:
            end_index = len(self.domains)
        if end_index < start_index:
            raise ValueError("end_index must be >= start_index")

        return (
            list(self.domains[start_index:end_index]),
            list(self.labels[start_index:end_index]),
        )


class DomainClassifier(Module):
    def __init__(
        self,
        allowed_chars: str,
        char2idx: dict[str, int],
        max_domain_length: int,
        pad_char: int,
        vocab_size: int,
        embed_dim: int,
        output_dim: int,
        hidden_size: int,
        num_layers: int,
        dropout_rate: float,
        device: str,
        bidirectional: bool,
    ):
        super().__init__()
        self._config = {
            "vocab_size": int(vocab_size),
            "embed_dim": int(embed_dim),
            "output_dim": int(output_dim),
            "hidden_size": int(hidden_size),
            "num_layers": int(num_layers),
            "dropout_rate": float(dropout_rate),
            "allowed_chars": str(allowed_chars),
            "char2idx": char2idx,
            "pad_char": int(pad_char),
            "max_domain_length": int(max_domain_length),
            "device": str(device),
            "bidirectional": bool(bidirectional),
        }
        self._validate_config()
        self._input_layer = Embedding(
            num_embeddings=self._config["vocab_size"],
            embedding_dim=self._config["embed_dim"],
            padding_idx=0,
        )
        self._lstm = LSTM(
            input_size=self._config["embed_dim"],
            hidden_size=self._config["hidden_size"],
            num_layers=self._config["num_layers"],
            batch_first=True,
            dropout=self._config["dropout_rate"],
            bidirectional=self._config["bidirectional"],
        )
        self._dropout = Dropout(self._config["dropout_rate"])

        _hidden_size = self._config["hidden_size"]
        if self._config["bidirectional"]:
            _hidden_size = self._config["hidden_size"] * 2
        self._output_layer = Linear(_hidden_size, self._config["output_dim"])
        self.set_and_move_to_device()

    def _validate_config(self):
        """Validate model configuration dictionary."""
        required_fields = {
            "vocab_size": int,
            "embed_dim": int,
            "output_dim": int,
            "hidden_size": int,
            "num_layers": int,
            "dropout_rate": float,
            "allowed_chars": str,
            "char2idx": dict,
            "pad_char": int,
            "max_domain_length": int,
            "device": str,
            "bidirectional": bool,
        }

        for field, field_type in required_fields.items():
            if field not in self._config:
                raise ValueError(f"Config missing {field}")
            if not isinstance(self._config[field], field_type):
                raise TypeError(f"{field} to be {field_type}")

        if self._config["vocab_size"] <= 0:
            raise ValueError("vocab_size > 0")
        if self._config["embed_dim"] <= 0:
            raise ValueError("embed_dim > 0")
        if self._config["output_dim"] <= 0:
            raise ValueError("output_dim > 0")
        if self._config["hidden_size"] <= 0:
            raise ValueError("hidden_size > 0")
        if self._config["num_layers"] <= 0:
            raise ValueError("num_layers > 0")
        if not (0.0 <= self._config["dropout_rate"] < 1.0):
            raise ValueError("dropout_rate must be between 0.0 and 1.0")
        if self._config["pad_char"] != 0:
            raise ValueError("pad_char must be 0")
        if self._config["vocab_size"] != len(self._config["char2idx"]) + 1:
            print(
                self._config["vocab_size"],
                len(self._config["char2idx"]) + 1,
            )
            raise ValueError(
                "vocab_size does not match length of char2idx + 1 for padding"
            )
        if self._config["device"] not in get_allowed_devices():
            raise ValueError(f"Invalid device: {self._config['device']}")

    def __del__(self):
        try:
            for _model_attributes in list(self.__dict__.keys()):
                delattr(self, _model_attributes)
            if cuda.is_available():
                cuda.empty_cache()
        except Exception:
            pass

    def forward(self, encoded_domains: Tensor) -> Tensor:
        """Perform a forward pass through the DomainClassifier.

        Args:
            encoded_domains (Tensor): A batch of integer-encoded domain sequences
                with shape [batch_size, sequence_length]. Each integer corresponds
                to a character index in the embedding vocabulary.

        Returns:
            Tensor: Probabilities for each input with shape [batch_size, output_dim].
                Values floats between[0, 1] due to the final sigmoid activation.

        """
        _embedded: Tensor = self._input_layer(encoded_domains)
        _lstm_out, (_hidden_states, cell_states) = self._lstm(_embedded)
        _sequence_representation: Tensor = _hidden_states[-1]
        if self._config["bidirectional"]:
            _sequence_representation = cat(
                (_hidden_states[-2], _hidden_states[-1]), dim=1
            )
        _dropped: Tensor = self._dropout(_sequence_representation)
        output_raw: Tensor = self._output_layer(_dropped)
        return sigmoid(output_raw)

    def set_and_move_to_device(self):
        """Move the model to a specified device and update its configuration.
        Updates self.device,
        Updates _config["device"],
        Moves all model parameters and buffers to the specified device
        """
        _target_device = "cpu"
        if self.get_model_device() in DomainClassifier._get_available_devices():
            _target_device = self._config["device"]
        self.to(_target_device)

    def predict(self, domains: list[str]) -> Tensor:
        """Predict probabilities for a list of raw domain strings.

        Args:
            domains (list[str]): List of domain strings to predict.

        Returns:
            torch.Tensor: Probabilities for each domain, shape [batch_size, output_dim].

        """
        self.eval()
        _vectorised_domains: Tensor = self.convert_domains_to_tensor(
            domains=domains
        ).to(self._config["device"])
        with no_grad():
            return self.forward(_vectorised_domains)

    def convert_domains_to_tensor(self, domains: list[str]) -> Tensor:
        """Convert a list of domain strings to a padded tensor of integer indices.

        Args:
            domains (list[str]): List of domain strings to encode.

        Returns:
            torch.Tensor: Tensor [batch_size, max_domain_length], dtype=torch.long.
                Element are integer index corresponding to a character,0=padding.

        """
        batch_encoded = []
        for _domain in domains:
            _filtered_doman: str = DomainClassifier._filter_domain(
                domain=_domain,
                allowed_chars=self.get_allowed_chars(),
            )
            _indexed_domain: list[int] = DomainClassifier._domain_to_indices(
                _filtered_doman, self.get_char2index()
            )
            _padded_domain: list[int] = DomainClassifier._pad_domain(
                domain_indices=_indexed_domain,
                max_domain_length=self._config["max_domain_length"],
                pad_char=self._config["pad_char"],
            )
            batch_encoded.append(_padded_domain)
        return tensor(batch_encoded, dtype=torchLong)

    def get_allowed_chars(self) -> str:
        return self._config["allowed_chars"]

    def get_model_device(self) -> str:
        return self._config["device"]

    def get_model_output_dim(self) -> int:
        return self._config["output_dim"]

    def get_char2index(self) -> dict:
        return self._config["char2idx"]

    @staticmethod
    def _get_available_devices() -> list[str]:
        """Returns a list of available devices as strings.
        Always includes 'cpu'. Adds 'cuda:0', 'cuda:1', etc. for available GPUs.
        """
        devices = ["cpu"]
        devices.extend([f"cuda:{i}" for i in range(device_count())])
        return devices

    @staticmethod
    def _domain_to_indices(domain: str, char2idx: dict[str, int]) -> list[int]:
        """Convert domain to list of integer indices using char2idx mapping.
        Only characters present in char2idx are included.
        """
        return [char2idx[_char] for _char in domain if _char in char2idx]

    @staticmethod
    def _filter_domain(domain: str, allowed_chars: str) -> str:
        """Return a copy of `domain` containing only characters from `allowed_chars`.

        Args:
            domain (str): The input string (e.g., a domain name).
            allowed_chars (str): Characters to keep.

        Returns:
            str: The filtered string.

        """
        return "".join([_char for _char in domain if _char in allowed_chars])

    @staticmethod
    def _pad_domain(
        domain_indices: list[int],
        max_domain_length: int,
        pad_char: int,
    ) -> list[int]:
        """Pad or truncate a list of integer indices to a fixed length.

        Args:
            domain_indices (list[int]): List of integer indices for a domain.
            max_domain_length (int): Desired length.
            pad_index (int): Integer index to use for padding (default 0).

        Returns:
            list[int]: Padded or truncated list of length `max_length`.

        """
        if not isinstance(domain_indices, list) or not all(
            isinstance(i, int) for i in domain_indices
        ):
            raise TypeError("domain_indices must be a list of integers")
        if not isinstance(max_domain_length, int) or max_domain_length <= 0:
            raise ValueError("max_domain_length must be a positive integer")
        if not isinstance(pad_char, int):
            raise TypeError("pad_char must be an integer")
        if len(domain_indices) > max_domain_length:
            return domain_indices[:max_domain_length]
        return domain_indices + [pad_char] * (max_domain_length - len(domain_indices))
