from torch import (
    Tensor,
    cat,
    device as torchDevice,
    long as torchLong,
    no_grad,
    sigmoid,
    tensor,
)
from torch.nn import LSTM, Dropout, Embedding, Linear, Module
from torch.utils.data import Dataset


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

    def __len__(self) -> int:
        return len(self.domains)

    def __getitem__(self, index: int) -> tuple[str, int]:
        return self.domains[index], self.labels[index]

    def get_items(
        self, start_index: int, end_index: int | None = None
    ) -> tuple[list[str], list[int]]:
        """
        Returns two lists: domains and labels from start_index to end_index.
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
        max_domain_length: int,
        pad_char: int,
        vocab_size: int,
        embed_dim: int,
        output_dim: int,
        hidden_size: int,
        num_layers: int,
        dropout_rate: float,
        device: str = 'cpu',
        bidirectional: bool = True,
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
            "char2idx": {c: i + 1 for i, c in enumerate(allowed_chars)},
            "pad_char": int(pad_char),
            "max_domain_length": int(max_domain_length),
            "device": str(device),
            "bidirectional": bool(bidirectional),
        }
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

    def forward(self, encoded_domains: Tensor) -> Tensor:
        """
        Perform a forward pass through the DomainClassifier.
        Args:
            encoded_domains (Tensor): A batch of integer-encoded domain sequences
                with shape [batch_size, sequence_length]. Each integer corresponds
                to a character index in the embedding vocabulary.
        Returns:
            Tensor: Probabilities for each input domain, with shape [batch_size, output_dim].
                Values are in the range [0, 1] due to the final sigmoid activation.
        """
        _embedded = self._input_layer(encoded_domains)
        _lstm_out, (_hidden_states, cell_states) = self._lstm(_embedded)
        _sequence_representation = _hidden_states[-1]
        if self._config["bidirectional"]:
            _sequence_representation = cat(
                (_hidden_states[-2], _hidden_states[-1]), dim=1
            )
        _dropped = self._dropout(_sequence_representation)
        _output_raw = self._output_layer(_dropped)
        return sigmoid(_output_raw)

    def set_and_move_to_device(self, device: str | None = None):
        """
        Move the model to a specified device and update its configuration.
        Args:
            device (str): The target device, e.g., 'cpu' or 'cuda:0'.
        Effects:
            - Updates the model's `self.device` attribute.
            - Updates the internal `_config["device"]` value.
            - Moves all model parameters and buffers to the specified device.
        """
        if device:
            torchDevice(device)
            self._config["device"] = device
        self.to(self._config["device"])

    def predict(self, domains: list[str]) -> Tensor:
        """
        Predict probabilities for a list of raw domain strings.
        Args:
            domains (list[str]): List of domain strings to predict.
        Returns:
            torch.Tensor: Probabilities for each domain, shape [batch_size, output_dim].
        """
        self.eval()
        _vectorised_domains = self.convert_domains_to_tensor(domains=domains).to(
            self._config["device"]
        )
        with no_grad():
            return self.forward(_vectorised_domains)

    def convert_domains_to_tensor(self, domains: list[str]) -> Tensor:
        """
        Convert a list of domain strings to a padded tensor of integer indices.
        Args:
            domains (list[str]): List of domain strings to encode.
            allowed_chars (str): Characters allowed in domains.
            max_domain_length (int): Maximum sequence length (pads or truncates domains).
        Returns:
            torch.Tensor: Tensor of shape [batch_size, max_domain_length], dtype=torch.long.
                        Each element is an integer index corresponding to a character.
                        0 is reserved for padding.
        """
        batch_encoded = []
        for _domain in domains:
            _filtered_doman: str = DomainClassifier._filter_domain(
                domain=_domain, allowed_chars=self._config["allowed_chars"]
            )
            _indexed_domain: list[int] = DomainClassifier._domain_to_indices(
                _filtered_doman, self._config["char2idx"]
            )
            _padded_domain: list[int] = DomainClassifier._pad_domain(
                domain_indices=_indexed_domain,
                max_domain_length=self._config["max_domain_length"],
                pad_char=self._config["pad_char"],
            )
            batch_encoded.append(_padded_domain)
        return tensor(batch_encoded, dtype=torchLong)

    @staticmethod
    def _domain_to_indices(domain: str, char2idx: dict[str, int]) -> list[int]:
        """
        Convert domain to list of integer indices using char2idx mapping.
        Only characters present in char2idx are included.
        """
        return [char2idx[_char] for _char in domain if _char in char2idx]

    @staticmethod
    def _filter_domain(domain: str, allowed_chars: str) -> str:
        """
        Return a copy of `domain` containing only characters from `allowed_chars`.
        Args:
            domain (str): The input string (e.g., a domain name).
            allowed_chars (str): Characters to keep.
        Returns:
            str: The filtered string.
        """
        return "".join([_char for _char in domain if _char in allowed_chars])

    @staticmethod
    def _pad_domain(
        domain_indices: list[int], max_domain_length: int, pad_char: int
    ) -> list[int]:
        """
        Pad or truncate a list of integer indices to a fixed length.
        Args:
            domain_indices (list[int]): List of integer indices for a domain.
            max_domain_length (int): Desired length.
            pad_index (int): Integer index to use for padding (default 0).
        Returns:
            list[int]: Padded or truncated list of length `max_length`.
        """
        if len(domain_indices) > max_domain_length:
            return domain_indices[:max_domain_length]
        return domain_indices + [pad_char] * (max_domain_length - len(domain_indices))
