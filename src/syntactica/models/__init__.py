"""Grammar models: a portable n-gram baseline and an optional Transformer LM."""
from .ngram import NGramGrammar

__all__ = ["NGramGrammar"]

try:  # torch is optional
    from .transformer import TransformerConfig, TransformerGrammar  # noqa: F401

    __all__ += ["TransformerConfig", "TransformerGrammar"]
except Exception:  # pragma: no cover
    pass
