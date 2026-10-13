"""A small causal Transformer language model over the protocol token stream.

This is the deep-learning heart of the project: a GPT-style decoder that learns
the grammar of *benign* DNS by next-token prediction. Conformance scoring is the
model's own per-token surprisal (negative log-likelihood); an attack that breaks
the grammar is, by construction, a sequence the model finds improbable.

The defaults are sized to train on a CPU in a couple of minutes so the result is
reproducible without a GPU. PyTorch is an *optional* dependency — importing this
module without torch raises a clear error, and the pipeline falls back to the
n-gram grammar.
"""
from __future__ import annotations

import math
from typing import List, Optional

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F

    _TORCH = True
except Exception:  # pragma: no cover - exercised only when torch is absent
    _TORCH = False

from ..tokenizer import PAD, Vocab


class TransformerConfig:
    def __init__(
        self,
        vocab_size: int,
        d_model: int = 128,
        n_heads: int = 4,
        n_layers: int = 2,
        d_ff: int = 256,
        max_len: int = 256,
        dropout: float = 0.1,
    ):
        self.vocab_size = vocab_size
        self.d_model = d_model
        self.n_heads = n_heads
        self.n_layers = n_layers
        self.d_ff = d_ff
        self.max_len = max_len
        self.dropout = dropout


def _require_torch():
    if not _TORCH:
        raise RuntimeError(
            "PyTorch is not installed. Install the 'nn' extra (pip install "
            "'syntactica[nn]') or use the n-gram grammar instead."
        )


if _TORCH:

    class _Block(nn.Module):
        def __init__(self, cfg: TransformerConfig):
            super().__init__()
            self.ln1 = nn.LayerNorm(cfg.d_model)
            self.attn = nn.MultiheadAttention(
                cfg.d_model, cfg.n_heads, dropout=cfg.dropout, batch_first=True
            )
            self.ln2 = nn.LayerNorm(cfg.d_model)
            self.ff = nn.Sequential(
                nn.Linear(cfg.d_model, cfg.d_ff),
                nn.GELU(),
                nn.Linear(cfg.d_ff, cfg.d_model),
                nn.Dropout(cfg.dropout),
            )

        def forward(self, x, attn_mask):
            h = self.ln1(x)
            a, _ = self.attn(h, h, h, attn_mask=attn_mask, need_weights=False)
            x = x + a
            x = x + self.ff(self.ln2(x))
            return x

    class _GPT(nn.Module):
        def __init__(self, cfg: TransformerConfig):
            super().__init__()
            self.cfg = cfg
            self.tok = nn.Embedding(cfg.vocab_size, cfg.d_model)
            self.pos = nn.Embedding(cfg.max_len, cfg.d_model)
            self.drop = nn.Dropout(cfg.dropout)
            self.blocks = nn.ModuleList([_Block(cfg) for _ in range(cfg.n_layers)])
            self.ln_f = nn.LayerNorm(cfg.d_model)
            self.head = nn.Linear(cfg.d_model, cfg.vocab_size, bias=False)

        def hidden(self, idx):
            b, t = idx.shape
            pos = torch.arange(t, device=idx.device).unsqueeze(0)
            x = self.drop(self.tok(idx) + self.pos(pos))
            mask = torch.triu(torch.full((t, t), float("-inf"), device=idx.device), diagonal=1)
            for blk in self.blocks:
                x = blk(x, mask)
            return self.ln_f(x)

        def forward(self, idx):
            return self.head(self.hidden(idx))


class TransformerGrammar:
    """Trainer/scorer wrapper around the GPT model."""

    def __init__(self, vocab: Vocab, cfg: Optional[TransformerConfig] = None, device: str = "cpu"):
        _require_torch()
        self.vocab = vocab
        self.cfg = cfg or TransformerConfig(vocab_size=len(vocab))
        self.cfg.vocab_size = len(vocab)
        self.device = device
        self.pad_id = vocab.stoi[PAD]
        self.model = _GPT(self.cfg).to(device)

    # ------------------------------------------------------------------ #
    def _batchify(self, seqs: List[List[int]]):
        maxlen = min(max(len(s) for s in seqs), self.cfg.max_len)
        out = torch.full((len(seqs), maxlen), self.pad_id, dtype=torch.long)
        for i, s in enumerate(seqs):
            s = s[:maxlen]
            out[i, : len(s)] = torch.tensor(s, dtype=torch.long)
        return out.to(self.device)

    def fit(
        self,
        sequences: List[List[int]],
        epochs: int = 6,
        batch_size: int = 128,
        lr: float = 3e-3,
        seed: int = 0,
        log: bool = True,
    ) -> "TransformerGrammar":
        torch.manual_seed(seed)
        opt = torch.optim.AdamW(self.model.parameters(), lr=lr)
        n = len(sequences)
        for epoch in range(epochs):
            self.model.train()
            perm = torch.randperm(n)
            total = 0.0
            for start in range(0, n, batch_size):
                batch = [sequences[i] for i in perm[start : start + batch_size].tolist()]
                x = self._batchify(batch)
                logits = self.model(x[:, :-1])
                target = x[:, 1:]
                loss = F.cross_entropy(
                    logits.reshape(-1, logits.size(-1)),
                    target.reshape(-1),
                    ignore_index=self.pad_id,
                )
                opt.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                opt.step()
                total += loss.item() * len(batch)
            if log:
                print(f"  epoch {epoch + 1}/{epochs}  train_loss={total / n:.4f}")
        return self

    # ------------------------------------------------------------------ #
    @torch.no_grad() if _TORCH else (lambda f: f)
    def sequence_nll(self, seq: List[int]) -> float:
        self.model.eval()
        x = torch.tensor(seq[: self.cfg.max_len], dtype=torch.long, device=self.device).unsqueeze(0)
        if x.size(1) < 2:
            return 0.0
        logits = self.model(x[:, :-1])
        target = x[:, 1:]
        loss = F.cross_entropy(logits.reshape(-1, logits.size(-1)), target.reshape(-1))
        return float(loss.item())

    def perplexity(self, seq: List[int]) -> float:
        return math.exp(self.sequence_nll(seq))

    @torch.no_grad() if _TORCH else (lambda f: f)
    def embed(self, seqs: List[List[int]], batch_size: int = 256):
        """Mean-pooled final-layer representation of each sequence (a flow vector).

        These learned embeddings are what the model uses to judge conformance;
        projecting them to 2D shows whether the grammar has organised traffic
        into meaningful regions (benign vs. each attack family).
        """
        import numpy as np

        self.model.eval()
        out = []
        for start in range(0, len(seqs), batch_size):
            chunk = seqs[start : start + batch_size]
            x = self._batchify(chunk)
            h = self.model.hidden(x)  # (B, T, D)
            mask = (x != self.pad_id).unsqueeze(-1).float()
            pooled = (h * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1)
            out.append(pooled.cpu().numpy())
        return np.concatenate(out, axis=0) if out else np.zeros((0, self.cfg.d_model))

    @torch.no_grad() if _TORCH else (lambda f: f)
    def sequence_nll_batch(self, seqs: List[List[int]], batch_size: int = 256) -> List[float]:
        """Mean per-token NLL for many sequences at once (pad-masked).

        Scoring one message at a time is correct but slow on CPU; batching turns
        the whole evaluation from minutes into seconds without changing results.
        """
        self.model.eval()
        out: List[float] = []
        for start in range(0, len(seqs), batch_size):
            chunk = seqs[start : start + batch_size]
            x = self._batchify(chunk)
            if x.size(1) < 2:
                out.extend(0.0 for _ in chunk)
                continue
            logits = self.model(x[:, :-1])
            target = x[:, 1:]
            tok_loss = F.cross_entropy(
                logits.reshape(-1, logits.size(-1)),
                target.reshape(-1),
                ignore_index=self.pad_id,
                reduction="none",
            ).reshape(target.shape)
            mask = (target != self.pad_id).float()
            per_seq = (tok_loss * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1)
            out.extend(per_seq.tolist())
        return out

    # ------------------------------------------------------------------ #
    def save(self, path: str) -> None:
        torch.save({"state": self.model.state_dict(), "cfg": self.cfg.__dict__}, path)

    def load(self, path: str) -> "TransformerGrammar":
        blob = torch.load(path, map_location=self.device)
        self.model.load_state_dict(blob["state"])
        return self
