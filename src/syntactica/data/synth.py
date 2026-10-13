"""Reproducible synthetic DNS corpora: benign traffic and three attack families.

Real captures are the gold standard, but they are messy to share, often
sensitive, and rarely labelled. Syntactica therefore ships a deterministic
generator so anyone can reproduce every number in the paper with a single
seed, and can *then* swap in their own ``tshark`` captures via ``data/pcap``.

The benign generator models the coarse statistics of real recursive-resolver
traffic (label lengths, qtype mix, dictionary-like labels). Each attack family
targets a *different* part of the learned grammar, which is what makes the
evaluation informative rather than a single blob of "anomaly":

* ``tunnel`` — DNS tunnelling / exfiltration: long, high-entropy labels.
* ``dga``    — algorithmically generated domains: unpronounceable labels.
* ``malformed`` — protocol violations the codec itself rejects or that break
  structural invariants (label-length, qtype, section-count).
"""
from __future__ import annotations

import base64
import random
import string
from typing import Iterable, List

from .schema import DnsMessage, DnsQuestion, DnsRecord

# A dictionary of realistic labels — broad enough that the benign grammar
# generalises to *real* domains, not just the toy corpus. Two pools:
#   _SUBS  — common subdomain/service labels
#   _SLDS  — real second-level domain names people actually resolve
# Mixing them gives benign traffic the pronounceable, Zipf-ish character
# statistics that separate it from DGA noise, while covering enough of the
# real-world head that a user typing "www.wikipedia.org" is not flagged.
_SUBS = (
    "www api cdn mail static assets img image images app apps auth login account "
    "accounts shop store news blog docs help support dev stage staging prod edge "
    "cache media video videos photos music cloud drive files file data search maps "
    "play live stream streaming analytics ns ns1 ns2 mx smtp imap pop vpn portal "
    "admin dashboard status update updates download downloads content secure www2 m "
    "mobile web api2 gateway proxy origin assets1 assets2 s3 storage cdn1 cdn2"
).split()
_SLDS = (
    "google youtube facebook wikipedia amazon reddit twitter instagram linkedin "
    "microsoft apple netflix spotify github gitlab bitbucket stackoverflow medium "
    "cloudflare akamai fastly wordpress adobe oracle salesforce dropbox slack zoom "
    "twitch discord pinterest tumblr yahoo bing duckduckgo mozilla ubuntu debian "
    "python nodejs docker kubernetes nvidia intel samsung sony paypal stripe shopify "
    "airbnb uber lyft booking expedia cnn bbc nytimes theguardian forbes bloomberg "
    "example acme contoso northwind globex initech umbrella university college school"
).split()
_WORDS = _SUBS + _SLDS  # combined pool used where any label will do

_TLDS = ["com", "com", "com", "org", "net", "io", "co", "dev", "app", "ai", "edu",
         "gov", "uk", "de", "in", "us", "info"]

_BENIGN_QTYPES = [1, 1, 1, 28, 28, 5, 15, 16, 33, 2]  # A-heavy, then AAAA/CNAME/MX/…


def _rng(seed: int) -> random.Random:
    return random.Random(seed)


# --------------------------------------------------------------------------- #
# Benign
# --------------------------------------------------------------------------- #
# Syllable pieces for generating *novel but pronounceable* labels. Real benign
# traffic is full of second-level domains the model has never seen, yet they
# obey English-like phonotactics (consonant-vowel alternation). Teaching the
# grammar this structure is what lets it accept "protonmail" or "jsdelivr"
# while still rejecting DGA's unpronounceable consonant soup.
_ONSETS = "b c d f g h j k l m n p r s t v w br cr dr fr gr pr tr st sp sc sh ch th".split()
_VOWELS = "a e i o u ai ea ou".split()
_CODAS = "b d g k l m n p r s t x ng nk st rd ld".split()


def _pronounceable(rng: random.Random) -> str:
    syllables = rng.randint(2, 3)
    out = []
    for _ in range(syllables):
        out.append(rng.choice(_ONSETS) + rng.choice(_VOWELS))
        if rng.random() < 0.5:
            out.append(rng.choice(_CODAS))
    word = "".join(out)
    return word[:15]


def _benign_qname(rng: random.Random) -> str:
    # Realistic shape: [subdomain.]* second-level-domain . tld
    # ~45% of second-level domains are novel-but-pronounceable, so the grammar
    # learns real-world phonotactics rather than memorising a fixed word list.
    sld = _pronounceable(rng) if rng.random() < 0.45 else rng.choice(_SLDS)
    depth = rng.choices([0, 1, 2], weights=[4, 5, 2])[0]  # number of subdomains
    labels = [rng.choice(_SUBS) for _ in range(depth)]
    # Occasionally a bounded numeric/service subdomain (edge3, node12, api2).
    if rng.random() < 0.12:
        labels.insert(0, rng.choice(_SUBS) + str(rng.randint(1, 40)))
    labels.append(sld)
    labels.append(rng.choice(_TLDS))
    return ".".join(labels)


def gen_benign(n: int, seed: int = 0) -> List[DnsMessage]:
    rng = _rng(seed)
    out: List[DnsMessage] = []
    for _ in range(n):
        qname = _benign_qname(rng)
        qtype = rng.choice(_BENIGN_QTYPES)
        q = DnsQuestion(qname, qtype, 1)
        msg = DnsMessage(
            txn_id=rng.randint(0, 0xFFFF),
            qr=0,
            opcode=0,
            rd=1,
            questions=[q],
            label="benign",
        )
        out.append(msg)
    return out


# --------------------------------------------------------------------------- #
# Attack 1: DNS tunnelling / exfiltration
# --------------------------------------------------------------------------- #
def gen_tunnel(n: int, seed: int = 1) -> List[DnsMessage]:
    rng = _rng(seed)
    bases = ["tunnel.example.com", "x.exfil.net", "t.badactor.io", "ns.c2.org"]
    out: List[DnsMessage] = []
    for _ in range(n):
        base = rng.choice(bases)
        # Encode a chunk of "stolen" random payload into base32 labels.
        payload = bytes(rng.getrandbits(8) for _ in range(rng.randint(30, 90)))
        blob = base64.b32encode(payload).decode("ascii").rstrip("=").lower()
        labels = [blob[i : i + rng.randint(20, 40)] for i in range(0, len(blob), 30)]
        qname = ".".join(labels) + "." + base
        qtype = rng.choice([16, 16, 10, 1])  # TXT / NULL-ish / A
        msg = DnsMessage(
            txn_id=rng.randint(0, 0xFFFF),
            qr=0,
            opcode=0,
            rd=1,
            questions=[DnsQuestion(qname, qtype, 1)],
            label="tunnel",
        )
        out.append(msg)
    return out


# --------------------------------------------------------------------------- #
# Attack 2: Domain generation algorithms (DGA)
# --------------------------------------------------------------------------- #
def _dga_label(rng: random.Random) -> str:
    # High-entropy but alphabetic — the classic Conficker/Cryptolocker signature.
    length = rng.randint(10, 22)
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(length))


def gen_dga(n: int, seed: int = 2) -> List[DnsMessage]:
    rng = _rng(seed)
    out: List[DnsMessage] = []
    for _ in range(n):
        qname = _dga_label(rng) + "." + rng.choice(_TLDS)
        msg = DnsMessage(
            txn_id=rng.randint(0, 0xFFFF),
            qr=0,
            opcode=0,
            rd=1,
            questions=[DnsQuestion(qname, 1, 1)],
            label="dga",
        )
        out.append(msg)
    return out


# --------------------------------------------------------------------------- #
# Attack 3: Malformed / protocol-violating
# --------------------------------------------------------------------------- #
def gen_malformed(n: int, seed: int = 3) -> List[DnsMessage]:
    """Structurally invalid messages that break grammar invariants.

    These are represented as :class:`DnsMessage` objects with impossible field
    combinations; the tokenizer surfaces the violation as out-of-grammar tokens.
    """
    rng = _rng(seed)
    out: List[DnsMessage] = []
    for _ in range(n):
        kind = rng.randint(0, 3)
        if kind == 0:  # non-printable / control characters in the label
            junk = "".join(chr(rng.randint(0, 31)) for _ in range(rng.randint(3, 8)))
            qname = junk + "." + rng.choice(_TLDS)
            msg = DnsMessage(questions=[DnsQuestion(qname, 1, 1)], label="malformed")
        elif kind == 1:  # reserved / invalid qtype
            qname = _benign_qname(rng)
            msg = DnsMessage(
                questions=[DnsQuestion(qname, rng.choice([0, 41, 65535, 9999]), 1)],
                label="malformed",
            )
        elif kind == 2:  # qdcount / section mismatch (query carrying answers)
            qname = _benign_qname(rng)
            rec = DnsRecord(qname, 1, 1, 0, b"\x00\x00\x00\x00")
            msg = DnsMessage(
                qr=0, questions=[DnsQuestion(qname, 1, 1)], answers=[rec], label="malformed"
            )
        else:  # over-long single label (>63 octets => illegal)
            qname = "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(70, 120)))
            qname += "." + rng.choice(_TLDS)
            msg = DnsMessage(questions=[DnsQuestion(qname, 1, 1)], label="malformed")
        msg.txn_id = rng.randint(0, 0xFFFF)
        msg.rd = 1
        out.append(msg)
    return out


ATTACK_GENERATORS = {"tunnel": gen_tunnel, "dga": gen_dga, "malformed": gen_malformed}

# Deterministic per-family seed offsets. Using the builtin ``hash`` here would be
# a reproducibility bug: string hashing is salted per process (PYTHONHASHSEED),
# so the corpus — and every number derived from it — would change run to run.
_ATTACK_SEED_OFFSET = {"tunnel": 101, "dga": 211, "malformed": 331}


def build_corpus(
    n_benign: int = 8000,
    n_attack_each: int = 500,
    seed: int = 0,
    attacks: Iterable[str] = ("tunnel", "dga", "malformed"),
):
    """Return ``(train_benign, test_messages)``.

    Training uses *benign only* — the model learns the grammar of normal traffic
    and never sees an attack, which is the whole point of an unsupervised,
    zero-day-capable detector. The test set mixes held-out benign with attacks.
    """
    benign = gen_benign(n_benign, seed=seed)
    split = int(len(benign) * 0.8)
    train_benign = benign[:split]
    test = list(benign[split:])
    for name in attacks:
        offset = _ATTACK_SEED_OFFSET.get(name, len(name) * 7)
        test.extend(ATTACK_GENERATORS[name](n_attack_each, seed=seed + offset))
    rng = _rng(seed + 7)
    rng.shuffle(test)
    return train_benign, test
