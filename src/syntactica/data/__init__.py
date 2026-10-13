"""Data layer: DNS schema, wire codec, synthetic corpora, and pcap ingestion."""
from .codec import DnsDecodeError, decode, encode
from .pcap import iter_dns_from_pcap, iter_dns_with_integrity, load_pcap
from .schema import DnsMessage, DnsQuestion, DnsRecord, labels_of
from .synth import build_corpus, gen_benign, gen_dga, gen_malformed, gen_tunnel

__all__ = [
    "DnsDecodeError",
    "DnsMessage",
    "DnsQuestion",
    "DnsRecord",
    "build_corpus",
    "decode",
    "encode",
    "gen_benign",
    "gen_dga",
    "gen_malformed",
    "gen_tunnel",
    "iter_dns_from_pcap",
    "iter_dns_with_integrity",
    "labels_of",
    "load_pcap",
]
