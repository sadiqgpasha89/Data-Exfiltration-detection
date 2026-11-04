"""Edge tokenization: keyed pseudonyms, masking and query sanitization."""

import pytest
from src.core.models import TelemetryEvent
from src.data_engineering.tokenizer import OpenStackEdgeTokenizer

KEY_A, KEY_B = "ab" * 32, "cd" * 32


def event(**kw):
    base = dict(event_id="t1", source_ip="10.240.12.84", destination_ip="203.0.113.9", destination_port=443, user_id="usr_dev_4091")
    base.update(kw)
    return TelemetryEvent(**base)


def test_tokens_are_deterministic_keyed_and_prefix_separated():
    a1, a2, b = OpenStackEdgeTokenizer(KEY_A), OpenStackEdgeTokenizer(KEY_A), OpenStackEdgeTokenizer(KEY_B)
    t = a1.tokenize_identifier("usr_dev_4091", "usr_tok")
    assert t == a2.tokenize_identifier("usr_dev_4091", "usr_tok")  # stable across instances with the same key
    assert t != b.tokenize_identifier("usr_dev_4091", "usr_tok")   # a different key gives unrelated tokens
    assert t != a1.tokenize_identifier("usr_dev_4091", "other")    # domain separation by prefix
    assert t.startswith("usr_tok_") and len(t) == len("usr_tok_") + 16 and "usr_dev_4091" not in t
    assert a1.tokenize_identifier("") == ""


def test_ephemeral_key_in_development_when_unset():
    one, two = OpenStackEdgeTokenizer(""), OpenStackEdgeTokenizer("")
    assert one.tokenize_identifier("x") != two.tokenize_identifier("x")  # random per instance, not a shared default


def test_mask_ip_keeps_prefix_pseudonymizes_internal_hosts_only():
    tok = OpenStackEdgeTokenizer(KEY_A)
    masked = tok.mask_ip("10.240.12.84")
    assert masked.startswith("10.240.x.") and "12.84" not in masked
    assert masked == tok.mask_ip("10.240.12.84")
    assert tok.mask_ip("172.20.5.9").startswith("172.20.x.")  # all of 172.16.0.0/12, not just 172.16.x
    assert tok.mask_ip("203.0.113.9") == "203.0.113.9"          # external addresses are kept for threat intel
    assert tok.mask_ip("fd00:1:2:3:4:5:6:7").startswith("fd00:0001:0002::x:")
    assert tok.mask_ip("not-an-ip") == "0.0.0.0" and tok.mask_ip("") == "0.0.0.0"


def test_sanitize_query_removes_values_but_keeps_structure():
    tok = OpenStackEdgeTokenizer(KEY_A)
    q = tok.sanitize_query("SELECT * FROM t WHERE name = 'O''Brien' AND card = '4111 1111 1111 1111' AND ssn='123-45-6789' AND id = 42 AND x IN (7) AND mail = 'a@b.co'")
    assert "O''Brien" not in q and "4111" not in q and "123-45-6789" not in q and "a@b.co" not in q
    assert q.count("[TOKEN_STR]") == 4 and "id = [TOKEN_NUM]" in q
    assert q.startswith("SELECT * FROM t WHERE name =")
    # a bare card number outside quotes is found by pattern; an arbitrary 16-digit number that is not a card is left alone
    assert "[TOKEN_CREDIT_CARD]" in tok.sanitize_query("INSERT INTO log VALUES (4111111111111111)")
    assert "1234567890123456" in tok.sanitize_query("order 1234567890123456")
    assert tok.sanitize_query("") == ""


def test_process_event_never_forwards_raw_user_or_payload():
    tok = OpenStackEdgeTokenizer(KEY_A)
    out = tok.process_event(event(raw_payload="SECRET-PAYLOAD " * 100, query="SELECT 1 WHERE c = '5500005555555559'"))
    dumped = out.model_dump_json()
    assert "usr_dev_4091" not in dumped and "SECRET-PAYLOAD" not in dumped and "5500005555555559" not in dumped
    assert out.masked_user_id.startswith("usr_tok_") and out.original_size_bytes > out.tokenized_size_bytes


def test_honeytoken_flag_uses_the_shared_registry_in_query_and_payload():
    tok = OpenStackEdgeTokenizer(KEY_A)
    assert tok.process_event(event(query="SELECT * FROM cardholder_records WHERE card_number = '4532-0198-4421-9988'")).is_honeytoken_hit
    assert tok.process_event(event(raw_payload="dump: 4532019844219988")).is_honeytoken_hit  # separators removed
    assert not tok.process_event(event(query="SELECT 1")).is_honeytoken_hit
