"""API keys, roles, rate limiting and the production start-up gate."""

import pytest
from src.core.config import Settings, settings
from src.core.security import Principal, TokenBucketLimiter, authenticate_key, parse_api_keys


def test_parse_api_keys_validates_shape_role_and_length():
    parsed = parse_api_keys("alice:analyst:alice-key-0123456789,bob:viewer:bob-key-0123456789abc")
    assert [(n, r) for n, r, _ in parsed] == [("alice", "analyst"), ("bob", "viewer")]
    assert len(parsed[0][2]) == 32  # only SHA-256 digests are held, never the key itself
    for bad in ("alice:analyst", "alice:root:alice-key-0123456789", "alice:analyst:short", ":analyst:alice-key-0123456789"):
        with pytest.raises(ValueError):
            parse_api_keys(bad)
    assert parse_api_keys("") == []


def test_authenticate_key(monkeypatch):
    monkeypatch.setattr(settings, "API_KEYS", "alice:analyst:alice-key-0123456789,svc:ingest:svc-key-0123456789abc")
    assert authenticate_key("alice-key-0123456789") == Principal("alice", "analyst")
    assert authenticate_key("svc-key-0123456789abc") == Principal("svc", "ingest")
    assert authenticate_key("alice-key-0123456780") is None
    assert authenticate_key("") is None and authenticate_key(None) is None


def test_role_permissions():
    assert Principal("a", "viewer").can("read") and not Principal("a", "viewer").can("adjudicate")
    assert Principal("a", "ingest").can("ingest") and not Principal("a", "ingest").can("read")
    assert Principal("a", "analyst").can("contain") and not Principal("a", "analyst").can("admin")
    assert Principal("a", "admin").can("simulate") and not Principal("a", "unknown").can("read")


def test_token_bucket_limits_and_recovers():
    now = [0.0]
    limiter = TokenBucketLimiter(clock=lambda: now[0])
    assert all(limiter.hit("k", 3)[0] for _ in range(3))
    allowed, retry = limiter.hit("k", 3)
    assert allowed is False and retry > 0
    assert limiter.hit("other", 3)[0] is True  # buckets are per key
    now[0] += 20.0  # 3 per minute refills one token every 20 seconds
    assert limiter.hit("k", 3)[0] is True
    assert limiter.hit("k", 0)[0] is True  # a limit of 0 disables limiting


def test_production_refuses_unsafe_configuration():
    unsafe = Settings(APP_ENV="production", TOKENIZATION_KEY_HEX="", API_KEYS="", AUTH_DISABLED=True, LEDGER_PATH="")
    problems = " | ".join(unsafe.production_problems())
    for expected in ("TOKENIZATION_KEY_HEX is not set", "AUTH_DISABLED", "API_KEYS is empty", "LEDGER_PATH"):
        assert expected in problems

    published = Settings(APP_ENV="production", TOKENIZATION_KEY_HEX="0123456789abcdef" * 4, API_KEYS="a:admin:aaaaaaaaaaaaaaaaaaaa", LEDGER_PATH="/tmp/x")
    assert any("published in the repository" in p for p in published.production_problems())
    short = Settings(APP_ENV="production", TOKENIZATION_KEY_HEX="abcd", API_KEYS="a:admin:aaaaaaaaaaaaaaaaaaaa", LEDGER_PATH="/tmp/x")
    assert any("at least 32 bytes" in p for p in short.production_problems())

    good = Settings(APP_ENV="production", TOKENIZATION_KEY_HEX="ab" * 32, API_KEYS="a:admin:aaaaaaaaaaaaaaaaaaaa", LEDGER_PATH="/var/lib/x/ledger.jsonl")
    assert good.production_problems() == []
    assert Settings(APP_ENV="development").production_problems() == []


def test_simulator_and_cors_defaults():
    assert Settings(APP_ENV="development").simulator_enabled is True
    assert Settings(APP_ENV="production").simulator_enabled is False
    assert Settings(APP_ENV="production", ENABLE_SIMULATOR=True).simulator_enabled is True
    assert Settings(CORS_ORIGINS="https://soc.bank.example, *").cors_origins == ["https://soc.bank.example"]  # a wildcard is never honoured
    assert Settings(CORS_ORIGINS="").cors_origins == []
