"""Basic Tests fuer DF-PAYMENT-STRIPE-ADAPTER [CRUX-MK].

Per env-var-gated-real-integration-default.md Pflicht-Tests:
1. Default-Mock-Test (keine ENV-Var → mock)
2. ENV-True + sk_test_ → real-test (kein PHRONESIS_TICKET noetig)
3. ENV-True + sk_live_ ohne PHRONESIS_TICKET → graceful Fallback zu mock (K_0-Schutz)
4. Validation: amount-range + currency-whitelist + tenant-id
5. HMAC Webhook Verify (valid + invalid + replay-window)
6. Source-Field Audit
7. Idempotency-Key Deterministic Mock-ID
"""
from __future__ import annotations

import sys
import pathlib
import time
import hmac as _hmac
import hashlib as _hashlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.adapter import (
    ALLOWED_CURRENCIES,
    MIN_AMOUNT_CENTS,
    MAX_AMOUNT_CENTS,
    PaymentResult,
    mock_create_payment_intent,
    real_create_payment_intent,
    dispatch_payment_intent,
    verify_webhook_signature,
    to_audit_record,
)


def _clear_env(monkeypatch):
    monkeypatch.delenv("DF_STRIPE_REAL_ENABLED", raising=False)
    monkeypatch.delenv("STRIPE_API_KEY", raising=False)
    monkeypatch.delenv("PHRONESIS_TICKET", raising=False)


def test_default_mock_no_env(monkeypatch):
    """Default-Mock: keine ENV-Var → mock_create_payment_intent."""
    _clear_env(monkeypatch)
    result = dispatch_payment_intent(
        amount_cents=5000, currency="eur",
        tenant_id="hildesheim", idempotency_key="bk-001-2026-05-13",
    )
    assert result.source == "mock"
    assert result.status == "mock"
    assert result.amount_cents == 5000
    assert result.currency == "eur"
    assert result.phronesis_ticket is None
    assert result.payment_intent_id.startswith("pi_mock_")


def test_env_true_with_test_key(monkeypatch):
    """ENV=true + sk_test_ → real-test (Stripe-Test-Mode, kein Phronesis noetig)."""
    _clear_env(monkeypatch)
    monkeypatch.setenv("DF_STRIPE_REAL_ENABLED", "true")
    monkeypatch.setenv("STRIPE_API_KEY", "sk_test_dummy_key_for_testing_only")
    result = dispatch_payment_intent(
        amount_cents=2500, currency="usd",
        tenant_id="cape-coral", idempotency_key="bk-002",
    )
    assert result.source == "real-test"
    assert result.payment_intent_id.startswith("pi_real_test_")


def test_env_true_live_without_phronesis_fallback(monkeypatch):
    """ENV=true + sk_live_ ohne PHRONESIS → graceful Fallback zu mock (K_0-Schutz)."""
    _clear_env(monkeypatch)
    monkeypatch.setenv("DF_STRIPE_REAL_ENABLED", "true")
    monkeypatch.setenv("STRIPE_API_KEY", "sk_live_dummy_dangerous_real_key")
    # NO PHRONESIS_TICKET
    result = dispatch_payment_intent(
        amount_cents=10000, currency="eur",
        tenant_id="hildesheim", idempotency_key="bk-003",
    )
    assert result.source == "mock", "Live ohne Phronesis MUSS Mock-Fallback ausloesen (K_0)"


def test_env_true_live_with_phronesis_real(monkeypatch):
    """ENV=true + sk_live_ + PHRONESIS_TICKET → real-api."""
    _clear_env(monkeypatch)
    monkeypatch.setenv("DF_STRIPE_REAL_ENABLED", "true")
    monkeypatch.setenv("STRIPE_API_KEY", "sk_live_dummy_dangerous_real_key")
    monkeypatch.setenv("PHRONESIS_TICKET", "PT-2026-05-13-W53-001")
    result = dispatch_payment_intent(
        amount_cents=5000, currency="eur",
        tenant_id="hildesheim", idempotency_key="bk-004",
    )
    assert result.source == "real-api"
    assert result.phronesis_ticket == "PT-2026-05-13-W53-001"


def test_validation_amount_out_of_range():
    """Amount muss in [1, 100k EUR cents]."""
    with pytest.raises(AssertionError):
        mock_create_payment_intent(0, "eur", "t1", "k1")
    with pytest.raises(AssertionError):
        mock_create_payment_intent(MAX_AMOUNT_CENTS + 1, "eur", "t1", "k1")


def test_validation_currency_whitelist():
    """Currency muss in Whitelist (eur/usd/gbp/chf)."""
    with pytest.raises(AssertionError):
        mock_create_payment_intent(1000, "xyz", "t1", "k1")


def test_validation_missing_tenant_id():
    """tenant_id Pflicht (K11)."""
    with pytest.raises(AssertionError):
        mock_create_payment_intent(1000, "eur", "", "k1")


def test_validation_missing_idempotency_key():
    """idempotency_key Pflicht (replay-protection)."""
    with pytest.raises(AssertionError):
        mock_create_payment_intent(1000, "eur", "t1", "")


def test_idempotency_key_deterministic_id():
    """Mock-Payment-Intent-ID deterministisch aus idempotency_key."""
    r1 = mock_create_payment_intent(1000, "eur", "t1", "stable-key-001")
    r2 = mock_create_payment_intent(1000, "eur", "t1", "stable-key-001")
    assert r1.payment_intent_id == r2.payment_intent_id


def test_hmac_webhook_valid_signature():
    """HMAC-SHA256 Webhook-Verify mit gueltiger Signatur."""
    secret = "whsec_test_secret"
    payload = b'{"event":"charge.succeeded","data":{}}'
    ts = int(time.time())
    signed = f"{ts}.".encode() + payload
    sig = _hmac.new(secret.encode(), signed, _hashlib.sha256).hexdigest()
    sig_header = f"t={ts},v1={sig}"
    assert verify_webhook_signature(payload, sig_header, secret, now_unix=ts) is True


def test_hmac_webhook_invalid_signature():
    """HMAC-SHA256 Webhook-Verify mit ungueltiger Signatur."""
    secret = "whsec_test_secret"
    payload = b'{"event":"charge.succeeded"}'
    ts = int(time.time())
    sig_header = f"t={ts},v1=deadbeef"
    assert verify_webhook_signature(payload, sig_header, secret, now_unix=ts) is False


def test_hmac_webhook_replay_attack():
    """Webhook-Tolerance: > 300s timestamp wird abgelehnt (Replay-Schutz)."""
    secret = "whsec_test_secret"
    payload = b'{"event":"x"}'
    ts_old = int(time.time()) - 3600  # 1h alt
    signed = f"{ts_old}.".encode() + payload
    sig = _hmac.new(secret.encode(), signed, _hashlib.sha256).hexdigest()
    sig_header = f"t={ts_old},v1={sig}"
    assert verify_webhook_signature(payload, sig_header, secret) is False


def test_audit_record_format():
    """Audit-Record-Format Pflicht-Felder (per audit-trail.md §1)."""
    result = mock_create_payment_intent(1500, "eur", "t-aud", "k-aud")
    rec = to_audit_record(result)
    required = {"ts", "df", "payment_intent_id", "tenant_id", "amount_cents",
                "currency", "status", "source", "phronesis_ticket"}
    assert required <= set(rec.keys())
    assert rec["df"] == "DF-PAYMENT-STRIPE-ADAPTER"
