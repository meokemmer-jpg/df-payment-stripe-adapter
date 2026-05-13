"""DF-PAYMENT-STRIPE-ADAPTER Engine [CRUX-MK].

Welle-53 Real-API-Wave-1 Top-5-Priority. Stripe Payment Intent + Webhook HMAC.

ENV-Var-gated Default-Disabled. Mock-Fallback bei Real-Mode-Disabled.

Pre/Post-Conditions:
- Pre: amount_cents (int > 0), currency (3-letter), tenant_id (str), idempotency_key (str)
- Post: PaymentResult mit source ("mock"|"real-api"|"real-test"), payment_intent_id, status
"""
from __future__ import annotations

import os
import hmac
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# Constants
ALLOWED_CURRENCIES = ("eur", "usd", "gbp", "chf")
MIN_AMOUNT_CENTS = 1
MAX_AMOUNT_CENTS = 100_000_00  # 100k EUR
WEBHOOK_TOLERANCE_SEC = 300  # 5 Minuten Replay-Window


def iso_now() -> str:
    """Pre: -; Post: ISO-UTC-Timestamp."""
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class PaymentResult:
    """Pflicht-Felder per env-var-gated-real-integration-default.md Property-3."""
    payment_intent_id: str
    status: str               # "succeeded"|"requires_action"|"failed"|"mock"
    amount_cents: int
    currency: str
    tenant_id: str
    idempotency_key: str
    source: str               # "mock"|"real-api"|"real-test"
    iso_timestamp: str
    phronesis_ticket: Optional[str] = None
    raw_response: dict = field(default_factory=dict)


def _validate_payment_input(amount_cents: int, currency: str, tenant_id: str, idempotency_key: str) -> None:
    """Pre/Post-Conditions Validation (K12 non-LLM-validation-layer)."""
    assert isinstance(amount_cents, int), f"amount_cents must be int: {type(amount_cents)}"
    assert MIN_AMOUNT_CENTS <= amount_cents <= MAX_AMOUNT_CENTS, \
        f"amount_cents out of range [{MIN_AMOUNT_CENTS}, {MAX_AMOUNT_CENTS}]: {amount_cents}"
    assert currency.lower() in ALLOWED_CURRENCIES, \
        f"currency not in whitelist {ALLOWED_CURRENCIES}: {currency}"
    assert tenant_id, "tenant_id required (K11 Tenant-Isolation)"
    assert idempotency_key, "idempotency_key required (K11 replay-protection)"


def mock_create_payment_intent(
    amount_cents: int,
    currency: str,
    tenant_id: str,
    idempotency_key: str,
) -> PaymentResult:
    """Mock-Payment-Intent (Default ohne Real-API).

    Pre: validation passing
    Post: PaymentResult mit source='mock', status='mock', payment_intent_id deterministic from key
    """
    _validate_payment_input(amount_cents, currency, tenant_id, idempotency_key)
    return PaymentResult(
        payment_intent_id=f"pi_mock_{idempotency_key[:16]}",
        status="mock",
        amount_cents=amount_cents,
        currency=currency.lower(),
        tenant_id=tenant_id,
        idempotency_key=idempotency_key,
        source="mock",
        iso_timestamp=iso_now(),
        phronesis_ticket=None,
        raw_response={"mock": True},
    )


def real_create_payment_intent(
    amount_cents: int,
    currency: str,
    tenant_id: str,
    idempotency_key: str,
    phronesis_ticket: Optional[str] = None,
) -> PaymentResult:
    """Real-Payment-Intent via Stripe API.

    Pre: STRIPE_API_KEY env-var gesetzt; PHRONESIS_TICKET fuer Live-Mode (sk_live_*)
    Post: PaymentResult mit source='real-api'|'real-test'; fallback zu mock bei Auth-Fehler.

    NOTE: Skeleton-Implementation. Echte HTTP-Calls in Welle-54+.
    """
    _validate_payment_input(amount_cents, currency, tenant_id, idempotency_key)
    api_key = os.environ.get("STRIPE_API_KEY", "")
    if not api_key:
        return mock_create_payment_intent(amount_cents, currency, tenant_id, idempotency_key)

    is_live_mode = api_key.startswith("sk_live_")
    if is_live_mode:
        if not phronesis_ticket:
            phronesis_ticket = os.environ.get("PHRONESIS_TICKET")
        if not phronesis_ticket:
            # K_0-Echtgeld-Schutz: kein Live-Charge ohne Phronesis
            return mock_create_payment_intent(amount_cents, currency, tenant_id, idempotency_key)

    # Skeleton: Skeleton-Stub fuer Stripe-HTTP-Call (Welle-54+ vervollstaendigt mit `requests`)
    source = "real-api" if is_live_mode else "real-test"
    return PaymentResult(
        payment_intent_id=f"pi_{source.replace('-', '_')}_{idempotency_key[:16]}",
        status="requires_action",  # Skeleton: default-state
        amount_cents=amount_cents,
        currency=currency.lower(),
        tenant_id=tenant_id,
        idempotency_key=idempotency_key,
        source=source,
        iso_timestamp=iso_now(),
        phronesis_ticket=phronesis_ticket,
        raw_response={"skeleton": True, "live_mode": is_live_mode},
    )


def dispatch_payment_intent(
    amount_cents: int,
    currency: str,
    tenant_id: str,
    idempotency_key: str,
) -> PaymentResult:
    """Dispatcher mit ENV-Var-Gating (Default-Disabled).

    Default: mock_create_payment_intent.
    Real-Mode: nur wenn DF_STRIPE_REAL_ENABLED='true' UND STRIPE_API_KEY gesetzt.
    """
    real_enabled = os.environ.get("DF_STRIPE_REAL_ENABLED", "").lower() == "true"
    if real_enabled:
        return real_create_payment_intent(amount_cents, currency, tenant_id, idempotency_key)
    return mock_create_payment_intent(amount_cents, currency, tenant_id, idempotency_key)


def verify_webhook_signature(
    payload: bytes,
    sig_header: str,
    secret: str,
    tolerance_sec: int = WEBHOOK_TOLERANCE_SEC,
    now_unix: Optional[int] = None,
) -> bool:
    """HMAC-SHA256 Webhook-Verification (per Stripe-Spec).

    Pre: payload bytes, sig_header in Stripe-Format ("t=...,v1=..."), secret non-empty
    Post: True iff valid signature within tolerance_sec
    """
    if not payload or not sig_header or not secret:
        return False

    # Parse Stripe sig-header: "t=1234567890,v1=hex_signature"
    parts = dict(p.split("=", 1) for p in sig_header.split(",") if "=" in p)
    timestamp_str = parts.get("t", "")
    signature_hex = parts.get("v1", "")

    if not timestamp_str or not signature_hex:
        return False

    try:
        timestamp = int(timestamp_str)
    except ValueError:
        return False

    # Replay-Window-Check
    import time
    now = now_unix if now_unix is not None else int(time.time())
    if abs(now - timestamp) > tolerance_sec:
        return False

    # HMAC-SHA256 compute
    signed_payload = f"{timestamp}.".encode() + payload
    expected = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_hex)


def to_audit_record(result: PaymentResult) -> dict:
    """Serialize PaymentResult fuer audit-log.jsonl (per audit-trail.md §1)."""
    return {
        "ts": result.iso_timestamp,
        "df": "DF-PAYMENT-STRIPE-ADAPTER",
        "payment_intent_id": result.payment_intent_id,
        "tenant_id": result.tenant_id,
        "amount_cents": result.amount_cents,
        "currency": result.currency,
        "status": result.status,
        "source": result.source,
        "phronesis_ticket": result.phronesis_ticket or "none",
    }
