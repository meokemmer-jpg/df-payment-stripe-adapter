# DF-PAYMENT-STRIPE-ADAPTER [CRUX-MK]

**Welle-53 Real-API-Wave-1 Top-5-Priority Foundation-DF**
**Version:** 0.1.0-SKELETON
**Status:** SKELETON-CONDITIONAL
**Domain:** payment-gateway / hotel-bookings

## Scope

Real-API-Adapter fuer Stripe Payment Intents + Webhook-HMAC-Verify (SHA256).
ENV-Var-Gated Default-Disabled. **KEIN Real-Charge ohne PHRONESIS_TICKET** (Live-Mode).
Test-Mode (sk_test_*) erlaubt ohne Phronesis fuer Dev/Sandbox.

## Operations

- `create_payment_intent`: POST /v1/payment_intents (Stripe REST API)
- `verify_webhook_signature`: HMAC-SHA256 Stripe-Webhook-Spec (Tolerance 5min Replay-Window)
- Idempotency-Key-Pflicht (K11 replay-protection)

## Real-API-Activation-Workflow

1. **Phronesis-Approval** Martin (Decision-Card geschrieben)
2. **PHRONESIS_TICKET** generiert (z.B. `PT-2026-05-13-W53-001`)
3. **ENV-Vars setzen:**
   ```bash
   export DF_STRIPE_REAL_ENABLED=true
   export STRIPE_API_KEY=sk_live_...   # oder sk_test_ fuer Test-Mode
   export PHRONESIS_TICKET=PT-2026-05-13-W53-001  # nur Live-Mode
   ```
4. **Audit-Log-Eintrag** automatisch bei Real-Aktivierung
5. **Monitoring-Alarm** pro Live-Charge-Event

## Strict-Conditions-Konformitaet

- KEIN Echtgeld ohne PHRONESIS_TICKET (K_0-Schutz)
- KEIN Cross-Tenant-Read (K11 Tenant-Isolation)
- Idempotency-Key-Pflicht pro Charge (replay-protection)
- HMAC-Webhook-Verify Pflicht (Stripe-Signed)
- Test-Mode (sk_test_*) ohne Phronesis erlaubt (kein K_0-Risk)

## CRUX-Bindung

- **K_0:** Echtgeld-Charge-Pfad, PHRONESIS-Gate Pflicht
- **Q_0:** Payment-Integrity via Idempotency + HMAC
- **W_0:** Manuelle Stripe-Dashboard-Zeit reduziert
- **L_Martin:** Live-Mode-Aktivierung explicit Phronesis-Trigger

## rho-Schaetzung

- **Annual:** ~60k EUR (Stripe-Direct ohne OTA-Kommission 18% Booking)
- **Validation:** unvalidated (rho_validation_source) bis Pilot 90+ Tage
- **Hildesheim-Pilot-Target:** Welle-54+

## Tests

```bash
cd ~/Projects/dark-factories/df-payment-stripe-adapter
python -m pytest tests/ -v
```

12 Pflicht-Tests:
1. Default-Mock (no ENV) → mock
2. ENV-True + sk_test_ → real-test (no PHRONESIS)
3. ENV-True + sk_live_ ohne PHRONESIS → mock-fallback (K_0-Schutz)
4. ENV-True + sk_live_ + PHRONESIS → real-api
5. Amount-Range-Validation
6. Currency-Whitelist-Validation
7. tenant_id Pflicht
8. idempotency_key Pflicht
9. Idempotency-Key Deterministic Mock-ID
10. HMAC Valid-Signature
11. HMAC Invalid-Signature
12. HMAC Replay-Attack (Tolerance 5min)
13. Audit-Record-Format

## Promotion-Pfad

- v0.1.0-SKELETON (jetzt): Mock + Test-Mode-API erlaubt
- v0.2.0 (Welle-54): Cross-LLM-Wargame Pflicht + Failure-Injection-Tests
- v0.3.0 (Welle-55+): Hildesheim-Pilot-Sandbox 30 Tage
- v1.0.0: PRODUCTION-READY-CONDITIONAL (Real-Pilot Year-1)

## Beziehung zu anderen Rules+Skills

- **Verstaerkt** `rules/env-var-gated-real-integration-default.md` (ENV-Var-Pattern)
- **Verstaerkt** `rules/df-akzeptanz-kriterien.md` K11-K16 + LC1-LC5
- **Verstaerkt** `rules/pre-production-conditional-default.md` (Default-Tier)
- **Komplementaer zu** `df-pms-opera-adapter` (PMS-Pipeline upstream)

[CRUX-MK]
