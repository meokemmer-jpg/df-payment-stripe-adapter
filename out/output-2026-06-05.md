# df-payment-stripe-adapter — Output [CRUX-MK]
*Autonom aktiviert 2026-06-05T15:51:03.254346+00:00 | ollama-local/qwen2.5:14b-instruct*

# Dark-Factory 'df-payment-stripe-adapter' Dokumentation

## Ziel und Umfang

Die **Dark-Factory df-payment-stripe-adapter** ist ein Real-API-Wave-1 Adap
Adapter für Stripe Payment Intents und Webhook-Signaturverifikation (SHA256
(SHA256). Dieser Prozess ist durch ENV-Variablen kontrolliert, die das Fram
Framework standardmäßig deaktivieren. Der Einsatz in Live-Modus erfordert e
explizit die Bereitstellung eines **PHRONESIS_TICKET**, um jegliche Transak
Transaktionen mit echtem Geld zu schützen (K_0-Schutz).

## Betriebsweise

Der Adapter unterstützt zwei Hauptfunktionen:

1. `create_payment_intent`: Erstellt ein Payment Intent via Stripe REST API
API.
2. `verify_webhook_signature`: Verifiziert Webhooks nach dem HMAC-SHA256-Pr
HMAC-SHA256-Protokoll von Stripe (Replay-Winduwe beträgt 5 Minuten).

Für jede Transaktion ist der **Idempotency-Key** Pflicht, um Replay-Angriff
Replay-Angriffe zu schützen.

## Aktivierungsprozess für Live-API

1. **Phronesis-Zustimmung:** Martin
2. Generierung eines **PHRONESIS_TICKET**, z.B.: `PT-2026-05-13-W53-001`
3. Setzen der ENV-Variablen:
   ```bash
   export DF_STRIPE_REAL_ENABLED=true
   export STRIPE_API_KEY=sk_live_...  # oder sk_test_* für Testmodus
   export PHRONESIS_TICKET=PT-2026-05-13-W53-001  # nur Live-Modus
   ```
4. Automatisches Erstellen eines Audit-Eintrags bei Aktivierung von Real-AP
Real-API.
5. Monitorings-Alarm für jede Live-Charge-Ereignis.

## Sicherheitsbedingungen

- Echtgeld-Chargen sind ohne PHRONESIS_TICKET nicht zulässig (K_0-Schutz).
- Keine Cross-Tenant-Leseoperationen (K11 Tenant-Isolation).
- Jede Charge muss einen Idempotency-Key haben.
- Pflicht zur HMAC-Webhook-Verifikation (Stripe-signed).
- Testmodus (sk_test_*-) ist ohne Phronesis erlaubt (kein K_0-Risiko).

## rho-Schätzung

Die jährliche Nutzung dieser Dark-Factory wird geschätzt bei ca. 60.000 EUR
EUR durch Reduzierung der manuellen Arbeit im Stripe-Dashboard und direkte 
Buchung ohne OTA-Kommission von 18%. Diese Schätzung ist noch unvalidiert (
(rho_validation_source) und soll zurzeit nur für Pilot-Zwecke eingesetzt we
werden.

## Tests

```bash
cd ~/Projects/dark-factories/df-payment-stripe-adapter
python -m pytest tests/ -v
```

Es gibt 12 Pflichttests:

1. Default-Mock (keine ENV) → Mock.
2. ENV-True + sk_test_* → Realtest (ohne PHRONESIS).
3. ENV-True + sk_live_* ohne PHRONESIS → Fallback auf Mock (K_0-Schutz).
4. ENV-True + sk_live_* + PHRONESIS → Real-API.
5. Validierung des Betragsbereichs.
6. Whitelist-Währung-Validierung.
7. Pflicht zur Übermittlung von tenant_id.
8. Pflicht zum Hinzufügen eines Idempotency-Key.
9. Deterministisches Mock-ID für Idempotency-Key.
10. HMAC Valid-Signatur.
11. HMAC Invalid-Signatur.
12. Replay-Angriff (Toleranz 5min).
13. Audit-Record-Format.

Diese Dark-Factory dient zur Optimierung der Payment-Prozesse und trägt daz
dazu bei, die Effizienz der Buchungsprozesse zu steigern, während gleichzei
gleichzeitig wichtige Sicherheitsstandards eingehalten werden.