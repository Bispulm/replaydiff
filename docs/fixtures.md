# Fixtures

`replaydiff-fixture` is a synthetic order service. Everything it returns is
invented. It exists so detection can be tested against a known answer.

Run one process per role. Each keeps its own state.

```bash
replaydiff-fixture --variant baseline  --instance a --listen 127.0.0.1:18201
replaydiff-fixture --variant baseline  --instance b --listen 127.0.0.1:18202
replaydiff-fixture --variant candidate --instance c --listen 127.0.0.1:18203
```

## Deliberate candidate regressions

| Route | Change | Kind |
|---|---|---|
| `GET /v1/orders/{id}` | `customer.tier` removed | Removed field |
| `GET /v1/orders/{id}` | `total` number becomes a string | Changed type |
| `GET /v1/orders/ord-missing` | 404 becomes 500 | Status class |
| `GET /v1/users/{id}` | `display_name` upper-cased | Value change |
| `GET /v1/users/{id}` | `loyalty_points` added | Additive field |
| `GET /v1/inventory/{sku}` | `stock_estimate` number becomes a string | Changed type on a noisy field |
| `GET /v1/inventory/{sku}` | `warehouse_hint` removed | Removed noisy field |
| `GET /v1/reports/daily` | Extra latency (`--candidate-latency`) | Latency |

## Noise and controls

- `server_time`, `generated_at` and `request_id` vary per call on every replica.
- `stock_estimate` and `warehouse_hint` vary between the two baselines.
- `GET /v1/catalog` has no regressions and acts as the control route.

## Routes for failure testing

| Route | Purpose |
|---|---|
| `POST /v1/orders`, `POST /v1/login` | Mutating calls, counted at `GET /__fixture/stats` |
| `GET /v1/me` | Returns 401 without an `Authorization` header |
| `GET /v1/cart/{sid}/step/{n}` | Returns 409 when a session's steps arrive out of order |
| `GET /v1/compressed` | Serves gzip when accepted |
| `GET /v1/redirect` | Redirects off-origin to `forbidden.invalid` |
| `GET /v1/protocol` | Reports the protocol the fixture saw, to prove a hop's HTTP version |

`--h2c` serves only HTTP/2 without TLS. `--tls-cert` and `--tls-key` serve TLS and
negotiate HTTP/2.
