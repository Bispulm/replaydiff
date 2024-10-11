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

An end-to-end test requires exactly these findings, so an extra one is a false positive and a
missing one is a regression the tool failed to find.

| Route | Change | Expected finding |
|---|---|---|
| `GET /v1/orders/{id}` | `customer.tier` removed | Breaking `field_removed` |
| `GET /v1/orders/{id}` | `total` number becomes a string | Breaking `type_changed` |
| `GET /v1/orders/ord-missing` | 404 becomes 500 | Breaking `status_class_changed` |
| `GET /v1/inventory/{sku}` | `stock_estimate` number becomes a string, on a noisy field | Breaking `type_changed` |
| `GET /v1/inventory/{sku}` | `warehouse_hint` removed, on a noisy field | Breaking `field_removed` |
| `GET /v1/users/{id}` | `display_name` upper-cased | Warning `value_changed` |
| `GET /v1/reports/daily` | Extra latency (`--candidate-latency`) | Warning `latency_regression` |
| `GET /v1/users/{id}` | `loyalty_points` added | Info `field_added` |

## Noise and controls

- `server_time`, `generated_at` and `request_id` vary per call on every replica.
- `stock_estimate` and `warehouse_hint` vary between the two baselines.
- `GET /v1/catalog` has no regressions and acts as the control route, so all it should
  produce is explained noise.

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
