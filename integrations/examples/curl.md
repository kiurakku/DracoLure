# DracoLure REST API — curl examples

Set your server (and key, if configured):

```bash
DL=http://localhost:5000
KEY=your-api-key            # only if DRACOLURE_API_KEY is set on the server
```

## Classify a request (ingest)

```bash
curl -s -X POST "$DL/api/v1/ingest" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{"method":"GET","path":"/search","query":"id=1'\'' OR 1=1--","source_ip":"203.0.113.5"}'
```

## Live snapshot

```bash
curl -s "$DL/api/v1/stats" -H "X-API-Key: $KEY"
```

## Recent events (only score ≥ 25)

```bash
curl -s "$DL/api/v1/events?limit=20&min_score=25" -H "X-API-Key: $KEY"
```

## Quarantine / release a source

```bash
curl -s -X POST "$DL/api/v1/block"   -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" -d '{"ip":"203.0.113.5","ttl_seconds":600}'

curl -s -X POST "$DL/api/v1/unblock" -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" -d '{"ip":"203.0.113.5"}'
```
