// Minimal DracoLure API client for Node.js (>=18, uses global fetch).
// Usage: DRACOLURE_URL=http://localhost:5000 node node_client.js

const BASE = process.env.DRACOLURE_URL || "http://localhost:5000";
const KEY = process.env.DRACOLURE_API_KEY || null;

function headers() {
  const h = { "Content-Type": "application/json" };
  if (KEY) h["X-API-Key"] = KEY;
  return h;
}

export async function ingest(event) {
  const res = await fetch(`${BASE}/api/v1/ingest`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify(event),
  });
  if (!res.ok) throw new Error(`ingest failed: ${res.status}`);
  return res.json();
}

export async function stats() {
  const res = await fetch(`${BASE}/api/v1/stats`, { headers: headers() });
  return res.json();
}

export async function block(ip, ttlSeconds) {
  const res = await fetch(`${BASE}/api/v1/block`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ ip, ttl_seconds: ttlSeconds }),
  });
  return res.json();
}

// Demo when run directly.
if (import.meta.url === `file://${process.argv[1]}`) {
  const verdict = await ingest({
    method: "GET",
    path: "/search",
    query: "id=1' OR 1=1--",
    source_ip: "203.0.113.5",
  });
  console.log("verdict:", verdict);
  console.log("stats:", await stats());
}
