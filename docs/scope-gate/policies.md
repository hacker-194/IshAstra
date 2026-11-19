# Policy-as-Code (CIDR + ASN + Geo)

# Policy-as-Code: CIDR + ASN + Geo

Advanced policy engine for network authorization using CIDR, ASN, and geographic rules.

## Overview

Strix Scope Gate supports three policy dimensions for `authorized_networks`:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Policy Dimensions                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. CIDR (Network)                                               │
│     "10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"            │
│     → Direct IP range matching                                   │
│                                                                  │
│  2. ASN (Autonomous System Number)                               │
│     "AS15169", "AS13335", "AS16509"                             │
│     → Google, Cloudflare, AWS networks                          │
│                                                                  │
│  3. Geo (Geographic)                                             │
│     "country:US", "country:EU", "region:US-CA"                  │
│     → Country/region based authorization                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

All three can be combined in a single scope document.

## CIDR Policies

### Basic CIDR

```json
{
  "authorized_networks": [
    "10.0.0.0/8",
    "192.168.0.0/16",
    "172.16.0.0/12",
    "2001:db8::/32"
  ]
}
```

### CIDR with Metadata (v2.1+)

```json
{
  "authorized_networks": [
    {"cidr": "10.0.0.0/8", "label": "US-East VPC", "environment": "production"},
    {"cidr": "10.1.0.0/16", "label": "US-West VPC", "environment": "staging"},
    {"cidr": "192.168.0.0/16", "label": "On-premises DC", "environment": "production"}
  ]
}
```

**Schema**:
```json
{
  "type": "array",
  "items": {
    "oneOf": [
      {"type": "string", "pattern": "^([0-9]{1,3}\\.){3}[0-9]{1,3}(/[0-9]{1,2})?$|^([0-9a-fA-F:]+)(/[0-9]{1,3})?$"},
      {
        "type": "object",
        "required": ["cidr"],
        "properties": {
          "cidr": {"type": "string", "pattern": "^([0-9]{1,3}\\.){3}[0-9]{1,3}(/[0-9]{1,2})?$|^([0-9a-fA-F:]+)(/[0-9]{1,3})?$"},
          "label": {"type": "string", "maxLength": 128},
          "environment": {"type": "string", "enum": ["production", "staging", "development", "testing"]},
          "owner": {"type": "string", "format": "email"}
        }
      }
    ]
  }
}
```

### IPv6 Support

Full IPv6 CIDR support:

```json
{
  "authorized_networks": [
    "2001:db8::/32",           // Documentation
    "2001:db8:1::/48",         // Production IPv6
    "2001:db8:2::/48",         // Staging IPv6
    "fc00::/7"                 // ULA (if explicitly needed)
  ]
}
```

---

## ASN Policies

### Concept

ASN (Autonomous System Number) policies allow authorizing entire organizational networks without listing every CIDR.

```
AS15169 (Google) → 300+ CIDRs automatically resolved
AS13335 (Cloudflare) → 200+ CIDRs automatically resolved
AS16509 (Amazon) → 5000+ CIDRs automatically resolved
```

### Configuration

```json
{
  "authorized_networks": [
    "AS15169",      // Google
    "AS13335",      // Cloudflare
    "AS16509",      // Amazon AWS
    "AS8075",       // Microsoft Azure
    "AS396982"      // DigitalOcean
  ]
}
```

### With Metadata

```json
{
  "authorized_networks": [
    {"asn": "AS15169", "label": "Google Cloud", "services": ["compute", "storage", "sql"]},
    {"asn": "AS13335", "label": "Cloudflare", "services": ["cdn", "waf", "dns"]},
    {"asn": "AS16509", "label": "AWS", "regions": ["us-east-1", "us-west-2", "eu-west-1"]}
  ]
}
```

### ASN Resolution

**File**: `src/strix/core/policy_asn.py` — `ASNResolver`

```python
class ASNResolver:
    def __init__(self, cache_ttl: int = 86400):  # 24h cache
        self.cache_ttl = cache_ttl
        self._cache: dict[str, list[str]] = {}

    async def resolve(self, asn: str) -> list[str]:
        """Resolve ASN to list of CIDRs"""
        if asn in self._cache:
            cached, timestamp = self._cache[asn]
            if time.time() - timestamp < self.cache_ttl:
                return cached

        # Fetch from multiple sources
        cidrs = await self._fetch_from_sources(asn)

        self._cache[asn] = (cidrs, time.time())
        return cidrs

    async def _fetch_from_sources(self, asn: str) -> list[str]:
        sources = [
            f"https://api.bgpview.io/asn/{asn}/prefixes",
            f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}",
            f"https://api.ipinfo.io/v1/asn/{asn}/prefixes?token={TOKEN}",
        ]

        all_cidrs = set()
        for source in sources:
            try:
                cidrs = await self._fetch_source(source)
                all_cidrs.update(cidrs)
            except Exception:
                continue  # Fail open - other sources may work

        return list(all_cidrs)
```

### Layer 2 Integration

When ASN policies are used, Layer 2 resolution includes ASN check:

```python
async def _authorize_layer2(self, url: str, scope: ScopeDocument) -> AuthResult:
    parsed = parse_url(url)
    addresses = await resolve_host(parsed.host)

    for addr in addresses:
        # 1. Check CIDR allowlist
        if self._ip_in_cidrs(addr, scope.get_cidrs()):
            continue

        # 2. Check ASN allowlist
        if scope.has_asn_policies():
            asn = await self._get_asn(addr)
            if asn and asn in scope.get_asns():
                continue

        # 3. Check Geo allowlist
        if scope.has_geo_policies():
            geo = await self._get_geo(addr)
            if geo and self._geo_matches(geo, scope.get_geo_policies()):
                continue

        # 4. Nothing matched → DENY
        return DENY(f"ip_not_authorized: {addr}")

    return ALLOW(layer=2, addresses=addresses)
```

### ASN Data Sources

| Source | Coverage | Update Frequency | Auth Required |
|--------|----------|------------------|---------------|
| BGPView | Global | Real-time | No |
| RIPEstat | Global (RIPE region) | Near real-time | No |
| IPInfo | Global | Daily | Yes (token) |
| MaxMind GeoIP2 | Global | Weekly | Yes (license) |
| AWS IP Ranges | AWS only | Daily | No |
| GCP IP Ranges | GCP only | Daily | No |
| Azure IP Ranges | Azure only | Weekly | No |

### Fallback Behavior

```
Primary: BGPView API
  ↓ (fail)
Secondary: RIPEstat
  ↓ (fail)
Tertiary: Cached cloud provider ranges (AWS/GCP/Azure)
  ↓ (fail)
Static: Built-in major ASN lists (updated per release)
```

---

## Geo Policies

### Concept

Geographic policies authorize based on IP location (country, region, city).

### Configuration

```json
{
  "authorized_networks": [
    "country:US",
    "country:CA",
    "country:GB",
    "region:US-CA",       // California
    "region:US-NY",       // New York
    "city:San Francisco"
  ]
}
```

### With Metadata

```json
{
  "authorized_networks": [
    {"geo": "country:US", "label": "United States", "compliance": ["SOC2", "HIPAA"]},
    {"geo": "country:EU", "label": "European Union", "compliance": ["GDPR"]},
    {"geo": "region:US-CA", "label": "California", "data_residency": true}
  ]
}
```

### Geo Resolution

**File**: `src/strix/core/policy_geo.py` — `GeoResolver`

```python
class GeoResolver:
    def __init__(self, db_path: str = "/usr/share/GeoIP/GeoLite2-Country.mmdb"):
        self.reader = maxminddb.open_database(db_path)

    def resolve(self, ip: str) -> GeoInfo | None:
        try:
            return self.reader.get(ip)
        except Exception:
            return None

    def match(self, geo: GeoInfo, policies: list[str]) -> bool:
        for policy in policies:
            if policy.startswith("country:") and geo.country.iso_code == policy[8:]:
                return True
            if policy.startswith("region:") and geo.subdivisions:
                for sub in geo.subdivisions:
                    if sub.iso_code == policy[7:]:
                        return True
            if policy.startswith("city:") and geo.city:
                if geo.city.names.get("en") == policy[5:]:
                    return True
        return False
```

### Geo Data Sources

| Source | Accuracy | Update | License |
|--------|----------|--------|---------|
| MaxMind GeoLite2 | Country: 99%, City: 80% | Weekly | Free (attribution) |
| MaxMind GeoIP2 | Country: 99.8%, City: 90% | Weekly | Paid |
| IPInfo | Country: 99%, City: 85% | Daily | Freemium |
| DB-IP | Country: 99%, City: 75% | Monthly | Free/Paid |

---

## Combining Policies

### Union Logic (OR)

All policy types are **OR'd together** — an IP passes if it matches ANY policy.

```json
{
  "authorized_networks": [
    "10.0.0.0/8",           // CIDR: Internal network
    "AS15169",              // ASN: Google Cloud
    "country:US",           // Geo: United States
    "region:US-CA"          // Geo: California
  ]
}
```

**Evaluation for IP `35.192.10.5` (Google Cloud, US-CA):**
1. CIDR `10.0.0.0/8` → NO
2. ASN `AS15169` → YES (Google) → **ALLOW**

### Precedence

Order doesn't matter — first match wins for performance, but logically it's a union.

```python
def _ip_authorized(self, ip: str, scope: ScopeDocument) -> bool:
    # Check CIDR (fastest, in-memory)
    if self._ip_in_cidrs(ip, scope.cidrs):
        return True

    # Check ASN (cached, may need lookup)
    if scope.asns:
        asn = self._get_asn(ip)
        if asn and asn in scope.asns:
            return True

    # Check Geo (cached, may need lookup)
    if scope.geo_policies:
        geo = self._get_geo(ip)
        if geo and self._geo_matches(geo, scope.geo_policies):
            return True

    return False
```

---

## Special-Use Address Handling

Special-use addresses are **denied by default** even if they match a policy.

```json
{
  "authorized_networks": [
    "10.0.0.0/8",
    "AS15169",
    "country:US"
  ]
}
```

| IP | CIDR Match | ASN Match | Geo Match | Result |
|----|------------|-----------|-----------|--------|
| `10.0.0.1` | YES | — | — | **ALLOW** |
| `35.192.10.5` | NO | YES (AS15169) | YES (US) | **ALLOW** |
| `127.0.0.1` | NO | NO | NO | **DENY** (loopback) |
| `169.254.169.254` | NO | YES (AS16509) | YES (US) | **DENY** (link-local) |

**To allow special-use addresses**, explicitly add their CIDR:

```json
{
  "authorized_networks": [
    "10.0.0.0/8",
    "169.254.169.254/32",  // Explicitly allow AWS metadata
    "AS15169"
  ]
}
```

---

## Policy DSL (Advanced)

### Policy Expressions

```json
{
  "authorized_networks": {
    "expression": "cidr:10.0.0.0/8 OR asn:AS15169 OR geo:country:US",
    "version": "1.0"
  }
}
```

### Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `OR` | Union (any match) | `cidr:10/8 OR asn:AS15169` |
| `AND` | Intersection (all match) | `asn:AS15169 AND geo:country:US` |
| `NOT` | Exclusion | `cidr:10/8 AND NOT cidr:10.0.0.0/16` |
| `()` | Grouping | `(asn:AS15169 OR asn:AS13335) AND geo:country:US` |

### Expression Evaluation

```python
class PolicyExpressionEvaluator:
    def evaluate(self, expr: str, ip: str) -> bool:
        # Parse expression to AST
        ast = self.parse(expr)

        # Evaluate with IP context
        return self._eval_node(ast, ip)

    def _eval_node(self, node: ASTNode, ip: str) -> bool:
        if node.type == "cidr":
            return self._ip_in_cidr(ip, node.value)
        elif node.type == "asn":
            asn = self._get_asn(ip)
            return asn == node.value
        elif node.type == "geo":
            geo = self._get_geo(ip)
            return self._geo_matches(geo, node.value)
        elif node.type == "or":
            return any(self._eval_node(c, ip) for c in node.children)
        elif node.type == "and":
            return all(self._eval_node(c, ip) for c in node.children)
        elif node.type == "not":
            return not self._eval_node(node.children[0], ip)
        return False
```

---

## Performance

### Caching Strategy

| Policy Type | Cache TTL | Cache Size | Lookup Time (p99) |
|-------------|-----------|------------|-------------------|
| CIDR | N/A (in-memory) | 10k entries | < 0.01ms |
| ASN | 24 hours | 1k ASNs | < 1ms (cached) |
| Geo | 30 days | 100k IPs | < 0.1ms (cached) |

### Warmup

```python
async def warmup_caches(scope: ScopeDocument):
    """Pre-populate caches for known policies"""
    tasks = []

    for asn in scope.asns:
        tasks.append(asn_resolver.resolve(asn))

    # Geo warmed on first use (lazy)

    await asyncio.gather(*tasks)
```

---

## Monitoring

### Policy Metrics

```prometheus
# Policy match rates
scope_gate_policy_match_total{type="cidr", result="allow"}
scope_gate_policy_match_total{type="asn", result="allow"}
scope_gate_policy_match_total{type="geo", result="allow"}

# Resolution latency
scope_gate_asn_resolution_duration_seconds
scope_gate_geo_resolution_duration_seconds

# Cache hit rates
scope_gate_asn_cache_hits_total
scope_gate_geo_cache_hits_total
```

### Alerting

```yaml
# High ASN resolution latency
- alert: ASNResolutionSlow
  expr: histogram_quantile(0.99, scope_gate_asn_resolution_duration_seconds) > 1
  for: 5m

# Low cache hit rate
- alert: ASNCacheMissRateHigh
  expr: rate(scope_gate_asn_cache_misses_total[5m]) / rate(scope_gate_asn_cache_requests_total[5m]) > 0.1
  for: 10m
```

---

## Examples

### Cloud Provider Allowlist

```json
{
  "authorized_networks": [
    "AS16509",      // AWS
    "AS8075",       // Microsoft Azure
    "AS15169",      // Google Cloud
    "AS396982",     // DigitalOcean
    "AS14061",      // Linode
    "AS20473",      // Vultr
    "country:US"    // Fallback for US-based services
  ]
}
```

### Compliance-Focused

```json
{
  "authorized_networks": [
    {"cidr": "10.0.0.0/8", "label": "Production VPC", "compliance": ["SOC2", "PCI-DSS"]},
    {"cidr": "10.1.0.0/16", "label": "Staging VPC", "compliance": ["SOC2"]},
    {"asn": "AS15169", "label": "Google Cloud", "services": ["sql", "storage"], "compliance": ["HIPAA"]},
    {"geo": "country:US", "label": "US Regions", "data_residency": true, "compliance": ["CCPA"]},
    {"geo": "country:EU", "label": "EU Regions", "data_residency": true, "compliance": ["GDPR"]}
  ]
}
```

### Minimal with Cloud Fallback

```json
{
  "authorized_networks": [
    "10.0.0.0/8",     // Known internal
    "AS16509",        // AWS (covers all AWS regions)
    "AS15169",        // Google Cloud
    "AS13335"         // Cloudflare (for proxied services)
  ]
}
```

---

## Troubleshooting

### Common Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| ASN not resolving | API rate limit, network | Check cache, add static fallback |
| Geo mismatch | DB outdated | Update GeoIP database |
| False deny | Special-use address | Explicitly add CIDR for metadata IPs |
| Slow authorization | Cold cache | Run warmup on startup |

### Debug Commands

```bash
# Test policy match
strix policy test --ip 35.192.10.5 --scope scope.json

# Check ASN resolution
strix policy asn-lookup 35.192.10.5

# Check Geo resolution
strix policy geo-lookup 35.192.10.5

# Show cache stats
strix policy cache-stats
```

---

## Related

- [Configuration](../scope-gate/configuration.md)
- [Concepts](../scope-gate/concepts.md)
- [Architecture: Scope Gate](../architecture/scope-gate.md)
- [API: Scope Management](../api/scope-management.md)