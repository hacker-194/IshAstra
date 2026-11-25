# Limitations

Known edges of the current release (`4.0.0-rc1`). Each is a deliberate trade
off, not an undiscovered bug.

## Scope and authorization

- A scan is refused when the scope cannot be parsed or verified. That is the
  intended failure mode; it means a malformed `testing_hours` value or an
  unreadable JWKS stops work until fixed.
- Only UTC windows are accepted for `testing_hours`. Convert local schedules.
- IPv6 pinning and DNS-rebinding checks depend on the resolver the worker uses;
  a host that changes answers mid-scan is denied rather than re-evaluated.

## Coverage

- Detection quality is bounded by the adapters (probe, nuclei, nmap, nikto,
  sqlmap). IshAstra correlates and normalizes; it does not invent findings.
- Authenticated scans need a working auth config; multi-step MFA flows are not
  automated through the CLI (`multi_step` requires an auth config file).
- Nuclei and Nmap scripts are restricted to the template allowlist. A template
  you add yourself is out of coverage until it is listed.

## Operations

- SQLite is the default backend and allows one writer. Use PostgreSQL for more
  than a single worker.
- PDF reports require the system libraries WeasyPrint needs; without them the
  CLI falls back to printable HTML.
- Imported SARIF/Nuclei/ZAP findings carry the importing tool's confidence; the
  fields the source format does not provide stay at their defaults.

