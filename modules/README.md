# NetRecon Internal Architecture and Module Development Guide

## Purpose
This document defines the internal structure, philosophy, and development guidelines for extending the NetRecon system with new modules. It is **not intended for public use**, but as an LLM-readable reference for consistent module development and orchestration.

---

## 🧠 NetRecon Design Philosophy

- **Recon Modules (`*_recon.py`)**: Passive or low-impact information gathering. Used to enrich intelligence on domains/IPs.
- **Check Modules (`check_*.py`)**: Vulnerability assessment focused on specific services, typically per-port.
- **Orchestrator (`netrecon.py`)**: Passes each unaltered target to recon modules. Supports domains, IPs, comma-separated lists, or CIDR blocks.

---

## 📁 File Structure

```
netrecon.py                 <-- Orchestrator
modules/
  *_recon.py                <-- Recon intelligence modules
  services/
    check_*.py              <-- Per-service vuln checks
```

---

## ✳️ Recon Module Template (`*_recon.py`)

Each module:
- Must expose a `collect(target: str)` method.
- Must **self-handle** domain/IP disambiguation and conversion logic.
- Should return:

```python
{
  "status": "success" | "error",
  "data": { ... },          # Core data
  "error": "<optional str>" # Present only if error occurred
}
```

### Example (from `dns_recon.py`):
```python
def collect(target: str):
    result = {
        "status": "success",
        "data": {}
    }
    try:
        # Domain/IP distinction logic here
        ...
        result["data"]["A"] = [...]
        ...
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result
```

---

## ⚙️ Service Check Module Template (`check_*.py`)

All `check_*.py` modules follow a format defined in `RESPONSE_TEMPLATE.md`. They return:

```json
{
  "target": "host:port",
  "port": [80],
  "timestamp": "2025-04-28T22:08:30.482120",
  "open": true,
  "vulnerabilities": {
    "check_name": {
      "status": "pass" | "fail" | "error" | "info",
      "detail": "String explanation",
      "summary": ["optional details..."]
    }
  },
  "summary": ["Overall notes..."]
}
```

### Core Design:
- All checks are isolated to their service and port(s).
- A `collect(target: str)` function is required.
- Internal functions like `check_port_open()`, `check_tls_certificate()`, etc., should be modular.
- Handles both individual and batched port scans (e.g., FTP on 21, 990).

### Example: `check_http.py`
- `get_http_banner(url)`
- `check_security_headers(url)`
- `check_default_files(url)`
- `check_http_to_https_redirect(domain)`
- Returns banner info, TLS cert info, redirect behavior, and exposed files.

---

## 🔄 Common Patterns

### Shared Utilities (per module):
- `parse_target(target: str)` → returns `(host, port)`
- `is_ip(host: str)` → boolean
- `check_port_open(host, port)` → boolean
- `datetime.now(timezone.utc).isoformat()` → standardized timestamp

### DNS Modules (Recon + Check):
- Recon pulls A/MX/CNAME/etc. records.
- Service check (`check_dns.py`) includes:
  - Recursion detection
  - Version disclosure
  - Zone transfer attempt
  - DNSSEC, wildcard DNS
  - NXDOMAIN hardening
  - DNS rebinding protection

---

## 🧩 Creating a New Module

1. **Recon Module** (`modules/your_recon.py`)
   - Copy any recon stub (`dns_recon.py`)
   - Implement `collect(target: str)` and fill `data`
   - Ensure graceful error reporting via `result["status"] = "error"`

2. **Service Check** (`modules/services/check_newservice.py`)
   - Use `check_ftp.py` or `check_http.py` as reference.
   - Use the shared vulnerability template in `RESPONSE_TEMPLATE.md`.
   - Avoid crashes on closed ports—check first.
   - Use `status: error` and helpful `detail` messages on exceptions.

---

## 📌 Notes

- Recon modules are plug-and-play. No registration required. Just drop them in `modules/`.
- All modules should handle IP vs domain logic independently.
- No dependencies should be assumed to exist beyond Python standard libraries and those explicitly documented in the project requirements.
- Blacklist and AbuseIPDB integrations are treated as **optional plugins**—safe to fail.

---

## ✅ Next Steps

- Continue validating recon modules for duplicate data.
- Begin porting more `check_*.py` modules for common services.
- Investigate cross-recon aggregation (e.g., DNS A record → ASN lookup fusion).


