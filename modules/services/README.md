# Sovereign Modular Network Vulnerability Scanner

## Project Overview

This project implements a modular, scalable, and self-contained framework 
for performing **network-layer vulnerability scanning** across critical 
protocols without reliance on third-party APIs or external services.

Each scanner is a standalone, importable Python module designed for 
extensibility, safe operation, and deep network analysis, adhering to 
rigorous best practices.

This project was architected by Wadih Khairallah, reflecting a deep 
commitment to sovereignty, precision, and ethical network analysis.

## Key Features

- Passive and non-destructive scanning philosophy.
- Modular structure: one module per protocol (`check_<protocol>.py`).
- CLI runnable and importable as Python modules.
- JSON-structured output by default.
- Tight connection timeouts to avoid hangs.
- TLS/SSL validation (where applicable).
- Default credential exposure checks (safe single-shot).
- Fingerprinting and protocol behavior analysis.
- Scans operate without dependence on external API services.
- Line-wrapped at 80 characters for portability.

## Supported Scanners

- SSH (`check_ssh.py`)
- DNS (`check_dns.py`)
- HTTP/HTTPS (`check_http.py`)
- Mail (SMTP, POP3, IMAP) (`check_mail.py`)
- FTP/FTPS (`check_ftp.py`)
- SNMP (`check_snmp.py`)
- Telnet (`check_telnet.py`)
- RDP (`check_rdp.py`)
- LDAP/LDAPS (`check_ldap.py`)
- MySQL (`check_mysql.py`)
- MSSQL (`check_mssql.py`)

## Technical Specifications

- Python 3 standard libraries (socket, ssl).
- External lightweight libraries:
    - pymysql (MySQL scanner)
    - pymssql (MSSQL scanner)
    - ldap3 (LDAP scanner)
    - pysnmp (SNMP scanner)
- `argparse` used for CLI options.
- All modules structured with:
    - `scan_<protocol>(target: str) -> dict`
    - `main()` entrypoint for CLI execution.

## Project Structure

```
/modules/
    check_ssh.py
    check_dns.py
    check_http.py
    check_mail.py
    check_ftp.py
    check_snmp.py
    check_telnet.py
    check_rdp.py
    check_ldap.py
    check_mysql.py
    check_mssql.py
README.md
```

## Methodology and Conventions

- Only passive safe probing (banner grabbing, handshake validation).
- No destructive or noisy behaviors (no flooding, no brute-force).
- Default credential probing limited to one attempt per service.
- Standardized `scan_*` functions returning JSON for automation use.
- Uniform error handling across modules.
- Common structure in every module for maintainability.

## Sample Usage

CLI Example:

```
python3 modules/check_http.py --target example.com
```

Programmatic Import:

```python
from modules.check_http import scan_http

results = scan_http("example.com")
print(results)
```

## Output Format

Each module returns:

```json
{
    "domain": "example.com",
    "findings": [
        "SSL certificate expired.",
        "TLS 1.0 support detected.",
        "Directory listing exposed on /uploads/."
    ]
}
```

## Future Extensions

- Extend coverage to other critical services (e.g., SMB, PostgreSQL).
- Implement a unified `scanner_orchestrator.py` runner.
- Introduce vulnerability severity tags to findings.
- Add configurable throttling/delays for extremely cautious scanning.

## User Style Alignment

- Clean, logical groupings.
- Minimal dependencies.
- Structured, testable, extensible design.
- Maximum clarity over complexity.
- Ethical, secure engineering practices.
- Clear documentation embedded with codebases and project artifacts.

## Licensing

This project is intended for private use, audits, self-assessment, 
and educational security research. Respect all laws and terms of 
network scanning where applicable.

## Maintainer

- Name: Wadih Khairallah
- Email: wadih@smallroom.com

## Assistant Findings

- The modular structure promotes extreme maintainability.
- Standardized function signatures enable simple orchestration.
- Line wrapping and documentation rigor ensures long-term 
  portability and resilience.
- Careful design avoids accidental active attacks, fitting 
  ethical pentesting models.
- Immediate opportunities include orchestrator design and 
  adding lightweight vulnerability scoring.

