{
    "target": "<string - target host or IP originally passed to collect()>",
    "port": [
        <integer - scanned port>,
        <integer - another port if multiple>
    ],
    "timestamp": "<ISO8601 UTC timestamp, e.g., '2025-04-28T22:08:30.482120'>",
    "open": <boolean - true if any port was reachable>,
    "vulnerabilities": {
        "<vulnerability_check_name>": {
            "status": "<'pass' | 'fail' | 'info' | 'error'>",
            "detail": "<string - detailed result description>",
            "summary": [
                "<optional additional line 1>",
                "<optional additional line 2>",
                "<optional additional line 3>"
            ]
        },
        "<another_vulnerability_check>": {
            ...
        }
    },
    "summary": [
        "<string - general scan summary line 1>",
        "<string - general scan summary line 2>",
        "<etc>"
    ]
}
Notes for Developers
target: Always record exactly what was passed into the collect() function.

port: Always a list, even if only one port scanned.

timestamp: Always in UTC, ISO8601 format with microseconds.

open: True if any port from the list was reachable.

vulnerabilities:

Each key is a logical name for the test.

status is mandatory (pass, fail, info, error).

detail is mandatory (human-readable description).

summary is optional, only if needed (list of extra notes).

summary: High-level overall notes across the scan.

Usage Example (Minimal)
json
Copy
Edit
{
    "target": "wadih.com",
    "port": [80, 443],
    "timestamp": "2025-04-28T22:08:30.482120",
    "open": true,
    "vulnerabilities": {
        "tls_certificate_check": {
            "status": "pass",
            "detail": "Valid SSL certificate.",
            "summary": [
                "Certificate issued by Let's Encrypt.",
                "Expires in 89 days."
            ]
        }
    },
    "summary": [
        "No major vulnerabilities detected.",
        "HTTPS correctly enforced."
    ]
}
