"""Default configuration values.

Any key absent from the user's JSON file is taken from here (deep merge).
Technique defaults are NOT stored here: each technique class declares its own
``default_config`` and the loader merges it into ``techniques.<ID>``.
"""

DEFAULT_CONFIG: dict = {
    "persona": {
        "company": "Northwind Logistics",
        "short_name": "Northwind",
        "domain": "northwind-logistics.example",
        "industry": "logistics",
        "city": "Rotterdam",
        "seed": 1337,
        "employees": 60,
        "services": ["intranet", "fleet-api", "billing", "vault", "ci", "backup"],
    },
    "decoy": {
        "host": "0.0.0.0",
        "port": 8080,
        "server_header": "nginx/1.24.0",
        "trust_proxy": False,
        "session_cookie": "NWSESSID",
        "threads": 64,
    },
    "admin": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 8443,
        "token": "",
    },
    "storage": {
        "path": "data/aitarpit.db",
        "store_request_headers": True,
        "store_request_bodies": True,
        "max_body_bytes": 65536,
    },
    "alerts": {
        "console": {
            "enabled": True,
            "color": True,
            "min_severity": "low",
            "show_requests": False,
        },
        "syslog": [],
        "webhooks": [],
    },
    "limits": {
        "max_slow_connections": 32,
        "max_bytes_per_session": 512 * 1024 * 1024,
        "max_body_bytes": 1024 * 1024,
        "session_idle_timeout": 3600,
    },
    "techniques": {},
}

SYSLOG_DEFAULTS: dict = {
    "enabled": True,
    "name": "syslog",
    "protocol": "udp",
    "framing": "octet-counting",
    "facility": "local0",
    "app_name": "aitarpit",
    "format": "rfc5424",
    "min_severity": "low",
    "timeout": 5.0,
}

WEBHOOK_DEFAULTS: dict = {
    "enabled": True,
    "name": "webhook",
    "method": "POST",
    "headers": {},
    "auth": {"type": "none"},
    "timeout": 10.0,
    "verify_tls": True,
    "retries": 3,
    "min_severity": "medium",
}
