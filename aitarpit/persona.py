"""Deterministic fake-company persona.

Everything a decoy shows (company name, staff, hostnames, service names, fake
secrets) comes from here so that the whole surface tells one consistent story.
Generation is seeded: the same ``persona.seed`` always produces the same
company, which keeps decoys stable across restarts and lets the test tool know
what to expect.

All secrets produced here are synthetic. They look like real credential
formats but grant nothing, anywhere.
"""

from __future__ import annotations

import hashlib
import random
import string
from dataclasses import dataclass, field
from functools import cached_property

FIRST_NAMES = [
    "Anna", "Bram", "Chloe", "Daan", "Elena", "Farid", "Greta", "Hugo", "Ines", "Jonas", "Katrin", "Lucas",
    "Maya", "Nils", "Olivia", "Pieter", "Quentin", "Rosa", "Sven", "Tara", "Umar", "Vera", "Willem", "Yara",
    "Zoe", "Adrien", "Bianca", "Cyril", "Dora", "Emil", "Fleur", "Gaspard", "Hanna", "Igor", "Julia", "Karim",
]
LAST_NAMES = [
    "Jansen", "de Vries", "Bakker", "Visser", "Smit", "Meyer", "Martin", "Dubois", "Rossi", "Novak", "Kowalski",
    "Lindqvist", "Moreau", "Schmidt", "Fischer", "Laurent", "Bernard", "Petit", "Garcia", "Silva", "Horvat",
    "Andersen", "Nielsen", "Weber", "Wagner", "Becker", "Hoffmann", "Leroy", "Fontaine", "Marchetti",
]
DEPARTMENTS = ["IT Operations", "Security", "Finance", "Engineering", "Fleet Management", "HR", "Sales", "Legal"]
TITLES = {
    "IT Operations": ["SysAdmin", "Cloud Engineer", "IT Manager", "Helpdesk Lead"],
    "Security": ["CISO", "Security Engineer", "SOC Analyst"],
    "Finance": ["CFO", "Accountant", "Controller"],
    "Engineering": ["Backend Developer", "DevOps Engineer", "Engineering Manager", "QA Engineer"],
    "Fleet Management": ["Fleet Manager", "Dispatcher", "Logistics Planner"],
    "HR": ["HR Manager", "Recruiter"],
    "Sales": ["Account Manager", "Sales Director"],
    "Legal": ["General Counsel", "Compliance Officer"],
}
HOST_PREFIXES = ["srv", "app", "db", "vault", "ci", "bkp", "k8s", "jump", "mail", "files"]


@dataclass(frozen=True)
class Employee:
    first: str
    last: str
    department: str
    title: str
    username: str
    email: str


@dataclass
class Persona:
    company: str
    domain: str
    seed: int
    short_name: str = ""
    industry: str = "logistics"
    city: str = ""
    employees_count: int = 60
    services: list[str] = field(default_factory=list)

    @classmethod
    def from_config(cls, cfg: dict) -> "Persona":
        p = cfg["persona"] if "persona" in cfg else cfg
        return cls(
            company=p["company"],
            domain=p["domain"],
            seed=int(p["seed"]),
            short_name=p.get("short_name") or p["company"].split()[0],
            industry=p.get("industry", "logistics"),
            city=p.get("city", ""),
            employees_count=int(p.get("employees", 60)),
            services=list(p.get("services") or []),
        )

    # ------------------------------------------------------------------ randomness
    def rng(self, *scope: object) -> random.Random:
        """A Random instance deterministic for (seed, scope). Use one scope per consumer."""
        h = hashlib.sha256(("|".join([str(self.seed), *map(str, scope)])).encode()).digest()
        return random.Random(int.from_bytes(h[:8], "big"))

    @property
    def slug(self) -> str:
        return "".join(ch for ch in self.short_name.lower() if ch.isalnum()) or "corp"

    # ------------------------------------------------------------------ staff
    @cached_property
    def employees(self) -> list[Employee]:
        r = self.rng("employees")
        seen: set[str] = set()
        out: list[Employee] = []
        while len(out) < self.employees_count:
            first, last = r.choice(FIRST_NAMES), r.choice(LAST_NAMES)
            base = (first[0] + last.replace(" ", "")).lower()
            username = base
            n = 2
            while username in seen:
                username = f"{base}{n}"
                n += 1
            seen.add(username)
            dept = DEPARTMENTS[len(out) % len(DEPARTMENTS)] if len(out) < len(DEPARTMENTS) else r.choice(DEPARTMENTS)
            title = r.choice(TITLES[dept])
            out.append(Employee(first, last, dept, title, username, f"{username}@{self.domain}"))
        return out

    def employees_in(self, department: str) -> list[Employee]:
        return [e for e in self.employees if e.department == department]

    @property
    def admin(self) -> Employee:
        ops = self.employees_in("IT Operations")
        return ops[0] if ops else self.employees[0]

    # ------------------------------------------------------------------ infrastructure
    @cached_property
    def hosts(self) -> list[dict]:
        r = self.rng("hosts")
        hosts = []
        for i, svc in enumerate(self.services or ["intranet"]):
            prefix = HOST_PREFIXES[i % len(HOST_PREFIXES)]
            hosts.append({
                "name": f"{prefix}-{svc}-{r.randint(1, 9):02d}.{self.domain}",
                "service": svc,
                "ip": f"10.{r.randint(10, 60)}.{r.randint(0, 254)}.{r.randint(2, 250)}",
                "env": r.choice(["prod", "prod", "staging"]),
            })
        return hosts

    # ------------------------------------------------------------------ synthetic secrets
    def token(self, kind: str, *scope: object, length: int = 32) -> str:
        """Synthetic secret shaped like ``kind``. Deterministic for (seed, kind, scope)."""
        r = self.rng("token", kind, *scope)
        alnum = string.ascii_letters + string.digits
        if kind == "aws_access_key":
            return "AKIA" + "".join(r.choice(string.ascii_uppercase + "234567") for _ in range(16))
        if kind == "aws_secret_key":
            return "".join(r.choice(alnum + "/+") for _ in range(40))
        if kind == "github":
            return "ghp_" + "".join(r.choice(alnum) for _ in range(36))
        if kind == "slack":
            return "xoxb-" + "-".join("".join(r.choice(string.digits) for _ in range(n)) for n in (12, 13)) + "-" + "".join(r.choice(alnum) for _ in range(24))
        if kind == "jwt_secret" or kind == "hex":
            return "".join(r.choice("0123456789abcdef") for _ in range(length * 2))
        if kind == "password":
            words = ["Harbor", "Falcon", "Cargo", "Atlas", "Delta", "Summit", "Nordic", "Pilot", "Anchor", "Comet"]
            return f"{r.choice(words)}{r.choice(words)}{r.randint(10, 99)}{r.choice('!#$%&*')}"
        if kind == "bearer":
            return "".join(r.choice(alnum) for _ in range(length))
        return "".join(r.choice(alnum) for _ in range(length))

    # ------------------------------------------------------------------ text helpers
    def describe(self) -> dict:
        return {
            "company": self.company,
            "short_name": self.short_name,
            "domain": self.domain,
            "industry": self.industry,
            "city": self.city,
            "services": self.services,
            "employees": len(self.employees),
            "admin": self.admin.email,
            "hosts": self.hosts,
        }
