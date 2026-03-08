#!/usr/bin/env python3
import csv
import json
import os
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from typing import Any

import dns.resolver
import requests
import whois
from colorama import Fore, Style, init

init(autoreset=True, strip=False)

DNS_KEYWORDS = [
    "bank",
    "login",
    "secure",
    "account",
    "verify",
    "update",
    "confirm",
    "support",
    "help",
    "official",
    "portal",
    "wallet",
]

HIGH_RISK_TERMS = [
    "login",
    "secure",
    "account",
    "verify",
    "update",
    "wallet",
    "portal",
    "official",
    "support",
    "help",
]

LOW_RISK_TERMS = [
    "vip",
    "invest",
    "investment",
    "vacancy",
    "media",
    "fix",
    "gift",
    "international",
    "bonus",
    "promo",
]

TARGET_DOMAINS = ["gazprom.ru", "gazprom.com"]

SUSPICIOUS_TLDS = {
    ".xyz",
    ".online",
    ".fun",
    ".tech",
    ".bet",
    ".pro",
    ".site",
    ".click",
    ".work",
}

SAFE_TLDS = {
    ".ru",
    ".com",
    ".net",
    ".org",
    ".edu",
    ".gov",
    ".ru.com",
    ".com.ru",
}

HOMOGRAPH_MAP = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "А": "A",
        "В": "B",
        "Е": "E",
        "К": "K",
        "М": "M",
        "Н": "H",
        "О": "O",
        "Р": "R",
        "С": "C",
        "Т": "T",
        "Х": "X",
    }
)

ASCII_VISUAL_REPLACEMENTS = [
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("0", "o"),
    ("1", "l"),
    ("3", "e"),
    ("5", "s"),
]

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")


def log_info(message: str) -> None:
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {message}")


def log_ok(message: str) -> None:
    print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} {message}")


def log_warn(message: str) -> None:
    print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} {message}")


def log_error(message: str) -> None:
    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")


def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def get_domain_base(domain: str) -> str:
    return domain.split(".")[0].lower() if "." in domain else domain.lower()


def get_domain_tokens(domain: str) -> list[str]:
    base = get_domain_base(domain)
    return [token for token in base.split("-") if token]


def normalize_visual_homographs(text: str) -> str:
    normalized = text.lower()
    for src, dst in ASCII_VISUAL_REPLACEMENTS:
        normalized = normalized.replace(src, dst)
    return normalized


def find_keywords(value: str, keywords: list[str]) -> list[str]:
    value_lower = value.lower()
    return [kw for kw in keywords if kw in value_lower]


def find_high_risk_terms(domain: str) -> list[str]:
    domain_lower = domain.lower()
    return [term for term in HIGH_RISK_TERMS if term in domain_lower]


def find_low_risk_terms(domain: str) -> list[str]:
    domain_lower = domain.lower()
    return [term for term in LOW_RISK_TERMS if term in domain_lower]


def is_unicode_homograph(domain: str) -> bool:
    domain_base = get_domain_base(domain)
    return domain_base.translate(HOMOGRAPH_MAP) != domain_base


def is_transposition_away(s1: str, s2: str) -> bool:
    if len(s1) != len(s2):
        return False

    diff_positions = [i for i in range(len(s1)) if s1[i] != s2[i]]
    if len(diff_positions) != 2:
        return False

    i, j = diff_positions
    return s1[i] == s2[j] and s1[j] == s2[i]


def is_ascii_homograph(domain: str, targets: list[str]) -> bool:
    candidates = [get_domain_base(domain)] + get_domain_tokens(domain)

    for candidate in candidates:
        normalized_candidate = normalize_visual_homographs(candidate)

        for target in targets:
            target_base = target.split(".")[0].lower()

            if candidate == target_base:
                continue

            if normalized_candidate == target_base:
                return True

            if levenshtein_distance(normalized_candidate, target_base) <= 1:
                return True

    return False


def is_visual_homograph_of_terms(domain: str, terms: list[str]) -> bool:
    tokens = get_domain_tokens(domain)

    for token in tokens:
        normalized = normalize_visual_homographs(token)
        for term in terms:
            term_lower = term.lower()

            if token == term_lower:
                continue

            if normalized == term_lower:
                return True

            if levenshtein_distance(normalized, term_lower) <= 1:
                return True

    return False


def is_typosquat(domain: str, targets: list[str]) -> bool:
    candidates = [get_domain_base(domain)] + get_domain_tokens(domain)

    for candidate in candidates:
        for target in targets:
            target_base = target.split(".")[0].lower()

            if candidate == target_base:
                continue

            if levenshtein_distance(candidate, target_base) <= 2:
                return True

            if is_transposition_away(candidate, target_base):
                return True

    return False


def contains_target_brand(domain: str, targets: list[str]) -> bool:
    base = get_domain_base(domain)
    for target in targets:
        target_base = target.split(".")[0].lower()
        if target_base in base:
            return True
    return False


def is_exact_brand_base(domain: str, targets: list[str]) -> bool:
    base = get_domain_base(domain)
    for target in targets:
        if base == target.split(".")[0].lower():
            return True
    return False


def has_brand_like_token(domain: str, targets: list[str]) -> bool:
    tokens = get_domain_tokens(domain)

    for token in tokens:
        for target in targets:
            target_base = target.split(".")[0].lower()

            if token == target_base:
                return True

            if levenshtein_distance(token, target_base) <= 2:
                return True

            if is_transposition_away(token, target_base):
                return True

            normalized_token = normalize_visual_homographs(token)
            if normalized_token == target_base:
                return True

    return False


def has_brand_like_substring(domain: str, targets: list[str], min_len: int = 5) -> bool:
    base = get_domain_base(domain)

    for target in targets:
        target_base = target.split(".")[0].lower()

        for i in range(len(base)):
            for j in range(i + min_len, len(base) + 1):
                part = base[i:j]

                if abs(len(part) - len(target_base)) > 2:
                    continue

                if part == target_base:
                    return True

                if levenshtein_distance(part, target_base) <= 2:
                    return True

                normalized_part = normalize_visual_homographs(part)
                if normalized_part == target_base:
                    return True

    return False


def get_tld(domain: str) -> str:
    if "." in domain:
        return "." + domain.split(".")[-1].lower()
    return ""


def get_tld_score(tld: str) -> int:
    if tld in SUSPICIOUS_TLDS:
        return 25
    if tld and tld not in SAFE_TLDS:
        return 10
    return 0


def load_domains(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        log_error(f"Input file not found: {path}")
        return []


def run_command(command: list[str], timeout: int = 60) -> list[str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        if result.returncode != 0:
            stderr = result.stderr.strip()
            if stderr:
                log_warn(f"Command failed: {' '.join(command)} | {stderr}")
            return []

        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    except FileNotFoundError:
        log_warn(f"Tool not installed: {command[0]}")
        return []
    except subprocess.TimeoutExpired:
        log_warn(f"Command timeout: {' '.join(command)}")
        return []
    except Exception as e:
        log_warn(f"Command error: {' '.join(command)} | {e}")
        return []


def run_subfinder(domain: str) -> list[str]:
    log_info(f"Running subfinder for {domain}")
    return run_command(["subfinder", "-d", domain, "-silent"], timeout=120)

def run_theharvester(domain: str) -> list[str]:
    log_info(f"Running theHarvester for {domain}")
    results = run_command(
        ["theHarvester", "-d", domain, "-b", "crtsh,virustotal"],
        timeout=120,
    )

    found = set()
    domain_lower = domain.lower()

    for line in results:
        line = line.strip().lower()
        if domain_lower in line:
            parts = [p.strip(" ,;[]()") for p in line.split()]
            for part in parts:
                if part.endswith(domain_lower):
                    found.add(part)

    return sorted(found)


def aggregate_subdomains(domain: str) -> list[str]:
    results = set()

    for tool_result in [
        run_subfinder(domain),
        run_theharvester(domain),
    ]:
        for item in tool_result:
            results.add(item)

    return sorted(results)


def resolve_dns_records(domain: str, record_type: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=5)
        return [str(r).strip() for r in answers]
    except Exception:
        return []


def find_keywords_in_records(records: list[str], keywords: list[str]) -> list[str]:
    found = set()
    for record in records:
        record_lower = record.lower()
        for kw in keywords:
            if kw in record_lower:
                found.add(kw)
    return sorted(found)


def get_dns_info(domain: str) -> dict[str, Any]:
    a_records = resolve_dns_records(domain, "A")
    aaaa_records = resolve_dns_records(domain, "AAAA")
    mx_records = resolve_dns_records(domain, "MX")
    ns_records = resolve_dns_records(domain, "NS")
    cname_records = resolve_dns_records(domain, "CNAME")
    txt_records = resolve_dns_records(domain, "TXT")

    resolves = bool(a_records or aaaa_records or cname_records)

    dns_keyword_hits = sorted(
        set(
            find_keywords_in_records(mx_records, DNS_KEYWORDS)
            + find_keywords_in_records(ns_records, DNS_KEYWORDS)
            + find_keywords_in_records(cname_records, DNS_KEYWORDS)
            + find_keywords_in_records(txt_records, DNS_KEYWORDS)
        )
    )

    return {
        "dns_resolves": resolves,
        "a_records": a_records,
        "aaaa_records": aaaa_records,
        "mx_records": mx_records,
        "ns_records": ns_records,
        "cname_records": cname_records,
        "txt_records": txt_records,
        "a_count": len(a_records),
        "aaaa_count": len(aaaa_records),
        "mx_count": len(mx_records),
        "ns_count": len(ns_records),
        "cname_count": len(cname_records),
        "txt_count": len(txt_records),
        "dns_keyword_hits": dns_keyword_hits,
    }


def get_dns_score(dns_info: dict[str, Any]) -> int:
    score = 0

    if not dns_info.get("dns_resolves"):
        score += 20

    if dns_info.get("ns_count", 0) == 0:
        score += 15

    if dns_info.get("mx_count", 0) == 0:
        score += 5

    return score


def normalize_whois_field(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value if v)
    if value is None:
        return ""
    return str(value)


def normalize_datetime(value: Any) -> str:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, datetime):
                return item.isoformat()
        return ""

    if isinstance(value, datetime):
        return value.isoformat()

    return ""


def get_domain_age_days(creation_date: Any) -> int | str:
    if isinstance(creation_date, list):
        creation_date = next(
            (item for item in creation_date if isinstance(item, datetime)),
            None,
        )

    if not isinstance(creation_date, datetime):
        return ""

    if creation_date.tzinfo is None:
        creation_date = creation_date.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    delta = now - creation_date
    return max(delta.days, 0)


def get_whois_info(domain: str) -> dict[str, Any]:
    try:
        data = whois.whois(domain)

        country = normalize_whois_field(getattr(data, "country", ""))
        org = normalize_whois_field(getattr(data, "org", ""))
        registrar = normalize_whois_field(getattr(data, "registrar", ""))
        emails = normalize_whois_field(getattr(data, "emails", ""))
        creation_date_raw = getattr(data, "creation_date", None)

        combined = " ".join([country, org, registrar, emails]).lower()
        privacy_markers = ["privacy", "redacted", "whoisguard", "protected", "proxy"]

        return {
            "whois_country": country,
            "whois_org": org,
            "whois_registrar": registrar,
            "whois_privacy": any(marker in combined for marker in privacy_markers),
            "whois_creation_date": normalize_datetime(creation_date_raw),
            "domain_age_days": get_domain_age_days(creation_date_raw),
        }
    except Exception:
        return {
            "whois_country": "",
            "whois_org": "",
            "whois_registrar": "",
            "whois_privacy": False,
            "whois_creation_date": "",
            "domain_age_days": "",
        }


def get_ssl_info(domain: str) -> dict[str, Any]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        if not isinstance(cert, dict):
            return {
                "ssl_issuer": "",
                "ssl_not_after": "",
                "ssl_days_left": "",
            }

        issuer_name = ""
        issuer = cert.get("issuer", [])
        if isinstance(issuer, list):
            for item in issuer:
                if isinstance(item, tuple):
                    for pair in item:
                        if (
                            isinstance(pair, tuple)
                            and len(pair) == 2
                            and isinstance(pair[0], str)
                            and isinstance(pair[1], str)
                        ):
                            if pair[0] in {"organizationName", "commonName"}:
                                issuer_name = pair[1]
                                break
                    if issuer_name:
                        break

        not_after_value = cert.get("notAfter", "")
        not_after = not_after_value if isinstance(not_after_value, str) else ""

        days_left: int | str = ""
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days_left = (expiry - datetime.now(timezone.utc)).days

        return {
            "ssl_issuer": issuer_name,
            "ssl_not_after": not_after,
            "ssl_days_left": days_left,
        }

    except Exception as e:
        log_warn(f"SSL check failed for {domain}: {e}")
        return {
            "ssl_issuer": "",
            "ssl_not_after": "",
            "ssl_days_left": "",
        }


def get_virustotal_info(domain: str) -> dict[str, Any]:
    if not VIRUSTOTAL_API_KEY:
        return {
            "vt_enabled": False,
            "vt_found": False,
            "vt_malicious": "",
            "vt_suspicious": "",
            "vt_harmless": "",
            "vt_undetected": "",
            "vt_reputation": "",
        }

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=20,
        )

        if response.status_code != 200:
            return {
                "vt_enabled": True,
                "vt_found": False,
                "vt_malicious": "",
                "vt_suspicious": "",
                "vt_harmless": "",
                "vt_undetected": "",
                "vt_reputation": "",
            }

        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "vt_enabled": True,
            "vt_found": True,
            "vt_malicious": stats.get("malicious", 0),
            "vt_suspicious": stats.get("suspicious", 0),
            "vt_harmless": stats.get("harmless", 0),
            "vt_undetected": stats.get("undetected", 0),
            "vt_reputation": attributes.get("reputation", 0),
        }
    except Exception:
        return {
            "vt_enabled": True,
            "vt_found": False,
            "vt_malicious": "",
            "vt_suspicious": "",
            "vt_harmless": "",
            "vt_undetected": "",
            "vt_reputation": "",
        }


def build_recommendation_reason(
    domain_keywords: list[str],
    high_risk_terms: list[str],
    low_risk_terms: list[str],
    suspicious_subdomains: list[str],
    whois_info: dict[str, Any],
    ssl_info: dict[str, Any],
    vt_info: dict[str, Any],
    dns_info: dict[str, Any] | None = None,
    is_exact_brand_flag: bool = False,
    is_typosquat_flag: bool = False,
    is_unicode_homograph_flag: bool = False,
    is_ascii_homograph_flag: bool = False,
    is_term_homograph_flag: bool = False,
    contains_brand: bool = False,
    has_brand_token: bool = False,
    has_brand_substring: bool = False,
    tld_score: int = 0,
) -> str:
    if dns_info is None:
        dns_info = {}

    reasons = []

    if domain_keywords:
        reasons.append(f"keywords in domain: {', '.join(domain_keywords)}")

    dns_keyword_hits = dns_info.get("dns_keyword_hits", [])
    if dns_keyword_hits:
        reasons.append(f"keywords in DNS records: {', '.join(dns_keyword_hits)}")

    if high_risk_terms:
        reasons.append(f"high-risk terms: {', '.join(high_risk_terms)}")

    if low_risk_terms:
        reasons.append(f"context terms: {', '.join(low_risk_terms)}")

    if is_exact_brand_flag:
        reasons.append("exact brand base detected in domain")

    if has_brand_token:
        reasons.append("brand-like token detected")
    elif has_brand_substring:
        reasons.append("brand-like substring detected inside domain")

    if is_typosquat_flag:
        reasons.append("typosquatting detected")

    if is_unicode_homograph_flag:
        reasons.append("Unicode homograph detected")

    if is_ascii_homograph_flag:
        reasons.append("ASCII visual homograph detected")

    if is_term_homograph_flag:
        reasons.append("visual homograph of important word detected")

    if contains_brand and not has_brand_token and not has_brand_substring:
        reasons.append("brand appears as substring")

    if tld_score >= 25:
        reasons.append("suspicious TLD zone")
    elif tld_score > 0:
        reasons.append("unusual TLD zone")

    if suspicious_subdomains:
        reasons.append(f"suspicious subdomains: {len(suspicious_subdomains)}")

    if not dns_info.get("dns_resolves", True):
        reasons.append("domain does not resolve in DNS")

    if dns_info.get("ns_count", 1) == 0:
        reasons.append("no NS records found")

    if dns_info.get("mx_count", 1) == 0:
        reasons.append("no MX records found")

    if whois_info.get("whois_privacy"):
        reasons.append("WHOIS privacy enabled")

    if not whois_info.get("whois_country"):
        reasons.append("WHOIS country unavailable")

    domain_age_days = whois_info.get("domain_age_days")
    if isinstance(domain_age_days, int):
        if domain_age_days < 30:
            reasons.append("very new domain")
        elif domain_age_days < 180:
            reasons.append("recently registered domain")

    ssl_days_left = ssl_info.get("ssl_days_left")
    if isinstance(ssl_days_left, int):
        if ssl_days_left < 0:
            reasons.append("SSL certificate expired")
        elif ssl_days_left < 30:
            reasons.append("SSL certificate expires soon")
    else:
        reasons.append("SSL certificate unavailable")

    vt_mal = vt_info.get("vt_malicious")
    vt_susp = vt_info.get("vt_suspicious")
    vt_rep = vt_info.get("vt_reputation")
    vt_found = vt_info.get("vt_found", False)

    if vt_found:
        if isinstance(vt_mal, int) and vt_mal > 0:
            reasons.append(f"VirusTotal malicious detections: {vt_mal}")

        if isinstance(vt_susp, int) and vt_susp > 0:
            reasons.append(f"VirusTotal suspicious detections: {vt_susp}")

        if isinstance(vt_rep, int) and vt_rep < 0:
            reasons.append(f"VirusTotal negative reputation: {vt_rep}")

    if not reasons:
        return "no strong suspicious indicators detected"

    return "; ".join(reasons)


def score_domain(
    domain: str,
    domain_keywords: list[str],
    high_risk_terms: list[str],
    low_risk_terms: list[str],
    suspicious_subdomains: list[str],
    whois_info: dict[str, Any],
    ssl_info: dict[str, Any],
    vt_info: dict[str, Any],
    dns_info: dict[str, Any] | None = None,
    is_exact_brand_flag: bool = False,
    is_typosquat_flag: bool = False,
    is_unicode_homograph_flag: bool = False,
    is_ascii_homograph_flag: bool = False,
    is_term_homograph_flag: bool = False,
    contains_brand: bool = False,
    has_brand_token: bool = False,
    has_brand_substring: bool = False,
    tld_score: int = 0,
) -> tuple[int, str]:
    if domain in TARGET_DOMAINS:
        return 0, "allow"

    if dns_info is None:
        dns_info = {}

    score = 0

    if domain_keywords:
        score += min(len(domain_keywords) * 8, 16)

    dns_keyword_hits = dns_info.get("dns_keyword_hits", [])
    if dns_keyword_hits:
        score += min(len(dns_keyword_hits) * 6, 12)

    if high_risk_terms:
        score += min(len(high_risk_terms) * 6, 12)

    if low_risk_terms:
        score += min(len(low_risk_terms) * 2, 4)

    if has_brand_token:
        score += 8
    elif has_brand_substring:
        score += 8

    if is_exact_brand_flag:
        score += 20

    if is_typosquat_flag:
        score += 35

    if is_unicode_homograph_flag:
        score += 32

    if is_ascii_homograph_flag:
        score += 35

    if is_term_homograph_flag:
        score += 18

    if is_ascii_homograph_flag and high_risk_terms:
        score += 8

    if is_term_homograph_flag and (has_brand_token or has_brand_substring):
        score += 8

    if (has_brand_token or has_brand_substring) and low_risk_terms:
        score += 6

    if contains_brand and tld_score > 0:
        score += 6

    tld = get_tld(domain)
    if is_exact_brand_flag and tld not in {".ru", ".com"}:
        score += 20

    if is_exact_brand_flag and tld in {".co", ".biz", ".info", ".online", ".site", ".xyz"}:
        score += 10

    if is_exact_brand_flag and (high_risk_terms or low_risk_terms):
        score += 10

    if (contains_brand or has_brand_token or has_brand_substring or is_exact_brand_flag) and (
    high_risk_terms or low_risk_terms):
        score += 10

    tld = get_tld(domain)
    if is_typosquat_flag and tld in {".com", ".net", ".org"}:
        score += 10

    score += tld_score
    score += get_dns_score(dns_info)

    if suspicious_subdomains:
        score += min(len(suspicious_subdomains) * 5, 20)

    if whois_info.get("whois_privacy"):
        score += 10

    if not whois_info.get("whois_country"):
        score += 5

    domain_age_days = whois_info.get("domain_age_days")
    if isinstance(domain_age_days, int) and (
        has_brand_token or has_brand_substring or is_typosquat_flag or is_exact_brand_flag
    ):
        if domain_age_days < 30:
            score += 15
        elif domain_age_days < 180:
            score += 8

    ssl_days_left = ssl_info.get("ssl_days_left")
    if isinstance(ssl_days_left, int):
        if ssl_days_left < 0:
            score += 20
        elif ssl_days_left < 30:
            score += 12
        elif ssl_days_left < 90:
            score += 6
    else:
        score += 10

    vt_mal = vt_info.get("vt_malicious")
    vt_susp = vt_info.get("vt_suspicious")
    vt_rep = vt_info.get("vt_reputation")

    if isinstance(vt_mal, int) and vt_mal > 0:
        score += min(40, vt_mal * 15)

    if isinstance(vt_susp, int) and vt_susp > 0:
        score += min(20, vt_susp * 8)

    if isinstance(vt_rep, int) and vt_rep < 0:
        score += min(15, abs(vt_rep))

    score = min(score, 100)

    if score >= 70:
        verdict = "block"
    elif score >= 40:
        verdict = "review"
    else:
        verdict = "allow"

    return score, verdict


def main() -> None:
    input_file = "input/domains.txt"
    csv_output_file = "output/report.csv"
    json_output_file = "output/report.json"
    block_csv_output_file = "output/blocklist.csv"
    review_csv_output_file = "output/review.csv"

    os.makedirs("output", exist_ok=True)

    domains = load_domains(input_file)
    if not domains:
        log_warn("No domains found for scanning")
        return

    log_info(f"Loaded {len(domains)} domains from {input_file}")

    rows = []

    for domain in domains:
        log_info(f"Scanning domain: {domain}")

        domain_keywords = find_keywords(domain, DNS_KEYWORDS)
        high_risk_terms = find_high_risk_terms(domain)
        low_risk_terms = find_low_risk_terms(domain)

        all_subdomains = aggregate_subdomains(domain)
        suspicious_subdomains = [
            sub
            for sub in all_subdomains
            if find_keywords(sub, DNS_KEYWORDS)
            or find_high_risk_terms(sub)
            or find_low_risk_terms(sub)
        ]

        whois_info = get_whois_info(domain)
        ssl_info = get_ssl_info(domain)
        dns_info = get_dns_info(domain)
        vt_info = get_virustotal_info(domain)

        if vt_info.get("vt_enabled"):
            log_info(
                f"VT for {domain}: found={vt_info.get('vt_found')} "
                f"mal={vt_info.get('vt_malicious')} "
                f"susp={vt_info.get('vt_suspicious')} "
                f"rep={vt_info.get('vt_reputation')}"
            )

        is_exact_brand = is_exact_brand_base(domain, TARGET_DOMAINS)
        is_ts = is_typosquat(domain, TARGET_DOMAINS)
        is_unicode_hg = is_unicode_homograph(domain)
        is_ascii_hg = is_ascii_homograph(domain, TARGET_DOMAINS)
        is_term_hg = is_visual_homograph_of_terms(
            domain, HIGH_RISK_TERMS + LOW_RISK_TERMS
        )
        contains_brand = contains_target_brand(domain, TARGET_DOMAINS)
        has_brand_token = has_brand_like_token(domain, TARGET_DOMAINS)
        has_brand_substring = has_brand_like_substring(domain, TARGET_DOMAINS)

        tld = get_tld(domain)
        tld_pts = get_tld_score(tld)

        score, verdict = score_domain(
            domain=domain,
            domain_keywords=domain_keywords,
            high_risk_terms=high_risk_terms,
            low_risk_terms=low_risk_terms,
            suspicious_subdomains=suspicious_subdomains,
            whois_info=whois_info,
            ssl_info=ssl_info,
            vt_info=vt_info,
            dns_info=dns_info,
            is_exact_brand_flag=is_exact_brand,
            is_typosquat_flag=is_ts,
            is_unicode_homograph_flag=is_unicode_hg,
            is_ascii_homograph_flag=is_ascii_hg,
            is_term_homograph_flag=is_term_hg,
            contains_brand=contains_brand,
            has_brand_token=has_brand_token,
            has_brand_substring=has_brand_substring,
            tld_score=tld_pts,
        )

        recommendation_reason = build_recommendation_reason(
            domain_keywords=domain_keywords,
            high_risk_terms=high_risk_terms,
            low_risk_terms=low_risk_terms,
            suspicious_subdomains=suspicious_subdomains,
            whois_info=whois_info,
            ssl_info=ssl_info,
            vt_info=vt_info,
            dns_info=dns_info,
            is_exact_brand_flag=is_exact_brand,
            is_typosquat_flag=is_ts,
            is_unicode_homograph_flag=is_unicode_hg,
            is_ascii_homograph_flag=is_ascii_hg,
            is_term_homograph_flag=is_term_hg,
            contains_brand=contains_brand,
            has_brand_token=has_brand_token,
            has_brand_substring=has_brand_substring,
            tld_score=tld_pts,
        )

        row = {
            "domain": domain,
            "domain_keywords": ",".join(domain_keywords),
            "high_risk_terms": ",".join(high_risk_terms),
            "low_risk_terms": ",".join(low_risk_terms),
            "contains_brand": contains_brand,
            "is_exact_brand": is_exact_brand,
            "has_brand_token": has_brand_token,
            "has_brand_substring": has_brand_substring,
            "is_typosquat": is_ts,
            "is_unicode_homograph": is_unicode_hg,
            "is_ascii_homograph": is_ascii_hg,
            "is_term_homograph": is_term_hg,
            "tld": tld,
            "dns_resolves": dns_info["dns_resolves"],
            "a_count": dns_info["a_count"],
            "aaaa_count": dns_info["aaaa_count"],
            "mx_count": dns_info["mx_count"],
            "ns_count": dns_info["ns_count"],
            "cname_count": dns_info["cname_count"],
            "txt_count": dns_info["txt_count"],
            "a_records": ",".join(dns_info["a_records"]),
            "mx_records": ",".join(dns_info["mx_records"]),
            "ns_records": ",".join(dns_info["ns_records"]),
            "cname_records": ",".join(dns_info["cname_records"]),
            "txt_records": ",".join(dns_info["txt_records"]),
            "dns_keyword_hits": ",".join(dns_info["dns_keyword_hits"]),
            "subdomains_found": len(all_subdomains),
            "suspicious_subdomains": ",".join(suspicious_subdomains),
            "whois_country": whois_info["whois_country"],
            "whois_org": whois_info["whois_org"],
            "whois_registrar": whois_info["whois_registrar"],
            "whois_privacy": whois_info["whois_privacy"],
            "whois_creation_date": whois_info["whois_creation_date"],
            "domain_age_days": whois_info["domain_age_days"],
            "ssl_issuer": ssl_info["ssl_issuer"],
            "ssl_not_after": ssl_info["ssl_not_after"],
            "ssl_days_left": ssl_info["ssl_days_left"],
            "vt_enabled": vt_info["vt_enabled"],
            "vt_found": vt_info["vt_found"],
            "vt_malicious": vt_info["vt_malicious"],
            "vt_suspicious": vt_info["vt_suspicious"],
            "vt_harmless": vt_info["vt_harmless"],
            "vt_undetected": vt_info["vt_undetected"],
            "vt_reputation": vt_info["vt_reputation"],
            "suspicion_score": score,
            "verdict": verdict,
            "recommendation_reason": recommendation_reason,
        }

        rows.append(row)

        if verdict == "block":
            log_warn(f"{domain} -> score={score}, verdict={verdict}")
        else:
            log_ok(f"{domain} -> score={score}, verdict={verdict}")

    rows.sort(key=lambda x: x["suspicion_score"], reverse=True)

    if not rows:
        log_warn("No rows to save")
        return

    fieldnames = list(rows[0].keys())

    with open(csv_output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with open(json_output_file, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)

    block_rows = [row for row in rows if row["verdict"] == "block"]
    review_rows = [row for row in rows if row["verdict"] == "review"]

    if block_rows:
        with open(block_csv_output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(block_rows)
        log_ok(f"Blocklist CSV saved to {block_csv_output_file}")

    if review_rows:
        with open(review_csv_output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(review_rows)
        log_ok(f"Review CSV saved to {review_csv_output_file}")

    total = len(rows)
    allow_count = sum(1 for row in rows if row["verdict"] == "allow")
    review_count = sum(1 for row in rows if row["verdict"] == "review")
    block_count = sum(1 for row in rows if row["verdict"] == "block")

    typosquat_count = sum(1 for row in rows if row["is_typosquat"])
    unicode_hg_count = sum(1 for row in rows if row["is_unicode_homograph"])
    ascii_hg_count = sum(1 for row in rows if row["is_ascii_homograph"])
    brand_count = sum(
        1
        for row in rows
        if row["contains_brand"] or row["has_brand_token"] or row["has_brand_substring"]
    )
    vt_positive_count = sum(
        1
        for row in rows
        if isinstance(row["vt_malicious"], int) and row["vt_malicious"] > 0
    )

    log_ok(f"CSV report saved to {csv_output_file}")
    log_ok(f"JSON report saved to {json_output_file}")
    log_info(
        f"Summary: total={total}, allow={allow_count}, review={review_count}, block={block_count}"
    )
    log_info(
        "Indicators summary: "
        f"brand_related={brand_count}, "
        f"typosquat={typosquat_count}, "
        f"unicode_homograph={unicode_hg_count}, "
        f"ascii_homograph={ascii_hg_count}, "
        f"vt_positive={vt_positive_count}"
    )


if __name__ == "__main__":
    main()
