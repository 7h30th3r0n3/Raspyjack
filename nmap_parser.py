from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any, Callable
import xml.etree.ElementTree as ET


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
VULN_RE = re.compile(r"\b(cve-\d{4}-\d{4,7}|vuln(?:erab(?:le|ility))?|exploit(?:able)?)\b", re.IGNORECASE)
SEVERITY_RE = re.compile(r"\b(critical|high|medium|low)\b", re.IGNORECASE)
SCRIPT_ENRICHERS: dict[str, Callable[[dict[str, Any]], dict[str, Any] | None]] = {}


def register_script_enricher(script_id: str, handler: Callable[[dict[str, Any]], dict[str, Any] | None]) -> None:
    SCRIPT_ENRICHERS[str(script_id or "").strip()] = handler


def parse_nmap_xml(xml_text: str, *, source_path: str | None = None, include_raw_xml: bool = False) -> dict[str, Any]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"invalid nmap xml: {exc}") from exc

    warnings: list[str] = []
    hosts = [_parse_host_node(host, warnings) for host in root.findall("host")]
    payload: dict[str, Any] = {
        "file": {
            "path": source_path,
            "name": Path(source_path).name if source_path else None,
        },
        "scan": _parse_scan_metadata(root),
        "hosts": hosts,
        "stats": _parse_runstats(root.find("runstats"), hosts),
        "warnings": warnings,
    }
    if include_raw_xml:
        payload["raw_xml"] = xml_text
    return payload


def parse_nmap_xml_file(path: str | Path, *, include_raw_xml: bool = False) -> dict[str, Any]:
    file_path = Path(path)
    xml_text = file_path.read_text(encoding="utf-8", errors="replace")
    payload = parse_nmap_xml(xml_text, source_path=str(file_path), include_raw_xml=include_raw_xml)
    try:
        stat = file_path.stat()
        payload.setdefault("file", {})["size"] = stat.st_size
        payload.setdefault("file", {})["mtime"] = int(stat.st_mtime)
    except OSError:
        pass
    return payload


def _parse_scan_metadata(root: ET.Element) -> dict[str, Any]:
    return {
        "scanner": _clean_text(root.get("scanner")),
        "args": _clean_text(root.get("args")),
        "start": _safe_int(root.get("start")),
        "start_str": _clean_text(root.get("startstr")),
        "version": _clean_text(root.get("version")),
        "xml_version": _clean_text(root.get("xmloutputversion")),
    }


def _parse_runstats(runstats: ET.Element | None, hosts: list[dict[str, Any]]) -> dict[str, Any]:
    hosts_node = runstats.find("hosts") if runstats is not None else None
    finished = runstats.find("finished") if runstats is not None else None
    up = _safe_int(hosts_node.get("up")) if hosts_node is not None else None
    down = _safe_int(hosts_node.get("down")) if hosts_node is not None else None
    total = _safe_int(hosts_node.get("total")) if hosts_node is not None else None
    if up is None:
        up = sum(1 for host in hosts if host.get("status") == "up")
    if total is None:
        total = len(hosts)
    if down is None and total is not None and up is not None:
        down = max(total - up, 0)
    return {
        "up": up,
        "down": down,
        "total": total,
        "elapsed": _safe_float(finished.get("elapsed")) if finished is not None else None,
        "summary": _clean_text(finished.get("summary")) if finished is not None else None,
        "exit": _clean_text(finished.get("exit")) if finished is not None else None,
        "time": _safe_int(finished.get("time")) if finished is not None else None,
        "time_str": _clean_text(finished.get("timestr")) if finished is not None else None,
    }


def _parse_host_node(host_node: ET.Element, warnings: list[str]) -> dict[str, Any]:
    status_node = host_node.find("status")
    hostnames = [
        _clean_text(node.get("name"))
        for node in host_node.findall("hostnames/hostname")
        if _clean_text(node.get("name"))
    ]
    addresses = []
    primary_ip = None
    mac = None
    vendor = None
    for address_node in host_node.findall("address"):
        address = _clean_text(address_node.get("addr"))
        addrtype = _clean_text(address_node.get("addrtype"))
        item = {
            "type": addrtype,
            "address": address,
            "vendor": _clean_text(address_node.get("vendor")),
        }
        addresses.append(item)
        if addrtype in ("ipv4", "ipv6") and not primary_ip:
            primary_ip = address
        if addrtype == "mac":
            mac = address
            vendor = item["vendor"]
    if not primary_ip and addresses:
        primary_ip = addresses[0].get("address")

    ports = []
    findings = []
    raw_scripts = []
    vulnerabilities = []
    for port_node in host_node.findall("ports/port"):
        port_item, port_findings, port_raw_scripts, port_vulns = _parse_port_node(port_node)
        ports.append(port_item)
        findings.extend(port_findings)
        raw_scripts.extend(port_raw_scripts)
        vulnerabilities.extend(port_vulns)

    for script_node in host_node.findall("hostscript/script"):
        script_item, script_findings, script_vulns = _parse_script_node(script_node, {"scope": "host"})
        raw_scripts.append(script_item)
        findings.extend(script_findings)
        vulnerabilities.extend(script_vulns)

    os_info = _parse_os_node(host_node.find("os"))
    vulnerabilities = _dedupe_vulnerabilities(vulnerabilities)
    severity_summary = _summarize_vulnerabilities(vulnerabilities)

    if not primary_ip:
        warnings.append("host missing primary address")

    return {
        "ip": primary_ip,
        "hostnames": hostnames,
        "status": _clean_text(status_node.get("state")) if status_node is not None else None,
        "status_reason": _clean_text(status_node.get("reason")) if status_node is not None else None,
        "mac": mac,
        "vendor": vendor,
        "addresses": addresses,
        "ports": ports,
        "os": os_info,
        "vulnerabilities": vulnerabilities,
        "findings": findings,
        "raw_scripts": raw_scripts,
        "severity_summary": severity_summary,
        "debug": {
            "uptime": _parse_uptime(host_node.find("uptime")),
            "distance": _safe_int(host_node.find("distance").get("value")) if host_node.find("distance") is not None else None,
        },
    }


def _parse_port_node(port_node: ET.Element) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    state_node = port_node.find("state")
    service_node = port_node.find("service")
    port_number = _safe_int(port_node.get("portid"))
    protocol = _clean_text(port_node.get("protocol"))
    scripts = []
    findings = []
    raw_scripts = []
    vulnerabilities = []

    context = {
        "scope": "port",
        "port": port_number,
        "protocol": protocol,
    }
    for script_node in port_node.findall("script"):
        script_item, script_findings, script_vulns = _parse_script_node(script_node, context)
        scripts.append(script_item)
        raw_scripts.append(script_item)
        findings.extend(script_findings)
        vulnerabilities.extend(script_vulns)

    return {
        "port": port_number,
        "protocol": protocol,
        "state": _clean_text(state_node.get("state")) if state_node is not None else None,
        "reason": _clean_text(state_node.get("reason")) if state_node is not None else None,
        "service": _clean_text(service_node.get("name")) if service_node is not None else None,
        "product": _clean_text(service_node.get("product")) if service_node is not None else None,
        "version": _clean_text(service_node.get("version")) if service_node is not None else None,
        "extrainfo": _clean_text(service_node.get("extrainfo")) if service_node is not None else None,
        "tunnel": _clean_text(service_node.get("tunnel")) if service_node is not None else None,
        "scripts": scripts,
    }, findings, raw_scripts, vulnerabilities


def _parse_script_node(script_node: ET.Element, context: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    script_id = _clean_text(script_node.get("id")) or "unknown-script"
    structured = _parse_script_children(script_node)
    output = _clean_text(script_node.get("output"))
    base_script = {
        "id": script_id,
        "output": output,
        "structured": structured,
        "context": {
            "scope": context.get("scope"),
            "port": context.get("port"),
            "protocol": context.get("protocol"),
        },
    }

    enricher = SCRIPT_ENRICHERS.get(script_id)
    if enricher:
        try:
            enriched = enricher(base_script)
            if isinstance(enriched, dict):
                base_script.update(enriched)
        except Exception:
            pass

    vulnerabilities = _extract_vulnerabilities(base_script)
    base_script["is_vulnerability"] = bool(vulnerabilities)
    if vulnerabilities:
        base_script["vulnerabilities"] = vulnerabilities

    finding = {
        "type": "script",
        "script_id": script_id,
        "output": output,
        "structured": structured,
        "scope": context.get("scope"),
        "port": context.get("port"),
        "protocol": context.get("protocol"),
        "is_vulnerability": bool(vulnerabilities),
    }
    return base_script, [finding], vulnerabilities


def _parse_script_children(script_node: ET.Element) -> Any:
    if not list(script_node):
        return {}

    keyed: dict[str, Any] = {}
    items: list[Any] = []
    for child in script_node:
        parsed = _parse_script_value(child)
        key = _clean_text(child.get("key"))
        if key:
            keyed[key] = _merge_duplicate_key(keyed.get(key), parsed)
        else:
            items.append(parsed)

    if keyed and items:
        keyed["_items"] = items
        return keyed
    if keyed:
        return keyed
    return items


def _parse_script_value(node: ET.Element) -> Any:
    if node.tag == "elem":
        return _clean_text(node.text)
    if node.tag != "table":
        return _clean_text(node.text)

    keyed: dict[str, Any] = {}
    items: list[Any] = []
    for child in node:
        parsed = _parse_script_value(child)
        key = _clean_text(child.get("key"))
        if key:
            keyed[key] = _merge_duplicate_key(keyed.get(key), parsed)
        else:
            items.append(parsed)

    if keyed and items:
        keyed["_items"] = items
        return keyed
    if keyed:
        return keyed
    if items:
        return items
    return _clean_text(node.text)


def _merge_duplicate_key(existing: Any, new_value: Any) -> Any:
    if existing is None:
        return new_value
    if isinstance(existing, list):
        existing.append(new_value)
        return existing
    return [existing, new_value]


def _parse_os_node(os_node: ET.Element | None) -> dict[str, Any]:
    if os_node is None:
        return {"name": None, "accuracy": None, "matches": []}

    matches = []
    for match_node in os_node.findall("osmatch"):
        matches.append({
            "name": _clean_text(match_node.get("name")),
            "accuracy": _safe_int(match_node.get("accuracy")),
            "line": _safe_int(match_node.get("line")),
            "classes": [
                {
                    "vendor": _clean_text(class_node.get("vendor")),
                    "family": _clean_text(class_node.get("osfamily")),
                    "generation": _clean_text(class_node.get("osgen")),
                    "type": _clean_text(class_node.get("type")),
                    "accuracy": _safe_int(class_node.get("accuracy")),
                }
                for class_node in match_node.findall("osclass")
            ],
        })
    matches.sort(key=lambda item: item.get("accuracy") or -1, reverse=True)
    best = matches[0] if matches else None
    return {
        "name": best.get("name") if best else None,
        "accuracy": best.get("accuracy") if best else None,
        "matches": matches,
    }


def _parse_uptime(uptime_node: ET.Element | None) -> dict[str, Any] | None:
    if uptime_node is None:
        return None
    return {
        "seconds": _safe_int(uptime_node.get("seconds")),
        "last_boot": _clean_text(uptime_node.get("lastboot")),
    }


def _extract_vulnerabilities(script: dict[str, Any]) -> list[dict[str, Any]]:
    content = "\n".join(filter(None, [
        _clean_text(script.get("id")),
        _clean_text(script.get("output")),
        "\n".join(_collect_strings(script.get("structured"))),
    ]))
    cves = _unique_preserve_case(CVE_RE.findall(content))
    severity = _extract_severity(content, script.get("structured"))
    references = _extract_references(content, cves)
    is_vulnerability = bool(cves or VULN_RE.search(content))
    if not is_vulnerability:
        return []

    description = _extract_description(script)
    base = {
        "description": description,
        "severity": severity,
        "references": references,
        "source_script_id": script.get("id"),
        "port": script.get("context", {}).get("port"),
        "protocol": script.get("context", {}).get("protocol"),
    }
    if cves:
        return [
            dict(base, id=cve.upper())
            for cve in cves
        ]
    generic_id = _clean_text(script.get("id")) or "nmap-script"
    return [dict(base, id=generic_id)]


def _extract_description(script: dict[str, Any]) -> str | None:
    structured = script.get("structured")
    for key in ("title", "description", "summary"):
        value = _find_in_structure(structured, key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    output = _clean_text(script.get("output"))
    if output:
        return output
    return _clean_text(script.get("id"))


def _extract_severity(content: str, structured: Any) -> str | None:
    value = _find_in_structure(structured, "severity")
    if isinstance(value, str) and value.strip():
        match = SEVERITY_RE.search(value)
        if match:
            return match.group(1).lower()

    for key in ("cvss", "cvss3", "cvss_base_score", "score"):
        score = _find_in_structure(structured, key)
        mapped = _severity_from_score(score)
        if mapped:
            return mapped

    match = SEVERITY_RE.search(content)
    if match:
        return match.group(1).lower()
    return None


def _severity_from_score(score: Any) -> str | None:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    if value > 0.0:
        return "low"
    return None


def _extract_references(content: str, cves: list[str]) -> list[str]:
    refs = [match for match in _unique_preserve_case(URL_RE.findall(content))]
    for cve in cves:
        upper = cve.upper()
        if upper not in refs:
            refs.append(upper)
    return refs


def _collect_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_collect_strings(item))
        return out
    if isinstance(value, dict):
        out = []
        for item in value.values():
            out.extend(_collect_strings(item))
        return out
    return [str(value)]


def _find_in_structure(value: Any, key: str) -> Any:
    if isinstance(value, dict):
        if key in value:
            return value[key]
        for child in value.values():
            found = _find_in_structure(child, key)
            if found is not None:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_in_structure(item, key)
            if found is not None:
                return found
    return None


def _dedupe_vulnerabilities(vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen = set()
    for vuln in vulnerabilities:
        marker = (
            vuln.get("id"),
            vuln.get("description"),
            vuln.get("port"),
            vuln.get("protocol"),
        )
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(vuln)
    return unique


def _summarize_vulnerabilities(vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(
        str(vuln.get("severity") or "unknown").lower()
        for vuln in vulnerabilities
    )
    highest = None
    for level in ("critical", "high", "medium", "low", "unknown"):
        if counts.get(level):
            highest = level
            break
    return {
        "highest": highest,
        "counts": {
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "unknown": counts.get("unknown", 0),
        },
    }


def _unique_preserve_case(values: list[str]) -> list[str]:
    out: list[str] = []
    seen = set()
    for value in values:
        normalized = str(value or "").upper()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(str(value))
    return out


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _safe_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _safe_float(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(str(value))
    except (TypeError, ValueError):
        return None