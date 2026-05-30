import ipaddress

from app.models.target import Target
from app.schemas.nmap_import import HostScopeDecision


def _normalize_domain(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip().lower().rstrip('.')


def _hostname_matches_scope(hostname: str, target_domain: str) -> bool:
    hostname = _normalize_domain(hostname)
    target_domain = _normalize_domain(target_domain)

    if not hostname or not target_domain:
        return False

    return hostname == target_domain or hostname.endswith(f'.{target_domain}')


def _safe_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _safe_network(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def get_target_scope(target: Target) -> dict:
    metadata = target.metadata_json or {}
    scope = metadata.get('scope', {}) if isinstance(metadata, dict) else {}

    return {
        'domain': _normalize_domain(target.domain),
        'allowed_ips': scope.get('allowed_ips', []) or [],
        'allowed_cidrs': scope.get('allowed_cidrs', []) or [],
    }


def evaluate_host_scope(
    *,
    target: Target,
    addresses: list[str],
    hostnames: list[str],
) -> HostScopeDecision:
    scope = get_target_scope(target)

    matched_by: list[str] = []
    rejected_reasons: list[str] = []

    target_domain = scope['domain']

    allowed_ips = {_safe_ip(x) for x in scope['allowed_ips']}
    allowed_ips.discard(None)

    allowed_networks = [_safe_network(x) for x in scope['allowed_cidrs']]
    allowed_networks = [x for x in allowed_networks if x is not None]

    normalized_hostnames = [_normalize_domain(x) for x in hostnames if _normalize_domain(x)]
    normalized_addresses = [x.strip() for x in addresses if x and x.strip()]

    for hostname in normalized_hostnames:
        if target_domain and _hostname_matches_scope(hostname, target_domain):
            matched_by.append(f'domain:{target_domain}')

    for raw_ip in normalized_addresses:
        ip_obj = _safe_ip(raw_ip)
        if not ip_obj:
            continue

        if ip_obj in allowed_ips:
            matched_by.append(f'ip:{raw_ip}')

        for network in allowed_networks:
            if ip_obj in network:
                matched_by.append(f'cidr:{network}')

    matched_by = list(dict.fromkeys(matched_by))
    in_scope = len(matched_by) > 0

    if not in_scope:
        if normalized_hostnames:
            rejected_reasons.append('hostname_not_in_target_domain')
        if normalized_addresses:
            rejected_reasons.append('ip_not_in_allowed_scope')
        if not normalized_hostnames and not normalized_addresses:
            rejected_reasons.append('host_has_no_address_or_hostname')

    return HostScopeDecision(
        addresses=normalized_addresses,
        hostnames=normalized_hostnames,
        in_scope=in_scope,
        matched_by=matched_by,
        rejected_reasons=list(dict.fromkeys(rejected_reasons)),
    )
