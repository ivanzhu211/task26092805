"""IP / 网段工具。"""
from __future__ import annotations

import ipaddress

from .errors import ValidationError

_V4_MAPPED_PREFIX = int(ipaddress.IPv6Address("::ffff:0:0")) & ~0xFFFFFFFF


def _normalize_address(addr):
    """IPv4 映射的 IPv6 地址（::ffff:a.b.c.d）按 IPv4 算。"""
    if isinstance(addr, ipaddress.IPv6Address):
        mapped = addr.ipv4_mapped
        if mapped is not None:
            return mapped
    return addr


def parse_network(text: str):
    """解析网段；主机位非 0 时抛 ValidationError。IPv4 映射的 IPv6 网段按 IPv4 处理。"""
    try:
        net = ipaddress.ip_network(text.strip(), strict=True)
    except ValueError:
        try:
            ipaddress.ip_network(text.strip(), strict=False)
        except ValueError as exc:
            raise ValidationError(f"非法网段: {text!r}") from exc
        raise ValidationError(f"网段主机位必须为 0: {text!r}")
    if isinstance(net, ipaddress.IPv6Network):
        mapped = net.network_address.ipv4_mapped
        if mapped is not None and net.prefixlen >= 96:
            net = ipaddress.ip_network(f"{mapped}/{net.prefixlen - 96}", strict=False)
    return net


def ip_in_networks(ip_text: str, networks) -> bool | None:
    """判断 IP 是否属于任一网段；IP 不合法返回 None（无法判定）。"""
    try:
        addr = ipaddress.ip_address(ip_text.strip())
    except (ValueError, AttributeError):
        return None
    addr = _normalize_address(addr)
    for net in networks:
        if addr.version == net.version and addr in net:
            return True
    return False
