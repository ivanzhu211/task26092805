"""IP 网段：IPv4 映射地址、主机位校验、非法 IP。"""
import pytest

from policy_engine.errors import ValidationError
from policy_engine.iputil import ip_in_networks, parse_network


def test_ipv4_mapped_address_counts_as_ipv4():
    net = parse_network("10.0.0.0/8")
    assert ip_in_networks("::ffff:10.1.2.3", [net]) is True
    assert ip_in_networks("::ffff:11.0.0.1", [net]) is False


def test_ipv4_mapped_network_normalized():
    net = parse_network("::ffff:10.0.0.0/104")
    assert net.version == 4
    assert str(net) == "10.0.0.0/8"


def test_ipv6_network():
    net = parse_network("2001:db8::/32")
    assert ip_in_networks("2001:db8::1", [net]) is True
    assert ip_in_networks("2001:db9::1", [net]) is False
    assert ip_in_networks("10.0.0.1", [net]) is False


def test_host_bits_must_be_zero():
    with pytest.raises(ValidationError):
        parse_network("10.0.0.1/8")
    with pytest.raises(ValidationError):
        parse_network("2001:db8::1/32")


def test_invalid_ip_is_unknown():
    assert ip_in_networks("not-an-ip", [parse_network("10.0.0.0/8")]) is None
    assert ip_in_networks("", [parse_network("10.0.0.0/8")]) is None
