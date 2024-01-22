from typing import List

import fixtures

from capa.capabilities.extract_domain_names import is_ip_addr


@fixtures.parameterize(
    "strings",
    [
        ("8.8.8.8"),  # Valid IPv4 addresses here on down
        ("128.0.0.1"),
        ("123.4.56.78"),
        ("0.0.0.0"),
        ("255.255.255.255"),
        ("255.255.255.256"),  # Invalid IPv4 addresses here on down
        ("255.255.255.-1"),
        ("2555.255.255.255"),
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),  # Valid IPv6 addresses here on down
        ("fe80:0000:0000:0000:0202:b3ff:fe1e:8329"),
        ("2002::1234:5678:9abc:def0"),
        ("::1"),
        ("2001:0db8:0001:0000:0000:0ab9:C0A8:0102"),
        ("2001:db8:1::ab9:C0A8:102"),
        ("::1234:5678"),
        ("::"),
        ("2001:db8::"),
        ("2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF"),
        ("2001:db8:3333:4444:5555:6666:7777:8888"),
        ("3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        ("2001:db8:3333:4444:5555:6666:1.2.3.4"),
        ("::11.22.33.44"),
        ("2001:db8::123.123.123.123"),
        ("::1234:5678:91.123.4.56"),
        ("::1234:5678:1.2.3.4"),
        ("2001:db8::1234:5678:5.6.7.8")("0:0:0:0:0:0:0:0"),  # Valid IPv4 addresses here on down
        ("2001:0db8:85a3:0000:0000:8a2e:0370:G334"),
        ("2001:db8:a0b:12f0:0000:0000:0000::0001"),
        ("2001:db8:a0b:12f0::1:2:3:4:5"),
        ("2001:db8::::1"),
        ("fe80:2030:31:24"),
        ("::1:2:3:4:5:6:7:8"),
        ("2001:db8:a0b:12f0:g:h:i:j"),
        ("1234567890:1234:5678:90ab:cdef:1234:5678:90ab"),
    ],
)
def test_is_ip_addr(strings: List[str]):
    # Valid IPv4 addresses
    assert is_ip_addr(strings) == "8.8.8.8"
    assert is_ip_addr(strings) == "128.0.0.1"
    assert is_ip_addr(strings) == "123.4.56.78"
    assert is_ip_addr(strings) == "0.0.0.0"
    assert is_ip_addr(strings) == "255.255.255.255"
    # Invalid IPv4 addresses
    assert not is_ip_addr(strings)  # '255.255.255.256'
    assert not is_ip_addr(strings)  # '255.255.255.-1'
    assert not is_ip_addr(strings)  # '2555.255.255.255'
    # Valid IPv6 addresses
    assert is_ip_addr(strings) == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    assert is_ip_addr(strings) == "fe80:0000:0000:0000:0202:b3ff:fe1e:8329"
    assert is_ip_addr(strings) == "2002::1234:5678:9abc:def0"
    assert is_ip_addr(strings) == "::1"
    assert is_ip_addr(strings) == "2001:0db8:0001:0000:0000:0ab9:C0A8:0102"
    assert is_ip_addr(strings) == "2001:db8:1::ab9:C0A8:102"
    assert is_ip_addr(strings) == "::1234:5678"
    assert is_ip_addr(strings) == "2001:db8::"
    assert is_ip_addr(strings) == "2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF"
    assert is_ip_addr(strings) == "2001:db8:3333:4444:5555:6666:7777:8888"
    assert is_ip_addr(strings) == "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
    assert is_ip_addr(strings) == "2001:db8:3333:4444:5555:6666:1.2.3.4"
    assert is_ip_addr(strings) == "::11.22.33.44"
    assert is_ip_addr(strings) == "2001:db8::123.123.123.123"
    assert is_ip_addr(strings) == "::1234:5678:91.123.4.56"
    assert is_ip_addr(strings) == "::1234:5678:1.2.3.4"
    assert is_ip_addr(strings) == "2001:db8::1234:5678:5.6.7.8"
    # Invalid IPv6 addresses
    assert not is_ip_addr(strings)  # "0:0:0:0:0:0:0:0"
    assert not is_ip_addr(strings)  # "2001:0db8:85a3:0000:0000:8a2e:0370:G334"
    assert not is_ip_addr(strings)  # "2001:db8:a0b:12f0:0000:0000:0000::0001"
    assert not is_ip_addr(strings)  # "2001:db8:a0b:12f0::1:2:3:4:5"
    assert not is_ip_addr(strings)  # "2001:db8::::1"
    assert not is_ip_addr(strings)  # "fe80:2030:31:24"
    assert not is_ip_addr(strings)  # "::1:2:3:4:5:6:7:8"
    assert not is_ip_addr(strings)  # "2001:db8:a0b:12f0:g:h:i:j"
    assert not is_ip_addr(strings)  # "1234567890:1234:5678:90ab:cdef:1234:5678:90ab"
