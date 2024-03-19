import pytest

from capa.capabilities.extract_domain_and_ip import is_ip_addr, is_valid_domain, potential_winapi_function


@pytest.mark.parametrize(
    "string",
    [
        # Valid IPv4 addresses
        ("8.8.8.8"),
        ("128.0.0.1"),
        ("123.4.56.78"),
        ("0.0.0.0"),
        ("255.255.255.255"),
        # Valid IPv6 addresses
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
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
        ("2001:db8::1234:5678:5.6.7.8"),
    ],
)
def test_is_ip_addr(string: str):
    # Valid IPv4 addresses
    assert is_ip_addr(string)


@pytest.mark.parametrize(
    "string",
    [
        # Invalid IPv4 addresses
        ("255.255.255.256"),
        ("255.255.255.-1"),
        ("2555.255.255.255"),
        # Invalid IPv6 addresses
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
def test_is_not_ip_addr(string: str):
    assert not is_ip_addr(string)


@pytest.mark.parametrize(
    "string",
    [
        (
            "google.com"
        ),  # the following talks about some domain matching considerations - (http://stackoverflow.com/a/7933253/433790)
        ("favorite.website"),
        ("dont.like.spiders"),
        ("lots.of.subnets.com.org.net"),
        ("walk-your-dog.net"),  # can have dashes in domain names
        (
            "whos--a---goood---boy.com"
        ),  # can have multiple dashes (https://stackoverflow.com/questions/16468309/can-domain-name-have-two-continuous-hyphens)
        ("fileshare.biz"),
        (
            "g00gle.c0m"
        ),  # can have numbers in top-level domain as long as the top-level domain doesn't start or end with a number
        (
            "coooooooooooool.we.b.s.t.e"
        ),  # single-character top-level-domains technically legal (https://stackoverflow.com/questions/7411255/is-it-possible-to-have-one-single-character-top-level-domain-name)
        ("really.long.jhgfjhgfjhgfkjh76547kjhgkjhgl234567gfdshgfkklkjh"),
        ("oiuyu78658765hgjj-i765jhgftuytruytr.jhgfhgfjhgf654365436576908-088098jhgjff.gdffdghdgfd"),
        ("xn--bcher-kva.tld"),
        (
            "xn--q1a.xn--b1aube0e.xn--c1acygb.xn--p1ai"
        ),  # https://superuser.com/questions/860121/what-does-it-mean-when-a-dns-name-starts-with-xn
        ("xn--diseolatinoamericano-66b.com"),  # https://stackoverflow.com/questions/9724379/xn-on-domain-what-it-means
        (
            "don't.like.sp1d3rs"
        ),  # apostropes in URLs technically legal (https://stackoverflow.com/questions/13442421/apostrophes-in-the-url-good-idea-or-bad-idea-and-why)
    ],
)
def test_valid_domain(string: str):
    assert is_valid_domain(string)


@pytest.mark.parametrize(
    "string",
    [
        ("yup"),
        ("no way this passes the test"),  # can't have spaces
        ("really.long-domainname"),  # can only have "-" in top-level domains if "xn--..."
        ("really.long-domain-name"),
        (
            "dog..cat"
        ),  # consecutive periods are invalid in a subdomain (https://stackoverflow.com/questions/41821416/are-urls-with-multiple-periods-in-the-url-path-valid)
        ("dog.34.cat"),  # subdomain has only numbers
        ("34.dog.cat"),
        (
            "dog.cat.34"
        ),  # top-level domains can not consist only of numbers (https://stackoverflow.com/questions/7411255/is-it-possible-to-have-one-single-character-top-level-domain-name)
        ("d0nt.lik3.sp1d3rs"),  # number at end of second subdomain
        ("definite.1nvalid"),  # number at start of the top-level domain
    ],
)
def test_invalid_domain(string: str):
    assert not is_valid_domain(string)


@pytest.mark.parametrize(
    "string",
    [
        ("InternetConnectA"),
        ("HttpQueryInfo"),
        ("HttpSendRequestW"),
        ("InternetCanonicalizeUrlA"),
        ("InternetCrackUrlA"),
        ("InternetCloseHandle"),
        ("InternetCombineUrlW"),
        ("InternetCheckConnectionA"),
        ("INTERNET_STATUS_CALLBACK"),
        ("INTERNET_CACHE_ENTRY_INFOA"),
        ("INTERNET_ASYNC_RESULT"),
        ("GetUrlCacheEntryInfoExA"),
        ("FindNextUrlCacheEntryW"),
        ("DeleteUrlCacheEntry"),
        ("DetectAutoProxyUrl"),
        ("FindFirstUrlCacheEntryExA"),
        ("InternetConfirmZoneCrossing"),
        ("InternetGoOnlineW"),
        ("InternetHangUp"),
        ("InternetSetOptionExW"),
        ("UnlockUrlCacheEntryFile"),
        ("URL_COMPONENTSA"),
        ("Internet"),
        ("recv"),
        ("send"),
    ],
)
def test_potential_winapi_function(string: str):
    assert potential_winapi_function(string)


@pytest.mark.parametrize(
    "string",
    [
        ("asdfadsfasdfasf"),
        ("plkj"),
        ("DSFLKJKLJKLDJFKJ"),
        ("LKJD LKJ ALKSDJFH"),
        ("dog cat mouse snake"),
        ("Dog CAT mOuse Snake"),
        (""),
        (" "),
        ("2345"),
        ("SDFGHJ_SDFGHJKLKJHG"),
        ("Sleep"),
    ],
)
def test_not_potential_winapi_function(string: str):
    assert not potential_winapi_function(string)
