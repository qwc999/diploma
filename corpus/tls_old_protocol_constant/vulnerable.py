"""Use of deprecated TLS/SSL protocol constants."""

import ssl
import ssl as s
from ssl import SSLContext, PROTOCOL_SSLv23
from ssl import SSLContext as TLSContext, PROTOCOL_SSLv3 as SSL_V3


def make_old_tls_context_v1():
    # VULN: TLS 1.0 is deprecated by RFC 8996.
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)


def make_old_tls_context_v11():
    # VULN: TLS 1.1 is deprecated by RFC 8996.
    return s.SSLContext(s.PROTOCOL_TLSv1_1)


def make_sslv23_context():
    # VULN: PROTOCOL_SSLv23 is a legacy, confusing constant.
    return SSLContext(PROTOCOL_SSLv23)


def make_ssl_v3_context():
    # VULN: SSLv3 is insecure.
    return TLSContext(SSL_V3)
