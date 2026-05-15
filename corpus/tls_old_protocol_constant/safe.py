"""Safe SSLContext variants with modern TLS settings."""

import ssl
import ssl as s
from ssl import SSLContext, PROTOCOL_TLS_CLIENT
from ssl import SSLContext as TLSContext, PROTOCOL_TLS_SERVER


def make_modern_client_context():
    # SAFE: modern client protocol with TLS 1.2 minimum.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def make_modern_server_context():
    # SAFE: modern server protocol with TLS 1.3 minimum.
    ctx = s.SSLContext(s.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = s.TLSVersion.TLSv1_3
    return ctx


def make_direct_client_context():
    # SAFE: direct imports use modern client protocol.
    ctx = SSLContext(PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def make_direct_server_context():
    # SAFE: direct aliases use modern server protocol.
    ctx = TLSContext(PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def make_default_context():
    # SAFE: stdlib helper chooses secure defaults.
    return ssl.create_default_context()
