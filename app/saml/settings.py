# app/saml/settings.py
from __future__ import annotations

import os
from urllib.parse import urljoin

from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2 import BINDING_HTTP_POST

from ..config import settings


def sp_config() -> SPConfig:
    """
    Build a pysaml2 SPConfig that:
      - uses Entra's remote IdP metadata (fetched via TenantId + AppId),
      - sets ACS = {BASE_URL}/saml/acs,
      - expects signed **Assertions** (typical for Entra),
      - does NOT require the outer **Response** to be signed.
    """
    base_url = settings.BASE_URL.rstrip("/")
    entity_id = settings.SAML_SP_ENTITY_ID  # e.g., "urn:entra-protocol-lab:sp"

    md_url     = settings.SAML_IDP_METADATA_URL

    conf: dict = {
        "entityid": entity_id,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [
                        (urljoin(base_url + "/", "saml/acs"), BINDING_HTTP_POST),
                    ],
                },
                "allow_unsolicited": True,        # Accept IdP-initiated SSO from Entra
                "authn_requests_signed": bool(getattr(settings, "SAML_SIGN_REQUEST", False)),
                # Entra typically signs the Assertion (not always the outer Response)
                "want_response_signed": False,
                "want_assertions_signed": True,
            }
        },
        "debug": 1,
        # Tolerate small clock skew (seconds)
        "accepted_time_diff": int(os.getenv("SAML_TIME_SKEW", "120")),
        # Path to xmlsec1 CLI used by pysaml2
        "xmlsec_binary": os.getenv("XMLSEC_BINARY", "/usr/bin/xmlsec1"),
        # Fetch IdP metadata remotely (recommended)
        "metadata": {
            "remote": [
                {"url": md_url}
            ]
        },
    }

    spc = SPConfig()
    spc.load(conf)
    return spc


def saml_client() -> Saml2Client:
    """Return a ready-to-use pysaml2 client based on the SP config above."""
    return Saml2Client(config=sp_config())
