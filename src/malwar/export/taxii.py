# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""TAXII 2.1 response formatters for Malwar threat intelligence.

This module provides functions that format STIX bundles and metadata
into TAXII 2.1-compliant JSON response structures.  It is **not** a
full TAXII server implementation; it only handles response formatting
so that Malwar's API can serve data to TAXII-compatible consumers
(e.g. SIEM tools).

See: https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"

# Default collection representing all Malwar threat intelligence
_DEFAULT_COLLECTION_ID = "malwar-threat-intel-001"
_DEFAULT_COLLECTION_TITLE = "Malwar Threat Intelligence"


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def format_taxii_discovery(
    *,
    api_root_url: str = "/api/v1/export/taxii",
    title: str = "Malwar TAXII Server",
    description: str = "TAXII 2.1 interface for Malwar threat intelligence data.",
    contact: str = "security@malwar.local",
) -> dict[str, Any]:
    """Build a TAXII 2.1 discovery response.

    Returns the top-level discovery document that clients use to
    find available API roots.
    """
    return {
        "title": title,
        "description": description,
        "contact": contact,
        "default": api_root_url,
        "api_roots": [api_root_url],
    }


# ---------------------------------------------------------------------------
# API Root
# ---------------------------------------------------------------------------

def format_taxii_api_root(
    *,
    api_root_url: str = "/api/v1/export/taxii",
    title: str = "Malwar Threat Intel API",
    description: str = "API root for Malwar threat intelligence collections.",
    max_content_length: int = 10_485_760,
) -> dict[str, Any]:
    """Build a TAXII 2.1 API root information response."""
    return {
        "title": title,
        "description": description,
        "versions": ["application/taxii+json;version=2.1"],
        "max_content_length": max_content_length,
    }


# ---------------------------------------------------------------------------
# Collections
# ---------------------------------------------------------------------------

def format_taxii_collections(
    *,
    collection_id: str = _DEFAULT_COLLECTION_ID,
    title: str = _DEFAULT_COLLECTION_TITLE,
    description: str = (
        "All threat intelligence produced by the Malwar detection engine, "
        "including campaigns, indicators, and scan analyses."
    ),
) -> dict[str, Any]:
    """Build a TAXII 2.1 collections response.

    Returns a single collection representing all Malwar data.
    Additional collections can be added by extending this function.
    """
    return {
        "collections": [
            {
                "id": collection_id,
                "title": title,
                "description": description,
                "can_read": True,
                "can_write": False,
                "media_types": [TAXII_MEDIA_TYPE],
            }
        ]
    }


# ---------------------------------------------------------------------------
# Objects (envelope)
# ---------------------------------------------------------------------------

def format_taxii_objects(
    stix_bundle: dict[str, Any],
    *,
    more: bool = False,
    next_id: str | None = None,
) -> dict[str, Any]:
    """Wrap a STIX bundle's objects in a TAXII 2.1 envelope response.

    The TAXII envelope format returns the individual STIX objects
    (not the bundle wrapper) along with pagination hints.

    Parameters
    ----------
    stix_bundle:
        A STIX 2.1 bundle dict (``{"type": "bundle", "objects": [...]}``)
    more:
        Whether additional pages of results are available.
    next_id:
        Opaque token for retrieving the next page, if *more* is True.
    """
    objects = stix_bundle.get("objects", [])

    envelope: dict[str, Any] = {
        "more": more,
        "objects": objects,
    }

    if next_id is not None:
        envelope["next"] = next_id

    return envelope
