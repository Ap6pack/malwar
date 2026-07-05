"""Publish short threat digests to X (Twitter) via the v2 API.

Used by ``malwar crawl monitor --publish`` to post the daily sweep summary to a
public threat feed. Authentication is OAuth 1.0a user context, signed with the
standard library (no extra dependencies).

Credentials come from settings / environment variables and must never be
committed or pasted into logs:

    MALWAR_X_API_KEY             (consumer key)
    MALWAR_X_API_SECRET          (consumer secret)
    MALWAR_X_ACCESS_TOKEN        (user access token)
    MALWAR_X_ACCESS_TOKEN_SECRET (user access token secret)

Note: findings are heuristic and can be false positives. Posting is opt-in
(``--publish``), fires only when a skill *newly* turns malicious, and uses
non-accusatory, detection-framed language. A human-reviewed draft (``--digest``)
is the recommended default over fully automated publishing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import time
from urllib.parse import quote

import httpx

logger = logging.getLogger("malwar.notifications.x")

_POST_TWEET_URL = "https://api.twitter.com/2/tweets"
_TIMEOUT_SECONDS = 15.0


def _pct(value: object) -> str:
    """Percent-encode a value per RFC 3986 / OAuth 1.0a."""
    return quote(str(value), safe="")


class XPublisher:
    """Posts short text updates to X using OAuth 1.0a user-context auth."""

    def __init__(
        self,
        api_key: str,
        api_secret: str,
        access_token: str,
        access_token_secret: str,
    ) -> None:
        self._api_key = api_key
        self._api_secret = api_secret
        self._access_token = access_token
        self._access_token_secret = access_token_secret

    @classmethod
    def from_settings(cls, settings=None) -> XPublisher:
        """Build a publisher from application settings / environment."""
        if settings is None:
            from malwar.core.config import get_settings

            settings = get_settings()
        return cls(
            api_key=settings.x_api_key,
            api_secret=settings.x_api_secret,
            access_token=settings.x_access_token,
            access_token_secret=settings.x_access_token_secret,
        )

    def is_configured(self) -> bool:
        """True only when all four OAuth credentials are present."""
        return all(
            (self._api_key, self._api_secret, self._access_token, self._access_token_secret)
        )

    def _auth_header(
        self,
        method: str,
        url: str,
        *,
        timestamp: int | None = None,
        nonce: str | None = None,
    ) -> str:
        """Build the OAuth 1.0a ``Authorization`` header for a request.

        The JSON body of a v2 tweet is not part of the signature base string
        (only ``application/x-www-form-urlencoded`` bodies are), so signing the
        oauth_* parameters alone is correct here.
        """
        oauth: dict[str, str] = {
            "oauth_consumer_key": self._api_key,
            "oauth_nonce": nonce or secrets.token_hex(16),
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(timestamp if timestamp is not None else int(time.time())),
            "oauth_token": self._access_token,
            "oauth_version": "1.0",
        }

        param_str = "&".join(f"{_pct(k)}={_pct(v)}" for k, v in sorted(oauth.items()))
        base_string = "&".join([method.upper(), _pct(url), _pct(param_str)])
        signing_key = f"{_pct(self._api_secret)}&{_pct(self._access_token_secret)}"
        signature = base64.b64encode(
            hmac.new(signing_key.encode(), base_string.encode(), hashlib.sha1).digest()
        ).decode()
        oauth["oauth_signature"] = signature

        return "OAuth " + ", ".join(
            f'{_pct(k)}="{_pct(v)}"' for k, v in sorted(oauth.items())
        )

    async def post(self, text: str) -> bool:
        """Post ``text`` as a tweet. Returns True on success."""
        if not self.is_configured():
            logger.warning("X credentials not configured; skipping post")
            return False

        header = self._auth_header("POST", _POST_TWEET_URL)
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
                resp = await client.post(
                    _POST_TWEET_URL,
                    json={"text": text},
                    headers={
                        "Authorization": header,
                        "Content-Type": "application/json",
                    },
                )
                resp.raise_for_status()
            logger.info("Posted threat digest to X")
            return True
        except Exception:
            logger.exception("Failed to post to X")
            return False
