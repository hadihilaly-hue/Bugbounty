"""Networking layer: per-host pacing/backoff and authenticated sessions.

Standalone, dependency-light helpers the recon and eval-adapter code use so that
every live request is politely paced (even in DRY_RUN recon) and so post-auth
testing can hold a real authenticated session. Kept out of the validator harness
internals on purpose (those are evolved on a separate branch).
"""

from __future__ import annotations

from .pacing import PacedTransport, PacingConfig, build_client
from .session import AuthError, Credentials, MfaRequired, SessionManager

__all__ = [
    "AuthError",
    "Credentials",
    "MfaRequired",
    "PacedTransport",
    "PacingConfig",
    "SessionManager",
    "build_client",
]
