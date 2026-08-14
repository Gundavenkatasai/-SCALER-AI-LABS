"""
Vercel serverless entry point for the PII Redaction API.

Vercel's Python runtime runs each request in a stateless serverless function,
so we can't rely on the local filesystem persisting between invocations.
The temp file for each request is created and returned within the same
function call, which works fine. History uses /tmp (available per-instance
but not shared across Vercel instances/re-deployments — accepted trade-off).
"""

import sys
import os

# Make the parent directory importable so redact_pii is accessible
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import and re-export the FastAPI app — Vercel looks for `app` in this file
from server import app  # noqa: F401 — Vercel needs the `app` symbol here
