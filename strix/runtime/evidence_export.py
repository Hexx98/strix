"""Pull evidence out of the sandbox before it is torn down.

A scan's proof lives in two places that vanish when the container is deleted
and the Caido project is dropped: the agent-browser screenshots under
``/workspace/.agent-browser-screenshots`` and the proxy's captured HTTP
exchanges. :func:`export_scan_evidence` copies both into the run directory
(``evidence/screenshots`` and ``evidence/http``) so a finding's
``evidence_steps`` screenshot references and ``http_exchange_ids`` still
resolve after the run ends — and so the evidence can be imported into an
external report.

Everything here is best-effort: an export failure must never stop the scan
from finishing cleanly. The caller wraps this in teardown and only the run's
own artifacts depend on it.
"""

from __future__ import annotations

import contextlib
import io
import json
import logging
import re
import tarfile
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from agents.sandbox.session.base_sandbox_session import BaseSandboxSession

    from strix.runtime.caido_handle import CaidoBootstrapHandle


logger = logging.getLogger(__name__)


# Matches ``AGENT_BROWSER_SCREENSHOT_DIR`` in ``containers/Dockerfile``.
_SCREENSHOT_DIR = "/workspace/.agent-browser-screenshots"
# Staging path inside the sandbox for the one-shot screenshot tar.
_EVIDENCE_TAR = "/workspace/.strix-evidence-screenshots.tar"
_TAR_TIMEOUT_S = 60
# Sentinel exit code: the screenshot dir is absent or empty (nothing to export).
_NOTHING_TO_EXPORT = 42

# A captured image basename is accepted only if it is a plain filename (no path
# separators, no traversal) with an image extension; the same shape the report
# tool stores for an evidence-step screenshot reference.
_IMAGE_EXT = frozenset({".png", ".jpg", ".jpeg", ".webp", ".gif"})
_SAFE_STEM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
# Defensive caps so a hostile or runaway workspace can't exhaust host disk.
_MAX_TAR_BYTES = 256 * 1024 * 1024
_MAX_SCREENSHOTS = 400
_MAX_HTTP_EXCHANGES = 1000
# Caido request ids are short numeric/opaque strings; bound the filename.
_SAFE_EXCHANGE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _safe_image_name(name: str) -> str | None:
    """Return ``name`` if it is a safe image filename, else ``None``."""
    base = PurePosixPath(name).name
    stem, _, ext = base.rpartition(".")
    if not stem or not ext:
        return None
    if f".{ext.lower()}" not in _IMAGE_EXT:
        return None
    if not _SAFE_STEM_RE.match(base):
        return None
    return base


def _safe_exchange_id(request_id: Any) -> str | None:
    text = str(request_id).strip()
    if not text or not _SAFE_EXCHANGE_ID_RE.match(text):
        return None
    return text


async def _export_screenshots(session: BaseSandboxSession, dest: Path) -> int:
    """Copy agent-browser screenshots out of the sandbox into ``dest``.

    The whole directory is exported (not just cited shots) so a screenshot the
    agent captured but forgot to reference is still preserved as proof.
    """
    result = await session.exec(
        "sh",
        "-c",
        'if [ -d "$1" ] && [ -n "$(ls -A "$1" 2>/dev/null)" ]; then '
        'tar -cf "$2" -C "$1" . ; else exit 42 ; fi',
        "sh",
        _SCREENSHOT_DIR,
        _EVIDENCE_TAR,
        timeout=_TAR_TIMEOUT_S,
    )
    if not result.ok():
        if getattr(result, "exit_code", None) == _NOTHING_TO_EXPORT:
            logger.debug("evidence export: no screenshots in the sandbox")
            return 0
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        logger.warning(
            "evidence export: packing screenshots failed (exit %s): %s",
            getattr(result, "exit_code", "?"),
            stderr,
        )
        return 0

    stream = await session.read(Path(_EVIDENCE_TAR))
    try:
        data = stream.read()
    finally:
        with contextlib.suppress(Exception):
            stream.close()
    if not data:
        return 0
    if len(data) > _MAX_TAR_BYTES:
        logger.warning(
            "evidence export: screenshot archive is %d bytes (> %d cap); skipping",
            len(data),
            _MAX_TAR_BYTES,
        )
        return 0

    return _extract_screenshots(data, dest)


def _extract_screenshots(tar_bytes: bytes, dest: Path) -> int:
    count = 0
    written = 0
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            name = _safe_image_name(member.name)
            if name is None:
                continue
            if count >= _MAX_SCREENSHOTS or written + member.size > _MAX_TAR_BYTES:
                logger.warning("evidence export: screenshot cap reached; some shots skipped")
                break
            extracted = tar.extractfile(member)
            if extracted is None:
                continue
            payload = extracted.read()
            dest.mkdir(parents=True, exist_ok=True)
            (dest / name).write_bytes(payload)
            count += 1
            written += len(payload)
    return count


async def _export_http_exchanges(
    caido_handle: CaidoBootstrapHandle | None,
    request_ids: list[str],
    dest: Path,
) -> int:
    """Dump each cited Caido request/response pair as a raw ``.http`` file."""
    if not request_ids or caido_handle is None:
        return 0

    try:
        client = await caido_handle.get()
    except Exception:  # noqa: BLE001 - a failed proxy must not break teardown.
        logger.warning(
            "evidence export: Caido client unavailable; skipping HTTP exchanges",
            exc_info=True,
        )
        return 0

    from strix.tools.proxy import caido_api

    count = 0
    seen: set[str] = set()
    for raw_id in request_ids[:_MAX_HTTP_EXCHANGES]:
        safe = _safe_exchange_id(raw_id)
        if safe is None or safe in seen:
            continue
        seen.add(safe)
        try:
            result = await caido_api.get_request_with_client(client, safe, part="request")
        except Exception:  # noqa: BLE001 - skip an exchange that won't resolve.
            logger.debug("evidence export: exchange %s did not resolve", safe, exc_info=True)
            continue
        if result is None:
            continue
        text = _render_exchange(result)
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{safe}.http").write_text(text, encoding="utf-8")
        count += 1
    return count


def _render_exchange(result: Any) -> str:
    request = getattr(result, "request", None)
    response = getattr(result, "response", None)
    req_raw = getattr(request, "raw", None) if request is not None else None
    resp_raw = getattr(response, "raw", None) if response is not None else None
    parts = ["=== HTTP REQUEST ===", _decode(req_raw) or "(no raw request captured)", ""]
    parts += ["=== HTTP RESPONSE ===", _decode(resp_raw) or "(no response captured)", ""]
    return "\n".join(parts)


def _decode(raw: Any) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, bytes | bytearray):
        return bytes(raw).decode("utf-8", errors="replace")
    return str(raw)


def _write_manifest(
    evidence_dir: Path,
    screenshots: int,
    exchanges: int,
    request_ids: list[str],
) -> None:
    manifest = {
        "screenshot_count": screenshots,
        "http_exchange_count": exchanges,
        "cited_http_exchange_ids": [
            safe for safe in (_safe_exchange_id(r) for r in request_ids) if safe is not None
        ],
        "screenshots_dir": "screenshots",
        "http_dir": "http",
    }
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


async def export_scan_evidence(
    session: BaseSandboxSession | None,
    caido_handle: CaidoBootstrapHandle | None,
    run_dir: Path,
    request_ids: list[str],
) -> dict[str, int]:
    """Export screenshots and cited HTTP exchanges into ``run_dir/evidence``.

    Returns the counts written. Best-effort: each half is isolated so one
    failing does not stop the other, and nothing here raises to the caller.
    """
    evidence_dir = Path(run_dir) / "evidence"
    screenshots = 0
    exchanges = 0

    pending = bool(getattr(session, "pending", False))
    if session is not None and not pending:
        try:
            screenshots = await _export_screenshots(session, evidence_dir / "screenshots")
        except Exception:  # noqa: BLE001 - teardown continues regardless.
            logger.warning("evidence export: screenshot export failed", exc_info=True)
    elif pending:
        logger.debug("evidence export: sandbox never came up; skipping screenshots")

    if not pending:
        try:
            exchanges = await _export_http_exchanges(
                caido_handle, request_ids, evidence_dir / "http"
            )
        except Exception:  # noqa: BLE001 - teardown continues regardless.
            logger.warning("evidence export: HTTP exchange export failed", exc_info=True)

    if screenshots or exchanges:
        with contextlib.suppress(Exception):
            _write_manifest(evidence_dir, screenshots, exchanges, request_ids)

    logger.info(
        "Evidence export: %d screenshot(s), %d HTTP exchange(s) -> %s",
        screenshots,
        exchanges,
        evidence_dir,
    )
    return {"screenshots": screenshots, "http_exchanges": exchanges}
