"""Rendering results as text, JSON, Markdown or SARIF."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

from . import __version__, checks, markdown, sarif, score
from .findings import ScanResult
from .textsafe import printable


def _scanned(result: ScanResult) -> bool:
    """False for a target that could not be scanned at all (see runner.failed)."""
    return bool(result["findings"]) or not result.get("error")


def to_json(result: ScanResult) -> dict[str, Any]:
    data: dict[str, Any] = {"url": result["url"], "status": result["status"], "findings": [f.to_dict() for f in result["findings"]]}
    result_score = score.compute(result["findings"])
    if result_score:
        data["score"], data["grade"] = result_score
    if result["note"]:
        data["note"] = result["note"]
    if result.get("error"):
        data["error"] = result["error"]
    return data


def to_text(result: ScanResult) -> str:
    """A plain-text report. Text the site controls is escaped, so it cannot drive the terminal."""
    status = result["status"]
    lines = [f"Target: {printable(result['url'])} ({f'HTTP {status}' if status is not None else 'no HTTP response'})"]
    result_score = score.compute(result["findings"])
    if result_score:
        lines.append(f"Score: {result_score[0]}/100 (grade {result_score[1]})")
    lines += [f"  [{f.status:4}] {f.check}: {printable(f.detail)}" for f in result["findings"]]
    if result["note"]:
        lines.append(f"  ({printable(result['note'])})")
    return "\n".join(lines)


def to_sarif(results: Sequence[ScanResult], errors: Sequence[str] = (), anchor: str | None = None) -> str:
    log = sarif.render(results, checks.NAMES, checks.SUMMARIES, errors=errors, anchor=anchor)
    return json.dumps(log, indent=2) + "\n"


def render(output_format: str, results: Sequence[ScanResult], single: bool, errors: Sequence[str] = (),
           sarif_anchor: str | None = None) -> str:
    """Return every result as one string. With one target it is a single object or report.

    errors (targets that could not be scanned) and sarif_anchor are used by the SARIF format only.
    """
    if output_format == "sarif":
        return to_sarif(results, errors, sarif_anchor)
    if output_format == "json":
        # Always one valid document: a target that could not be scanned has an "error".
        if single:
            return json.dumps(to_json(results[0]), indent=2) + "\n"
        return json.dumps({"results": [to_json(r) for r in results]}, indent=2) + "\n"
    if output_format == "markdown":
        now = datetime.now(timezone.utc)
        return "\n".join(markdown.render(r["url"], r["status"], r["findings"], __version__, now, note=r["note"],
                                          score=score.compute(r["findings"]), error=r.get("error")) for r in results)
    # The text report leaves out targets that could not be scanned: their error is on stderr.
    scanned = [r for r in results if _scanned(r)]
    return "\n\n".join(to_text(r) for r in scanned) + "\n" if scanned else ""
