"""Rendering results as text, JSON, Markdown or SARIF."""

import json
from datetime import datetime, timezone

from . import __version__, markdown, runner, sarif, score
from .textsafe import printable


def to_json(result):
    data = {"url": result["url"], "status": result["status"], "findings": [f.to_dict() for f in result["findings"]]}
    result_score = score.compute(result["findings"])
    if result_score:
        data["score"], data["grade"] = result_score
    if result["note"]:
        data["note"] = result["note"]
    return data


def to_text(result):
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


def to_sarif(results, errors=(), anchor=None):
    log = sarif.render(results, runner.ALL_CHECKS, runner.CHECK_SUMMARIES, errors=errors, anchor=anchor)
    return json.dumps(log, indent=2) + "\n"


def render(output_format, results, single, errors=(), sarif_anchor=None):
    """Return every result as one string. With one target it is a single object or report.

    errors (targets that could not be scanned) and sarif_anchor are used by the SARIF format only.
    """
    if output_format == "sarif":
        return to_sarif(results, errors, sarif_anchor)
    if output_format == "json":
        if single:
            return json.dumps(to_json(results[0]), indent=2) + "\n" if results else ""
        return json.dumps({"results": [to_json(r) for r in results]}, indent=2) + "\n"
    if output_format == "markdown":
        now = datetime.now(timezone.utc)
        return "\n".join(markdown.render(r["url"], r["status"], r["findings"], __version__, now, note=r["note"],
                                          score=score.compute(r["findings"])) for r in results)
    return "\n\n".join(to_text(r) for r in results) + "\n" if results else ""
