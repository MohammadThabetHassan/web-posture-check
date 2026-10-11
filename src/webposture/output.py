"""Rendering results as text, JSON or Markdown."""

import json
from datetime import datetime, timezone

from . import __version__, markdown, score


def to_json(result):
    data = {"url": result["url"], "status": result["status"], "findings": [f.to_dict() for f in result["findings"]]}
    result_score = score.compute(result["findings"])
    if result_score:
        data["score"], data["grade"] = result_score
    if result["note"]:
        data["note"] = result["note"]
    return data


def to_text(result):
    status = result["status"]
    lines = [f"Target: {result['url']} ({f'HTTP {status}' if status is not None else 'no HTTP response'})"]
    result_score = score.compute(result["findings"])
    if result_score:
        lines.append(f"Score: {result_score[0]}/100 (grade {result_score[1]})")
    lines += [f"  [{f.status:4}] {f.check}: {f.detail}" for f in result["findings"]]
    if result["note"]:
        lines.append(f"  ({result['note']})")
    return "\n".join(lines)


def render(output_format, results, single):
    """Return every result as one string. With one target it is a single object or report."""
    if output_format == "json":
        if single:
            return json.dumps(to_json(results[0]), indent=2) + "\n" if results else ""
        return json.dumps({"results": [to_json(r) for r in results]}, indent=2) + "\n"
    if output_format == "markdown":
        now = datetime.now(timezone.utc)
        return "\n".join(markdown.render(r["url"], r["status"], r["findings"], __version__, now, note=r["note"],
                                          score=score.compute(r["findings"])) for r in results)
    return "\n\n".join(to_text(r) for r in results) + "\n" if results else ""
