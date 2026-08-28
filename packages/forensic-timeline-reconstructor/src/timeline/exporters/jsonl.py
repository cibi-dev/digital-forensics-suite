"""Streaming JSON-Lines exporter for forensic events.

Enforces bounded memory stream consumption (CWE-400).
"""

from __future__ import annotations

import io
import os
import sys
from typing import Iterable, Iterator, TextIO, Union

from timeline.normalizer import ForensicEvent


def export_jsonl_stream(events: Iterable[ForensicEvent]) -> Iterator[str]:
    """Yield JSON-Lines strings line by line from an event generator."""
    for evt in events:
        yield evt.to_jsonl() + "\n"


def export_jsonl(
    events: Iterable[ForensicEvent],
    target: Union[str, TextIO, io.TextIOBase] = sys.stdout,
) -> int:
    """Export a stream of ForensicEvents directly to a file or stream.

    Returns the number of events exported.
    """
    count = 0
    if isinstance(target, str):
        safe_path = os.path.realpath(target)
        os.makedirs(os.path.dirname(safe_path), exist_ok=True)
        with open(safe_path, "w", encoding="utf-8") as f:
            for line in export_jsonl_stream(events):
                f.write(line)
                count += 1
    else:
        for line in export_jsonl_stream(events):
            target.write(line)
            count += 1
    return count
