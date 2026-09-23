"""Check the curated candidate JSONL without external dependencies."""

import hashlib
import json
import re
from pathlib import Path


DATA = Path(__file__).with_name("pentest_sft_candidates.jsonl")
REQUIRED = {
    "source_repo", "source_path", "source_record", "license",
    "topic", "task_type", "review_status", "curation_track", "source_snapshot",
    "upstream_dataset",
}


def main() -> None:
    seen_conversations = set()
    seen_sources = set()
    count = 0
    for line_no, line in enumerate(DATA.read_text().splitlines(), 1):
        row = json.loads(line)
        messages = row["messages"]
        assert [message["role"] for message in messages] == ["user", "assistant"], line_no
        assert all(isinstance(message["content"], str) and message["content"].strip() for message in messages), line_no
        assert not any(re.search(r"<\s*/?\s*think\s*>", message["content"], re.I) for message in messages), line_no
        assert all("tool_calls" not in message for message in messages), line_no
        metadata = row["metadata"]
        assert REQUIRED <= metadata.keys(), line_no
        assert all(str(metadata[key]).strip() for key in REQUIRED), line_no
        conversation = tuple(re.sub(r"\s+", " ", message["content"].casefold()).strip() for message in messages)
        source = (metadata["source_path"], str(metadata["source_record"]).split(":")[-1])
        assert conversation not in seen_conversations, (line_no, "duplicate conversation")
        assert source not in seen_sources, (line_no, "duplicate source row")
        seen_conversations.add(conversation)
        seen_sources.add(source)
        count += 1
    print(f"{count} records valid; sha256 {hashlib.sha256(DATA.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
