# Methodology curation audit

`methodology.jsonl` contains **15 source-checked, rewritten examples** drawn from `reloading0101/threat-intelligence-dataset` in `Infinityy7/DATASET`. Each example has a 1-based source line, upstream reference metadata, and a primary `verified_source` URL. `build.py` reproduces the export.

The original CTI questions and generated answers were used as topic leads. I rewrote them into concise, open-ended pentest planning, validation, evidence, and remediation responses. The answer text is not copied. Claims were checked against the corresponding official OWASP API Security Top 10, OWASP Top 10, or MITRE CWE page. The 15 records comprise planning (2), validation (7), reporting (2), and remediation (4). No actor-specific playbooks, tool outputs, exploit payloads, MCQ option letters, or `<think>` traces are included.

I inspected both `theelderemo/pentesting-explanations` parquet shards for scope, evidence, validation, reporting, and remediation concepts. The matching records were mostly exploit mechanics, anti-forensics, or narrow tool trivia. A few were plausible evidence-interpretation leads, but none added enough value after source review to justify inclusion here. The AttackLM balanced set was likewise excluded from this methodology slice because its dominant content is command and module demonstrations.

The final set is deliberately small. It does **not** provide full pentest workflows or real findings. Add de-identified lab evidence, reviewer-approved findings, risk decisions, and complete reports before using this as a report-writing fine-tune. The `source_record` values are line numbers in this particular train snapshot; pin that file before publishing. The CTI dataset states CC BY 4.0, while its underlying sources retain their own terms. Retain attribution and review rights before redistribution.

Validation: all 15 records parse as JSONL, have exactly one user and one assistant message, have distinct prompts and answers, and contain no tool-call claims or reasoning traces. `review_status` is `source_checked_rewrite`.
