# Curation report

## Source selection

Three independent passes selected the 79 records in `pentest_sft_candidates.jsonl` from the pinned [`DATASET` source snapshot](https://github.com/Infinityy7/DATASET/tree/74091180ba25b8f8fc465c3e9e03317831a35b1d). The source repository is an archive of several upstream projects, not a single homogeneous training set.

| Source group | Decision | Reason |
| --- | --- | --- |
| `theelderemo/pentesting-explanations` | 64 rewritten candidates | Relevant scan and foothold concepts; original MCQ framing and `<think>` traces excluded. Upstream technical and rights review pending. |
| `reloading0101/threat-intelligence-dataset` | 15 rewritten candidates | Selected methodology topics checked against official OWASP or MITRE references. The original CTI corpus was not bulk imported. |
| `Veedubin/AttackLM` | Excluded | The balanced export mixes source types, emphasizes command/module demonstrations, and often omits per-record rights in that export. |
| `02_eval_safety` | Reserved | Contains safety and benchmark material; training on it could contaminate evaluation. |
| `03_payload_wordlists_rag` | Excluded from SFT | Payloads, templates, and wordlists are reference material, not conversational outcomes. Some files contain credential lists. |
| `04_network_packet_analysis` | Excluded | Tooling, not labeled pentest dialogues. |
| `_hf_datasets` duplicate snapshots | Deduplicated | The pentesting Parquet shards are byte-identical to copies under `01_core_sft`; they were counted once. |

## Transformations

- Converted selected MCQs into standalone open-ended user questions and concise answers. Removed choices, answer letters, and synthetic reasoning traces.
- Preserved source file and exact source row or line for each record.
- Added qualifications where a source question could otherwise imply a scan result, exploitation, or finding without evidence.
- Did not invent tool executions or claim a target was tested.

## Validation

- 79 valid JSONL records, with exactly one user and one assistant message per record.
- 15 methodology, 37 scans, and 27 footholds; no duplicate conversations or duplicate source rows across the export.
- All 79 source references point to an in-range row or line in the pinned source files.
- No `<think>` tags and no tool calls; assistant answers range from 167 to 547 characters.
- SHA-256 of `pentest_sft_candidates.jsonl`: `6f0068c79cc12c110f5393fbcf6c522bb64f2d81c4ab6bd07217bf1ecdea7c99`.

## Remaining gates before fine-tuning

1. A pentest reviewer checks the 64 scan/foothold rewrites against current tooling and realistic lab conditions. The 15 methodology records are source-checked rewrites but still need the normal dataset approval process.
2. Confirm source rights, attribution, and intended training/distribution use. In particular, the pentesting shard credits HackTricks, MITRE ATT&CK, and a public evaluation set but lacks row-level upstream rights.
3. Collect real authorized lab traces: scope, tool schema, tool call, abbreviated actual output, interpretation, finding or no-finding, and remediation. Include negative results and tool failures.
4. Create held-out evaluations by lab/target and measure technical accuracy, false positives, tool-call validity, evidence use, and report quality.

The per-track audit notes are included with the pull request under `curated/audits/`.
