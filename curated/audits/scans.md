# Discovery and scanning curation audit

## Output

`scans.jsonl` contains **37** two-turn, open-ended SFT examples. Twenty-seven derive from `train-00001.parquet` (MITRE ATT&CK-derived) and ten from `train-00000.parquet` (HackTricks and benchmark-derived). The 37 assistant answers contain about 1,217 words in total. Each example cites an exact zero-based Parquet row number in `metadata.source_record` and its source shard in `metadata.source_path`.

Topic mix: passive discovery 12; cloud discovery 5; DNS enumeration 2; active discovery 2; host discovery 2; vulnerability scanning 2; web content discovery 2; local service discovery 2; image scanning 2; and one each of web app validation, service enumeration, passive network observation, repository scanning, false-positive validation, and scan interpretation.

## Selection and transformations

- Selected rows that taught a reusable discovery method, a scan type, a prerequisite, or a careful interpretation of a result. Kept both passive and active methods, cloud inventories, local protocols, and example false-positive reasoning.
- Rewrote multiple-choice stems as standalone user questions and replaced answer-letter explanations with concise direct answers. Did **not** copy the `<think>` traces, original MCQ choices, raw wordlists, attack strings, or example target identities.
- Added editorial qualifications about scope, stale data, incomplete coverage, and validation. These qualifications are curation guidance, not new observations from a tool run.
- Did not convert any record into a tool-call trajectory, because the source has no actual tool responses. No assistant answer claims to have run a scan.
- Removed rows primarily about privilege escalation, evasion, credential harvesting, exploitation, or single command recall. Also rejected apparent weak claims, including a blanket recommendation for aggressive initial Nmap scanning and an inference that failed FTP bounce scanning definitively proves server protection.

## Rights and quality status

The source README claims Apache-2.0 for `theelderemo/pentesting-explanations`, but explicitly says the shards derive from HackTricks, `preemware/pentesting-eval`, and MITRE ATT&CK. The repository has no uniform rights statement covering every upstream contribution. Each record therefore carries `curated_pending_technical_and_rights_review`; **do not treat this export as cleared for training or distribution** until upstream rights and attribution are checked. The MITRE and HackTricks provenance should be preserved in a final manifest. The first shard may contain material seeded from a benchmark; evaluate train/eval overlap before adding it to a training split.

Technical review is also pending. The answers are source-grounded edits, not independently reproduced scan results. Some source questions present commands or tool features without environmental context. Review each final example against current tool documentation and a lab before release. In particular, cloud permission behavior, regional coverage, and protocol-specific inferences should be verified.

## Gaps to fill with new authorized lab traces

- A broader scan taxonomy: TCP connect versus SYN, UDP, authenticated versus unauthenticated, discovery versus vulnerability checks, web crawling, API inventory, cloud configuration assessment, and ICS-safe passive-first workflows.
- Actual scan artifacts with timestamps, scope, command or API arguments, abbreviated tool output, uncertainty, and a verified interpretation. These are required to teach tool calling and grounding.
- Realistic false positives and negative controls: wildcard DNS, HTTP catch-all pages, stale banners, rate limiting, filtering, and vulnerability checks contradicted by configuration or backported fixes.
- Multi-step methodology: scope verification, choosing a scan depth, limiting impact, interpreting contradictory evidence, deciding the next test, and writing a concise finding or no-finding report.
- Held-out labs and targets for evaluation. Do not use benchmark-derived source material in training until overlap with planned evaluations is resolved.

## Source access

Curated from the local Parquet samples and README already present under `work/samples` and `work/repo_docs`; no generated tool output or external scan data was inserted.
