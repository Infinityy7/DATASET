# Foothold curation audit

## Output

- `footholds.jsonl`: **27** two-message records; 22 derive from `train-00000.parquet`, 5 from `train-00001.parquet`.
- 27 unique source row references, represented as `parquet_row_0based:<index>` under the exact source path. The repository snapshot is commit `74091180ba25b8f8fc465c3e9e03317831a35b1d`.
- Task types: 7 precondition, 7 root-cause, 3 classification, 3 validation, 3 variant, 2 next-step, and 2 evidence-interpretation.
- Coverage includes SQL and command injection, NFS permission exposure, memory and format-string flaws, session fixation, SSRF variants, second-order SQL injection, DOM XSS, archive traversal, unsafe deserialization, prototype pollution, remote-service exposure, software supply chain, AD CS template risk, ICS application exposure, and MFA fatigue.

## Selection and transformation

I examined the two downloaded pentesting-explanations Parquet shards and the downloaded AttackLM balanced JSONL. The latter begins with prompt-injection material and does not preserve reliable per-record source/license fields in the balanced export, so it contributed no records. I selected source questions that illuminate a foothold's prerequisite, root cause, evidence, or remediation and discarded entries centered on exploit payloads, credential theft, persistence, exfiltration, or unsupported claims.

Each selected multiple-choice item was rewritten as an open-ended authorized-lab scenario with an answer describing a bounded validation path and mitigation. I omitted choices, answer letters, the original `think` traces, and exploit strings. These are **editorially derived examples**, not verbatim source answers or independently reproduced lab runs. All are marked `needs_human_review` because neither source item correctness nor my expanded remediation text has had expert sign-off. The source row reference allows a reviewer to compare the transformation against the original.

## Exclusions and quality cautions

- Excluded `02_eval_safety`, benchmark files, raw payloads and wordlists, credential acquisition instructions, and generic autonomous attacker orchestration.
- Excluded source items with apparent technical errors or stale version-specific assertions. For example, a source item characterized Python `marshal.loads()` itself as executing arbitrary code, which is not a sound standalone mechanism.
- The original shards are multiple-choice questions, with known answer-letter bias in shard 1. The derived prompts remove those shortcuts, but the source material is still educational explanation rather than observed exploit evidence.
- No record contains a real tool call, tool response, target scan, or verified finding. This file can support method selection and evidence interpretation; **it cannot train tool calling on its own**.
- Five records touch AD CS, ICS, mobile supply chain, and MFA. Those topics have only one or two examples each. This is breadth, not enough depth for a dedicated foothold skill. Build verified lab trajectories for each priority environment before weighting this subset heavily.

## Provenance and rights

The derivative repository's README claims Apache 2.0. It says shard `train-00000` was built from `preemware/pentesting-eval` and HackTricks, and shard `train-00001` from MITRE ATT&CK STIX. The source rows do not carry upstream record IDs or licenses. Treat shard 0's commercial training rights as **unresolved** until the underlying benchmark and HackTricks terms, attribution, and any share-alike implications are reviewed. MITRE ATT&CK attribution and trademark guidance also need to be reflected in distribution. The `license` field therefore records claims and caveats, not legal clearance.

## Next data to collect

1. For every retained topic, add reproducible lab cases with explicit scope, environment/version, observation, allowed tool schema, actual tool call and output, decision after the output, and verified remediation. Include failures and ambiguous evidence.
2. Hold out entire labs, targets, and vulnerability families for evaluation. These 27 records should remain `needs_human_review` and out of a production fine-tune until a security reviewer verifies them and a rights reviewer clears the source.
3. Expand beyond vulnerability labels to safe workflow decisions: when to stop, how to distinguish exposure from exploitability, and how to write a finding with impact bounded to observed evidence.
