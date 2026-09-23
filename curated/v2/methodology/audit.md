# Methodology corpus audit

## What was built

This is an **original, synthetic authorized-lab corpus** for pentest methodology, prompted by gaps in `Infinityy7/DATASET`. It does not copy CTI answers, MCQ text, tool output, or reasoning traces. Each record has `messages=[user, assistant]` and metadata with `source_urls`, `fixture_id`, `scenario_family`, `source_record`, `review_status`, `split_group`, and `split`. The responses are concise and bound to the fictional facts stated in their prompts. Primary references are official NIST SP 800-115, OWASP WSTG v4.2, OWASP Top 10/API Top 10 2023, and MITRE CWE-89.

| Split | Families | Rows | Assets |
|---|---:|---:|---|
| train | 6 | 30 | Shop, clinic API, inventory search, admin portal, staging network, helpdesk |
| eval | 2 | 10 | Image importer, ticket export |
| total | 8 | 40 | 8 distinct lab fixtures |

Each family has five independently authored examples. Task coverage: scope 7, planning 1, test selection 7, evidence 8, reporting 8, remediation 5, and stop conditions 4. The programmatic source of truth is `build.py`; running it regenerates both JSONL files and checks counts, uniqueness, split separation, and absence of `<think>` and tool-call claims.

## Quality gates

- All 40 JSONL records parsed successfully. All have exactly one user and one assistant message, 40 unique prompts, and 40 unique answers.
- Evaluation holds out entire scenario families and fixture assets. No asset or `split_group` appears in both files.
- Observed vulnerabilities and scanner outputs are **fictional lab facts provided in the user prompt**. Answers distinguish leads from verified findings and avoid claiming effects beyond the supplied observation.
- Scope, excluded targets, rate limits, stop conditions, and evidence handling are explicit where relevant. No real credentials, personal records, commands, payloads, or invented tool outputs occur.
- Primary links were checked against the official source pages during authoring. The links support testing principles and weakness definitions; they do not imply the fictional lab events occurred in the source documents.

## Limits

This is a compact behavior seed, not enough on its own to fine-tune a 27B model. It has no multi-turn interactions, actual tool trajectories, complete reports, or real lab artifacts. The held-out examples test transfer to two scenario families but are too small for a stable accuracy estimate. Expand with de-identified, reviewer-approved engagement traces and evaluate whole workflows before using it as a production training set. Keep the eval fixtures out of future train expansions.
