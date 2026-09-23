# Foothold corpus v2 audit

## Inventory and split

- 44 original, synthetic authorized-lab examples: 34 `train.jsonl`, 10 `eval.jsonl`.
- 18 scenario families across web applications, Windows endpoints, identity/VPN, AWS, and Active Directory Certificate Services.
- Split key is the **fixture asset** (`split_group`), never an individual row. Train assets: `LAB-WEB-AURORA`, `LAB-WEB-BOREAL`, `LAB-ENDPOINT-CEDAR`, `LAB-IDENTITY-DELTA`, `LAB-CLOUD-EMBER`, `LAB-AD-FALCON`. Held-out eval assets: `LAB-WEB-GARNET`, `LAB-ENDPOINT-HARBOR`, `LAB-IDENTITY-IRIS`, `LAB-CLOUD-JADE`.
- Every row has two `messages` (`user`, `assistant`) and identical metadata keys: `source_urls`, `fixture_id`, `scenario_family`, `review_status`, `split_group`, `task_type`, `origin`.

## Design

Each case gives an observation or bounded task in a fictional lab, then asks for classification, prerequisite, safe validation, evidence interpretation, alternative explanation, risk, or remediation. Answers distinguish observed facts from possible impact. No output is presented as a real scan or verified exploit. Source URLs refer to official OWASP Cheat Sheet Series, MITRE CWE/ATT&CK, Microsoft Learn, or AWS documentation for the **general concept**; the named lab assets and observations are invented fixtures. All examples are original wording. No multiple-choice question, `<think>` trace, raw exploit payload, credential, wordlist, lateral movement, or exfiltration content was copied from the source repository.

## Quality and rights

- `review_status=needs_human_review` on all 44 examples. They are structurally ready for an SFT pipeline, but a pentest subject-matter reviewer should approve technical nuance and intended behavior before a production run.
- The case text is original synthetic content. Official URLs are citations, not copied training passages. Recheck source versions and product behavior for time-sensitive Microsoft/AWS cases before training.
- The eval split is held out by asset, but it has only 10 cases; it is a smoke test, not a robust benchmark. Hold out additional labs and test tools in a separate executable evaluation suite.
- No tool-call examples are in this file. To enhance tool calling, pair the same scenario families with real tool schemas, reproducible fixture outputs, assistant calls, and post-result decisions in a separate corpus. Do not fabricate tool results from these answers.

## Gap analysis

This corpus has useful foothold reasoning breadth but limited depth per class. It does not cover Linux, macOS, containers, Kubernetes, Azure/GCP, mobile, wireless, social engineering, or industrial control environments in depth. It has no end-to-end validated finding with measured impact. A specialized foothold fine-tune would need more diverse, expert-reviewed scenarios and executable lab trajectories before heavy weighting.
