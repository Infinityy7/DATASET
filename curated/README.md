# Curated pentest SFT candidate set

## Purpose and status

This is a small, provenance-tracked candidate set for teaching an assistant how to discuss authorized pentest methodology, discovery/scanning, and foothold classes. It is **not yet cleared as a production training set**. Technical review is still needed for 64 examples, and upstream rights need review for the examples derived from `theelderemo/pentesting-explanations`.

The source snapshot is [`Infinityy7/DATASET` commit `7409118`](https://github.com/Infinityy7/DATASET/tree/74091180ba25b8f8fc465c3e9e03317831a35b1d).

## Contents

| Track | Records | What they cover |
| --- | ---: | --- |
| Methodology | 15 | API and web assessment planning, validation, reporting, remediation |
| Scans | 37 | Passive and active discovery, host/web/cloud scan types, interpretation and false positives |
| Footholds | 27 | Preconditions, vulnerability classes, bounded validation, evidence, and mitigation |
| **Total** | **79** | Two-message, open-ended chat examples |

Each JSONL record has `messages` (`user`, `assistant`) and `metadata` with source repository, source file, exact source row/line, license claim, topic, task type, review status, curation track, and pinned snapshot. Some records add a verified reference URL. No raw wordlists, exploit payloads, benchmark prompts, multiple-choice answer letters, `<think>` traces, invented scan outputs, or tool calls are included.

## How to use it

Review each record and its cited source before training. Resolve rights and attribution for the original sources. After approval, use this set as a **small component** of a broader conversational SFT mix, rather than the sole fine-tune corpus for a 27B model. Keep the metadata outside the assistant text; format the `messages` with the exact Qwen checkpoint's chat template.

This set does not teach tool calling. A separate tool-use dataset needs real tool schemas, assistant tool calls, tool responses, and evidence-based assistant follow-ups. Reserve entire labs, assets, and scenarios for evaluation; random row splitting of this set would overstate generalization.

## Limits

- The source material is largely educational questions and synthetic answers, not recorded pentest engagements.
- Scanning coverage is broad but shallow; it lacks real scan outputs, tool arguments, and negative controls.
- Foothold examples describe classes and validation criteria, not verified end-to-end paths.
- The underlying source files have mixed rights. The derivative dataset's Apache-2.0 claim does not establish that every upstream contribution has been cleared for this use.
- Review statuses in the JSONL are intentional. They must not be silently promoted to approved.

See [CURATION_REPORT.md](CURATION_REPORT.md) for source decisions and validation results.
