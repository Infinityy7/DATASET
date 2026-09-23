# Pentest fine-tuning corpus, pilot release

This package contains four **trainable JSONL tracks** for an authorized pentest assistant. Every line is a JSON object with `messages`; tool-call rows also contain `tools`. The material is an original, synthetic lab corpus. It teaches bounded assessment decisions and how to interpret supplied observations. It is a **pilot seed**, not a sufficient or expert-approved corpus for a 27B production model.

| Track | Train | Eval | Focus |
| --- | ---: | ---: | --- |
| `methodology` | 30 | 10 | scope, test planning, evidence, reporting, remediation, stop conditions |
| `scans` | 33 | 9 | discovery types, scan selection, results, uncertainty, false positives |
| `footholds` | 34 | 10 | foothold hypotheses, preconditions, bounded validation, evidence |
| `tools` | 30 | 20 | schema-following calls, result interpretation, no-tool decisions |
| **Total** | **127** | **49** | **176** |

## Format and validation

Run `python3 validate.py` from this folder. The validator uses Python's standard library and checks counts, JSON, roles, duplicates, split-group isolation, tool schema arguments, tool responses, and the ATT&CK index. The three text tracks are ordinary conversational SFT. The tool track follows the TRL `messages` plus `tools` convention. `metadata` is provenance and curation data; do not insert it into the assistant's spoken response.

The tool track supplies the available function schemas in each row. Brand-style names based on Nmap, ffuf, Hashcat, John the Ripper, LinPEAS, WinPEAS, Evil-WinRM, and BloodHound are **examples**, alongside generic aliases. Evaluation uses unseen aliases and parameter names. Kerberos artifact inspection is represented as a capability, since Kerberos is a protocol. These schemas are *abstract wrappers*, not the command-line API of those products. Your runtime must map approved wrapper operations to installed tools and enforce asset scope independently of the model. No arbitrary shell executor is included.

## Training use

1. Select the exact abliterated Qwen checkpoint and its tokenizer. The upstream `Qwen/Qwen3.8-27B` tokenizer rendered all 176 rows in a smoke check, but a derivative may use a different chat template or tool format.
2. Load each `train.jsonl` and `eval.jsonl` as separate datasets. Keep the four evaluation sets out of training and augmentation. Apply the **selected checkpoint's** chat template to `messages` and `tools`; inspect rendered tool-call tokens and end-of-turn behavior before SFT. Check the training library's assistant-only loss support with that template.
3. Mix these examples into a larger vetted conversational corpus. Track per-track sampling so the 50 tool rows and concise two-turn examples do not dominate training. The provided splits are useful regression fixtures, not a stable estimate of real-world performance.
4. Add reviewer-approved, de-identified, replayable lab traces with genuine tool outputs, errors, misleading observations, multi-step state, and alternate tool suites. Create a separate held-out test with whole engagements, unseen labs, and unseen tools. Evaluate scope adherence, schema accuracy, result grounding, uncertainty, and tool-result error recovery before deployment.
5. Have a qualified reviewer inspect every example, including the synthetic technical claims and citation relevance. Preserve `review_status` rather than relabeling these as approved. Resolve checkpoint license, tool licenses, and any further data rights before release.

A minimal load check (with `datasets` installed):

```python
from datasets import load_dataset
train = load_dataset("json", data_files="tools/train.jsonl", split="train")
eval_set = load_dataset("json", data_files="tools/eval.jsonl", split="train")
```

The files are not pre-rendered as one model-specific prompt string because the exact derivative checkpoint is undecided.

## ATT&CK reference

`reference/attack_technique_index.jsonl` is a 697-row lookup index extracted from **Enterprise ATT&CK v19.2**. It contains IDs, names, tactics, platforms, URLs, and release labels. Use it for retrieval, controlled tagging, and post-hoc cross-checks when useful. Do not append the entire taxonomy as SFT answers or treat its labels as verified observations from a lab. The source STIX bundle is downloaded and SHA256-verified by `reference/build.py`; it is not bundled in this compact package. MITRE's required license and copyright notice are in `reference/LICENSE.txt`.

## Source decision

The [Canstralian pentesting_dataset](https://huggingface.co/datasets/Canstralian/pentesting_dataset) was reviewed at the dataset-card level only. Its files require gated access and its linked GitHub source was unavailable when checked. No records from it are included. It can be assessed later if file access, provenance, rights, and record-level quality are confirmed.

See each track's `audit.md` for the detailed coverage and limitations. The earlier 79-row derivative candidate set remains in `curated/` in the repository, separate from this synthetic pilot.
