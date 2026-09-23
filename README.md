# Pentest / Red-Team / Cybersecurity Datasets

Organized dataset/repository collection downloaded by Hermes.

## Folder layout

- `01_core_sft/` — datasets intended for supervised fine-tuning / instruction tuning.
- `02_eval_safety/` — red-team, jailbreak, model-safety, and benchmark/evaluation repos.
- `03_payload_wordlists_rag/` — payloads, wordlists, templates, and reference corpora; best used for RAG/evals rather than raw SFT.
- `04_network_packet_analysis/` — packet / PCAP analysis dataset tooling.
- `_hf_datasets/` — Hugging Face dataset snapshots if downloaded successfully.
- `_manifests/` — machine-readable clone/download logs.

## Safety note

Use these only for authorized security research, owned lab environments, and defensive/educational workflows. For model training, avoid raw unfiltered offensive payload SFT; pair cyber examples with authorization framing, mitigation, detection, and safe refusal behavior.
