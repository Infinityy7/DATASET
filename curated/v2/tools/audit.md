# Suite-agnostic tool-call corpus audit

## Inventory

`train.jsonl` has 30 fixture-backed conversations; `eval.jsonl` has 20 held-out conversations. The training set contains 27 tool-call trajectories and three no-tool decisions. The evaluation set contains 18 tool-call trajectories and two no-tool decisions. Nine capability families are represented: network scanning, web discovery, two offline password-audit implementations, Kerberos artifact inspection, Linux and Windows local configuration review, bounded WinRM session checks, and identity-graph queries.

The named tools (Nmap, ffuf, Hashcat, John the Ripper, LinPEAS, WinPEAS, Evil-WinRM, and BloodHound) are **implementation examples**. The conversation supplies the available JSON tool schemas. Training includes both brand-style names and generic names with renamed arguments; evaluation uses unseen aliases and argument names. This tests whether the model follows the offered schema rather than memorizing a fixed command name. `kerberos_inspect` is a generic inspection capability because Kerberos is a protocol, not one specific executable.

## Grounding and format

All targets, artifacts, observations, and tool results are synthetic authorized-lab fixtures authored for this corpus. They are not claimed to be outputs from an actual tool run. Each call has a matching declared function, required parameters, valid enum values, and a corresponding tool response. Every assistant conclusion is bounded by its fixture result. Recovered passwords, ticket material, raw hashes, and real credentials are absent. The WinRM wrapper permits only connectivity and identity checks; the remaining wrappers use bounded read-only or offline audit profiles.

The dataset uses TRL's `messages` plus `tools` JSON-schema format. All 50 rows load with Hugging Face Datasets. All 50 render through the upstream `Qwen/Qwen3.8-27B` tokenizer's chat template; the maximum rendered length is under 1,000 tokens. The user's eventual abliterated checkpoint must be checked separately before training and serving. The abstract tool schemas here must be implemented or mapped to the real runtime's tool interfaces.

## Sources and limits

The technical roles and result interpretations were checked against official [Nmap](https://nmap.org/book/man.html), [ffuf](https://github.com/ffuf/ffuf/blob/master/README.md), [Hashcat](https://hashcat.net/wiki/doku.php?id=hashcat), [John the Ripper](https://www.openwall.com/john/doc/), [Microsoft Kerberos](https://learn.microsoft.com/windows-server/security/kerberos/kerberos-authentication-overview), [PEASS-ng](https://github.com/peass-ng/PEASS-ng), [Evil-WinRM](https://github.com/Hackplayers/evil-winrm), and [BloodHound](https://github.com/SpecterOps/bloodHound-docs) documentation. The tool wrappers are **new interface designs**, not promised APIs of those programs.

This is a small syntax-and-decision seed, not evidence that a 27B model can operate any pentest suite. A production tool-calling corpus needs much more diversity from real, replayable lab executions, including tool failures, misleading outputs, multi-step state, and held-out tools. The executor must enforce engagement scope and protect secrets independently of the model.
