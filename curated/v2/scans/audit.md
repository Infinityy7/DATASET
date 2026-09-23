# Scan and discovery corpus: audit

## Result

- `train.jsonl`: **33** original, two-turn examples across `orion-net`, `cedar-web`, and `fir-cloud`.
- `eval.jsonl`: **9** held-out examples across `larch-net`, `willow-web`, and `ash-cloud`.
- Total: **42 distinct examples**. The train and eval scenario families, fixture IDs, and split groups are disjoint. No exact prompt duplicate or prompt/answer pair with character similarity above 0.75 was found.
- All 42 JSONL rows passed schema, nonempty source URL, answer-length, and duplicate checks in `build.py`.

Each row has `messages` with one user and one assistant turn, plus `metadata` containing `source_urls`, `fixture_id`, `scenario_family`, `review_status`, `split_group`, `topic`, `task_type`, and `synthetic`. All rows are marked `original_synthetic_doc_grounded_pending_human_review`.

## Sources and method

The underlying principles were checked against primary documentation from [Nmap host discovery](https://nmap.org/book/man-host-discovery.html), [Nmap scan techniques](https://nmap.org/book/man-port-scanning-techniques.html), [Nmap port states](https://nmap.org/book/man.html), [Nmap version detection](https://nmap.org/book/vscan-technique.html), and [Nmap's discussion of vantage-dependent results](https://nmap.org/book/determining-firewall-rules.html). Web testing examples use OWASP WSTG pages on [attack-surface identification](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Attack_Surface_Identification/), [server fingerprinting](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server/), [page content review](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage/), and [entry-point mapping](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points/). Cloud examples use [AWS EC2 DescribeInstances](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instances.html), [Azure Resource Graph permissions and coverage](https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview), and [Google Cloud Asset Inventory search](https://docs.cloud.google.com/asset-inventory/docs/search-resources).

The lab names, networks, scanner responses, and application behavior are **invented fixtures**, not real scans. The documentation supports the interpretation or limit in each answer; it does not attest that any fixture occurred. No external host was scanned. No MCQ trace, payload, wordlist, private data, or tool result from the original repository was copied. Answers are newly written and concise. Test-net addresses and `.test` hostnames are used only in synthetic prompts.

## Coverage and split

Training covers scope and scan timing; passive versus active work; host discovery; TCP SYN and connect methods; UDP states; service and version interpretation; vantage differences; web asset and entry-point inventory; path enumeration false positives and rate limits; and AWS, Azure, and Google Cloud asset discovery with pagination, permissions, filters, and scope. Evaluation asks related questions using separate asset families and observations. Whole-family isolation makes the evaluation more meaningful than randomly splitting near-identical prompts.

The corpus emphasizes **what the evidence permits an assistant to conclude**. It includes stop conditions for out-of-scope assets, fragile systems, elevated errors, and rate limiting. It does not teach a model to emit valid tool calls. A separate tool-use corpus still needs real tool schemas, calls, actual returned results, and final answers.

## Remaining review and limits

Human review should check clarity, technical correctness against the chosen scanner and cloud API versions, and consistency with the engagement's rules. This corpus does not demonstrate real-world efficacy or sufficient coverage to fine-tune a 27B model alone. It also omits specialized scan types, authenticated web scanning, and vendor-specific cloud configuration checks. Those should be added from reproducible, authorized lab traces rather than extrapolated from these synthetic examples.
