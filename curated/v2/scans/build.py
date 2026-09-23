"""Build original, synthetic, scope-bound discovery SFT fixtures."""
import json
import re
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCES = {
    "host": "https://nmap.org/book/man-host-discovery.html",
    "tech": "https://nmap.org/book/man-port-scanning-techniques.html",
    "states": "https://nmap.org/book/man.html",
    "version": "https://nmap.org/book/vscan-technique.html",
    "view": "https://nmap.org/book/determining-firewall-rules.html",
    "websurface": "https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Attack_Surface_Identification/",
    "webfinger": "https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server/",
    "webcontent": "https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage/",
    "webentry": "https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points/",
    "aws": "https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instances.html",
    "azure": "https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview",
    "gcp": "https://docs.cloud.google.com/asset-inventory/docs/search-resources",
}

# family, source keys, topic, question, answer. All observations are invented lab fixtures.
TRAIN = [
    ("orion-net", "host", "scope", "Lab Orion permits read-only discovery of 192.0.2.0/28. A linked inventory mentions 198.51.100.8. Should you include it in the scan?", "No. The approved range does not include 198.51.100.8. Record it as an out-of-scope lead and request a scope update before sending traffic there."),
    ("orion-net", "host", "passive-vs-active", "Lab Orion allows passive inventory now and active probes tomorrow. Can you run host discovery today?", "Host discovery sends probes to target systems, so defer it until the active window. Today, reconcile approved asset lists and existing observations."),
    ("orion-net", "host", "host-discovery", "An authorized host discovery run gets no response from 192.0.2.4. What can you conclude?", "Only that this probe did not establish that the host was up. Filtering, probe choice, and host configuration can hide a live system. Mark status unknown and choose another approved method if needed."),
    ("orion-net", "host", "host-discovery", "The same lab host answers a TCP probe but not ICMP echo. How should its status be recorded?", "Record the host as reachable by the tested TCP path and note that ICMP did not answer. Do not label it down based on the ICMP result."),
    ("orion-net", "tech", "tcp-syn", "A lab scanner with raw-packet privileges sends a SYN and receives SYN/ACK on TCP 443. What does this show?", "For that vantage point and moment, TCP 443 appears open. It identifies a listening TCP endpoint, not the application or its security posture; confirm the service separately."),
    ("orion-net", "tech", "tcp-connect", "A lab scanner lacks raw-packet privileges. Which TCP scan class fits and what does it do?", "A TCP connect scan uses the operating system's connection call to complete a connection attempt. Keep it within approved hosts and ports and note that it may generate application or network logs."),
    ("orion-net", "tech", "tcp-state", "A SYN probe to one approved port receives a reset. How should the port be classified?", "Classify it as closed from that scan path and time: the reset indicates no listener accepted the connection. This does not describe other interfaces or later states."),
    ("orion-net", "tech,states", "tcp-state", "Several probes to an approved TCP port receive no answer. Is the service confirmed absent?", "No. A filtered state means the scanner cannot determine whether the port is open or closed because traffic may be blocked or lost. Preserve that uncertainty."),
    ("orion-net", "tech", "udp-scan", "An authorized UDP probe receives an ICMP port-unreachable reply. What is the narrow conclusion?", "The tested UDP port is closed from that path at that time. Avoid extending the conclusion to other UDP ports or protocols."),
    ("orion-net", "tech", "udp-scan", "An authorized UDP probe receives no reply after retries. What does open|filtered mean?", "It means the scanner cannot distinguish an open service that stayed silent from filtering or packet loss. Do not report the service as confirmed open."),
    ("orion-net", "tech,version", "udp-scan", "A UDP port is open|filtered and the service matters to the lab inventory. What is a measured next step?", "With scope and load limits confirmed, use a service-specific probe or version detection and look for an actual protocol response. Keep open|filtered if the follow-up remains inconclusive."),
    ("orion-net", "tech", "scan-planning", "Lab Orion has a fragile appliance and only a short maintenance window. Should you run an exhaustive scan?", "Start with the approved narrow host and port set at the agreed rate. Coordinate any expansion with the owner, and stop if latency or errors rise beyond the engagement threshold."),
    ("orion-net", "view", "vantage-point", "Two authorized scanners report different states for the same lab port. What should the report include?", "Record both results with source location, time, scan type, and route. Port states are observations from a vantage point, so filtering and path differences can explain a mismatch."),
    ("orion-net", "version", "service-version", "A service label in a port table says HTTP because the port is 80, but no version probe ran. Is HTTP verified?", "No. A port-based service label is a hint. Verify the protocol with an application response before naming the running service or version."),
    ("orion-net", "version", "service-version", "A lab service returns a recognizable protocol greeting but no precise version. How should it be recorded?", "Record the protocol as observed and the version as unknown. Do not invent a product release from the port number or a partial banner."),
    ("orion-net", "states", "interpretation", "A scanner reports an open TCP port but an application check times out. What is the next interpretation?", "The transport-level result and application-level result differ. Confirm timing and path, retry within limits, and report only the layer actually observed; a successful connection does not establish a working application."),
    ("orion-net", "states", "interpretation", "A scan output omits a port after using a display filter that shows only open ports. Can you call it closed?", "No. The display setting hides other states. Inspect the full result and scan coverage before concluding anything about that port."),
    ("cedar-web", "websurface", "web-inventory", "Lab Cedar approves https://cedar.test/app only. A certificate record lists admin.cedar.test. May it be probed?", "No. A certificate entry is an asset lead, not authorization. Document it and ask whether the additional host is in scope before any direct test."),
    ("cedar-web", "websurface", "virtual-hosts", "Two hostnames resolve to the same lab IP. Should the tester treat them as one application?", "No. Virtual hosting can serve different applications at one address. Inventory each approved hostname and path separately while respecting the defined scope."),
    ("cedar-web", "webentry", "web-entry-points", "A lab application has pages, forms, and JSON requests. What should the initial map capture?", "Capture each approved route, method, parameter, form field, and response role observed during normal navigation. This gives a bounded list of entry points for later tests."),
    ("cedar-web", "webentry", "web-entry-points", "A form submits with POST while a search page uses GET. Why record the difference?", "Method and parameter placement affect how the application processes input and how a later test should be reproduced. Record the actual request and response instead of assuming that every page behaves alike."),
    ("cedar-web", "webcontent", "client-side-review", "A public lab page references a JavaScript source map. Is that automatically a vulnerability?", "No. It is an artifact to review for exposed source, routes, or sensitive data. Report a finding only if the content creates a verified exposure in this deployment."),
    ("cedar-web", "webcontent", "client-side-review", "A JavaScript bundle contains an internal-looking API path. What can be concluded?", "It is a candidate route, not proof that the endpoint exists or is reachable. Check whether it is in scope, then validate safely and record the actual response."),
    ("cedar-web", "webfinger", "web-fingerprint", "A response header claims an old server version. Should the report assert a known vulnerability?", "No. Headers can be hidden, modified, or stale. Treat the version as a lead, verify the software and patch state through permitted evidence, and validate any claimed vulnerability."),
    ("cedar-web", "websurface", "web-enumeration", "A content discovery run returns HTTP 200 for every candidate path and for a random invalid path. What should the tester infer?", "The site likely has a catch-all response, so status 200 alone is not evidence that each path exists. Compare body, length, redirects, and known invalid controls before retaining candidates."),
    ("cedar-web", "websurface", "web-enumeration", "A web enumeration job starts returning HTTP 429. What is the appropriate action?", "Stop or reduce the authorized request rate according to the engagement rules and coordinate with the owner. Mark results during rate limiting as incomplete rather than treating missing pages as absent."),
    ("cedar-web", "websurface", "web-enumeration", "A candidate administrative route redirects to a login page. Is an unauthenticated bypass established?", "No. The redirect shows the route's behavior, not bypass or data exposure. Record the path and authentication boundary, then test further only if the engagement allows it."),
    ("fir-cloud", "aws", "cloud-inventory", "Lab Fir grants read-only access to one AWS account and region. DescribeInstances returns zero rows. Does the organization have no EC2?", "No. The result covers the queried account, region, identity, filters, and time. Check approved regions and pagination before stating the inventory boundary; other accounts remain unknown."),
    ("fir-cloud", "aws", "cloud-pagination", "A lab EC2 query returns a next token. What must happen before calling the inventory complete?", "Retrieve subsequent pages until no next token remains, while staying within the approved account and rate limits. A single page is an incomplete inventory."),
    ("fir-cloud", "aws", "cloud-filter", "An EC2 inventory call uses a tag filter and returns no instances. How should that be reported?", "State that no instances matched the filter in the queried scope. Do not generalize the filtered result to all instances in the account."),
    ("fir-cloud", "azure", "cloud-permission", "Azure Resource Graph returns only two lab resources, while the owner expects five. What is a plausible coverage limit?", "Resource Graph results depend on the caller's Azure RBAC read access. Check subscriptions and permissions before treating the two visible resources as a complete tenant inventory."),
    ("fir-cloud", "gcp", "cloud-scope", "A Google Cloud Asset Inventory search covers one project. Can its empty result clear the whole organization?", "No. The search is bounded by its project scope, permissions, supported resource types, and query. Describe those limits and request an approved wider scope if needed."),
    ("fir-cloud", "aws,azure,gcp", "cloud-interpretation", "Three provider inventories have different resource counts. Is the smallest count proof of missing assets?", "No. Providers and identities have different scopes, permissions, resource definitions, and filters. Normalize the intended asset classes and record each query boundary before comparing counts."),
]

EVAL = [
    ("larch-net", "tech", "tcp-syn", "Lab Larch permits 203.0.113.16/29. A SYN probe to 203.0.113.18:22 gets SYN/ACK. What is established, and what is not?", "TCP 22 appears open from that scanner at that time. The response does not establish that SSH is running, identify its version, or show a vulnerability."),
    ("larch-net", "tech", "udp-scan", "A permitted UDP probe to 203.0.113.19 gets no packet back. The dashboard labels it open|filtered. What should the analyst write?", "The UDP state is inconclusive: the service may be open and silent, filtered, or affected by loss. Do not claim an open service without an actual protocol response or other corroboration."),
    ("larch-net", "view", "vantage-point", "Two lab scanners disagree: one sees filtered on TCP 443, the other sees open. Which result wins?", "Neither is universally authoritative. Preserve both observations with vantage point, route, scan method, and timestamp, then investigate path-specific filtering within the approved scope."),
    ("larch-net", "host", "stop-condition", "During a narrow lab scan, the owner's appliance begins timing out. What should the assistant recommend?", "Stop the active probes, preserve the partial observations, and notify the owner under the engagement procedure. Resume only after the agreed rate or target plan is adjusted."),
    ("willow-web", "websurface", "web-enumeration", "Lab Willow's path check returns identical 200 responses for /known-missing and /candidate. Is /candidate confirmed?", "No. The identical invalid-path control suggests a catch-all page. Compare response details and verify the candidate through a distinct, permitted signal before calling it a real resource."),
    ("willow-web", "webfinger", "web-fingerprint", "A lab web banner says Server: ExampleServer/1.0, but the owner reports a patched backport. Can a CVE be reported from the banner alone?", "No. A banner does not prove the effective patch state or exploitability. Record the discrepancy and seek permitted version, package, or behavior evidence before deciding whether the CVE applies."),
    ("ash-cloud", "aws", "cloud-pagination", "Lab Ash's AWS instance listing returns three entries and a continuation token. What is the coverage status?", "Incomplete. Continue through all result pages within the approved account and region, then report the identity, filters, and time used for the inventory."),
    ("ash-cloud", "gcp", "cloud-permission", "A Google Cloud asset search fails with a permission error. May the assistant infer there are no resources?", "No. The search did not return an inventory. Record the permission failure and request an authorized identity or role with the needed asset search permission."),
    ("ash-cloud", "azure", "cloud-scope", "Azure Resource Graph shows no VMs under one subscription. What caveat belongs in the result?", "The result applies only to that subscription, query, time, and resources visible to the caller's read permissions. It does not establish that other subscriptions or hidden resources contain no VMs."),
]


def render(items, split):
    result = []
    for n, (family, keys, topic, question, answer) in enumerate(items, 1):
        fixture_id = f"{split}-{family}-{n:03d}"
        result.append({
            "messages": [
                {"role": "user", "content": question},
                {"role": "assistant", "content": answer},
            ],
            "metadata": {
                "source_urls": [SOURCES[k] for k in keys.split(",")],
                "fixture_id": fixture_id,
                "scenario_family": family,
                "review_status": "original_synthetic_doc_grounded_pending_human_review",
                "split_group": family,
                "topic": topic,
                "task_type": "open_ended_methodology_sft",
                "synthetic": True,
            },
        })
    return result


def validate(train, evaluation):
    assert len(train) + len(evaluation) >= 40
    assert {x["metadata"]["split_group"] for x in train}.isdisjoint(
        {x["metadata"]["split_group"] for x in evaluation}
    )
    seen = set()
    for row in train + evaluation:
        assert [m["role"] for m in row["messages"]] == ["user", "assistant"]
        assert row["metadata"]["source_urls"]
        assert all(url.startswith("https://") for url in row["metadata"]["source_urls"])
        assert len(row["messages"][1]["content"].split()) >= 12
        normalized = re.sub(r"\W+", " ", row["messages"][0]["content"].lower()).strip()
        assert normalized not in seen, normalized
        seen.add(normalized)
    return Counter(x["metadata"]["topic"] for x in train + evaluation)


def main():
    train, evaluation = render(TRAIN, "train"), render(EVAL, "eval")
    topics = validate(train, evaluation)
    for name, rows in (("train", train), ("eval", evaluation)):
        with (HERE / f"{name}.jsonl").open("w") as stream:
            for row in rows:
                stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"train={len(train)} eval={len(evaluation)} topics={dict(topics)}")


if __name__ == "__main__":
    main()
