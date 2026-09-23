import json,collections
from pathlib import Path
O=Path('work/curation_v2/footholds')
U={
 'sqli':'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
 'cmd':'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
 'ssrf':'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
 'upload':'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
 'authz':'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html',
 'session':'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
 'authn':'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
 'deser':'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html',
 'cwe434':'https://cwe.mitre.org/data/definitions/434',
 'cwe269':'https://cwe.mitre.org/data/definitions/269',
 'mitre_ia':'https://attack.mitre.org/tactics/TA0001/',
 'mslog':'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details',
 'msmfa':'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match',
 'msadcs':'https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-insecure-adcs-certificate-enrollment',
 'msapp':'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol',
 'awsana':'https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html',
 'awsimds':'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html',
}
A=[]
def add(split,asset,family,task,refs,q,a):
 A.append({'messages':[{'role':'user','content':q},{'role':'assistant','content':a}],
 'metadata':{'source_urls':[U[x] for x in refs.split(',')],'fixture_id':asset,'scenario_family':family,
             'review_status':'needs_human_review','split_group':asset,'task_type':task,
             'origin':'original_synthetic_authorized_lab'}})
# Training fixtures: each asset occurs in only one split.
add('train','LAB-WEB-AURORA','web_sql_injection','classification','sqli',
 'In the authorized Aurora lab, a search endpoint concatenates the search term into a SQL query. A quote in the term produces a database syntax error. What is supported by this observation?',
 'It supports a SQL injection hypothesis, not a confirmed data-access foothold. Trace the value into query construction and compare a harmless control input with a syntax-changing test in the lab. Record query logs and the affected role; use parameterized queries and least-privilege database permissions.')
add('train','LAB-WEB-AURORA','web_sql_injection','evidence_boundary','sqli',
 'Aurora returns fewer rows for one unusual search term, but application logs show the term was parameterized. Should the finding be SQL injection?',
 'No. A changed row count can reflect ordinary search semantics. The parameterized query log is contrary evidence; inspect other query paths before closing the hypothesis. Report the observed behavior without claiming injection.')
add('train','LAB-WEB-AURORA','web_command_injection','bounded_validation','cmd',
 'Aurora’s image converter builds a shell command from an uploaded filename. What is a bounded way to assess the risk?',
 'Review the construction path and run a harmless, agreed marker test in the disposable lab. Confirm whether input changes command structure, using process logs rather than assuming execution from an error. Replace shell use with a direct library or fixed executable and structured arguments; restrict process privileges.')
add('train','LAB-WEB-AURORA','web_file_upload','precondition','upload,cwe434',
 'Aurora accepts a file with a script-like extension. Is that enough to claim server-side execution?',
 'No. Establish whether the file is stored in an executable location, served with a dangerous type, and interpreted by the server. A harmless uploaded marker can test storage and retrieval. Enforce an allowlist, inspect content, rename files, store outside the web root, and disable execution in upload storage.')
add('train','LAB-WEB-AURORA','web_file_upload','alternative','upload',
 'Aurora rejects script extensions but accepts image files. What alternative risk should a reviewer still consider?',
 'Assess image processing and downstream rendering separately. A valid image may still exercise a vulnerable parser, and an image served as active content can create a client-side issue. Validate MIME handling and processing in a test environment; use current libraries, content checks, safe response headers, and isolated processing.')
add('train','LAB-WEB-AURORA','web_ssrf','classification','ssrf',
 'Aurora fetches a user-supplied avatar URL. A controlled external server receives the request. Does that prove SSRF into internal services?',
 'It proves a server-originated fetch to the controlled host. Internal reachability remains unproven. Inspect destination validation, redirects, address resolution, and egress policy with approved test endpoints. Allow only required destinations and schemes, and block sensitive network ranges.')
add('train','LAB-WEB-AURORA','web_ssrf','variant','ssrf',
 'Aurora validates a URL before following redirects. What check is missing?',
 'Every redirect destination needs the same scheme, host, and resolved-address validation as the initial URL. Test with a controlled redirect target and record the final connected address. Limit redirects and apply egress rules so a validation mistake cannot reach internal services.')
add('train','LAB-WEB-AURORA','web_access_control','evidence_boundary','authz',
 'An Aurora user changes a document ID and receives a 200 response with a generic page. Is this an IDOR finding?',
 'Not yet. Compare the response body and server authorization logs using two lab accounts with different document ownership. A 200 status alone does not show access to another user’s record. Enforce authorization on each object request and use deny-by-default checks.')
add('train','LAB-WEB-AURORA','web_session','risk','session',
 'Aurora retains an anonymous session identifier after login. What must be checked before reporting session fixation?',
 'Check whether the identifier value remains the same and whether another party could cause the victim to use that value before login. Merely retaining the cookie name is not evidence. Regenerate the session identifier at authentication and privilege changes, and invalidate the old identifier.')
add('train','LAB-WEB-AURORA','web_deserialization','precondition','deser',
 'Aurora imports serialized job settings from users. What preconditions matter before calling this a foothold path?',
 'Confirm the format, whether untrusted objects reach a dangerous deserializer, and whether the application instantiates or invokes attacker-influenced types. Validate with a harmless marker in the lab. Prefer a data-only format, explicit schema validation, and isolated processing.')

add('train','LAB-WEB-BOREAL','web_sql_injection','variant','sqli',
 'In the Boreal lab, a profile field is stored first and interpolated into a nightly report query later. What vulnerability variant is plausible?',
 'This is a second-order SQL injection hypothesis. Map both the write and later query path; use a benign marker to correlate them in logs without extracting data. Parameterize the nightly query as well as the initial write path.')
add('train','LAB-WEB-BOREAL','web_command_injection','alternative','cmd',
 'Boreal passes a filename as a single argument to a fixed program without a shell. Is command injection impossible?',
 'Shell metacharacter injection is less likely, but argument injection or unsafe behavior inside the program may remain. Check whether the filename can be interpreted as an option and whether an end-of-options delimiter or allowlist is used. Report the specific behavior observed, not a generic command-execution claim.')
add('train','LAB-WEB-BOREAL','web_ssrf','variant','ssrf',
 'Boreal validates a hostname once, then the HTTP client resolves it again. What class of validation gap exists?',
 'The checked address may differ from the connected address, which creates a DNS rebinding risk. Test only with a domain and endpoint controlled by the lab. Pin the validated address through connection and recheck all addresses after redirects.')
add('train','LAB-WEB-BOREAL','web_file_upload','evidence_boundary','upload',
 'Boreal stores uploaded files outside the web root and serves them as downloads. A scanner flags the accepted .html extension. How should this be triaged?',
 'Inspect actual response headers and whether the content executes in an origin with application privileges. Storage outside the web root lowers server execution risk, but unsafe inline rendering can still matter. Confirm impact in a test browser, then use attachment disposition, safe content types, and a separate download origin when needed.')
add('train','LAB-WEB-BOREAL','web_access_control','bounded_validation','authz',
 'Boreal has an export endpoint reachable by a standard test user. How should authorization be checked without collecting real data?',
 'Use two synthetic accounts and records created for the lab. Compare permitted and forbidden export requests and verify the returned record IDs. The endpoint should enforce object-level and function-level authorization server side; UI visibility is not a control.')
add('train','LAB-WEB-BOREAL','web_deserialization','evidence_boundary','deser',
 'Boreal accepts JSON configuration. Is JSON acceptance itself an unsafe-deserialization finding?',
 'No. JSON is a data format, and the risk depends on how the application maps it into objects and actions. Inspect schema validation, type allowlists, and any downstream dynamic dispatch. Report a deserialization issue only when a dangerous path is evidenced.')

add('train','LAB-ENDPOINT-CEDAR','endpoint_permissions','precondition','cwe269',
 'In a Cedar Windows lab, a service executable is writable by ordinary users. What else must be established before claiming a privilege-escalation foothold?',
 'Determine which account runs the service, whether the writable file is the executable actually launched, and whether the service can be restarted under the rules of engagement. Use ACL and service configuration evidence, not a replacement binary. Correct the ACL, restrict service-control rights, and run the service with least privilege.')
add('train','LAB-ENDPOINT-CEDAR','endpoint_permissions','evidence_boundary','cwe269',
 'A Cedar user can edit a folder that contains a privileged service, but the service binary is protected. Is the service compromised?',
 'Not from that fact alone. Check whether the service loads any writable configuration, plugin, or dependent file from that folder. A writable parent directory can still matter, but the exact load path must be shown. Lock down the directory and any consumed files as appropriate.')
add('train','LAB-ENDPOINT-CEDAR','endpoint_app_control','risk','msapp',
 'Cedar blocks an untrusted test executable through App Control for Business. What should the assessor conclude?',
 'The control blocked that execution attempt under the tested policy. Do not generalize to all binaries or scripts; review policy coverage and audit events for the relevant file types. Maintain signed, approved application rules and monitor policy changes.')
add('train','LAB-ENDPOINT-CEDAR','endpoint_app_control','alternative','msapp',
 'Cedar allows a signed administrative utility to run. Does its signature alone make the workflow safe?',
 'No. Signing establishes publisher trust, not that every use of the utility is benign. Check whether its allowed functions and privilege are necessary, and review process ancestry and policy scope. Limit use to approved operators and monitor sensitive actions.')
add('train','LAB-ENDPOINT-CEDAR','endpoint_memory_safety','evidence_boundary','mitre_ia',
 'A network service in Cedar crashes on an oversized lab input. The report draft says “remote code execution confirmed.” What correction is needed?',
 'State that a crash or possible denial-of-service condition was reproduced. Code execution needs separate evidence, and the root cause may not be memory corruption. Preserve version, input size, crash trace, and logs; coordinate any further test because availability may be affected.')

add('train','LAB-IDENTITY-DELTA','identity_mfa','evidence_interpretation','mslog,msmfa',
 'Delta’s Entra sign-in logs show many denied MFA prompts for one test account. What can be concluded?',
 'The logs support repeated MFA challenge attempts, but they do not by themselves prove the account was accessed. Check authentication details, successful sign-ins, source context, and the test user’s report. Reset a compromised first factor, revoke sessions if needed, and use number matching or phishing-resistant MFA.')
add('train','LAB-IDENTITY-DELTA','identity_mfa','precondition','mslog',
 'A Delta test account receives MFA prompts after a password attempt. What prerequisite does that suggest, and what is still uncertain?',
 'The flow reached the MFA stage, which may indicate a valid first-factor attempt for that policy path. Confirm the sign-in method and result in Authentication Details; some flows can satisfy factors through existing claims. Do not infer credential theft solely from a push notification.')
add('train','LAB-IDENTITY-DELTA','identity_external_service','classification','mitre_ia,mslog',
 'Delta exposes a VPN portal. A normal account logs in from an approved external lab network. Is this a vulnerability?',
 'External access is an expected service function, not a vulnerability by itself. Assess whether the account, device, and conditional-access policy were authorized, using sign-in logs and the engagement scope. A finding requires a specific weakness such as missing MFA or unintended access.')
add('train','LAB-IDENTITY-DELTA','identity_authentication','risk','authn,mslog',
 'Delta’s test login endpoint gives different errors for unknown users and wrong passwords. What is the risk and a bounded validation?',
 'The difference may allow account enumeration. Compare a small set of synthetic accounts at a safe rate and confirm the difference is stable across responses and timing. Use uniform responses and rate limits, while preserving useful internal logging.')
add('train','LAB-IDENTITY-DELTA','identity_session','evidence_boundary','session,mslog',
 'Delta shows a successful sign-in followed by an active session token. Does that show a new foothold?',
 'It shows a successful authentication event for that account, not whether the session was unauthorized. Correlate device, location, application, and the test user’s expected activity. If unauthorized use is confirmed, revoke sessions and investigate the first-factor and MFA path.')

add('train','LAB-CLOUD-EMBER','cloud_resource_policy','evidence_boundary','awsana',
 'AWS IAM Access Analyzer flags an Ember bucket as externally accessible. Has outside data access been proven?',
 'No. The finding shows that policy permits access beyond the analyzer’s trust boundary; it does not prove anyone used it. Review the principal, actions, conditions, and resource scope, then validate with an approved test principal if allowed. Narrow the policy and monitor access logs.')
add('train','LAB-CLOUD-EMBER','cloud_resource_policy','alternative','awsana',
 'Ember’s analyzer reports no external-access finding for a role in the same AWS organization. Is its access necessarily appropriate?',
 'No. The external analyzer’s trust boundary treats in-organization principals as trusted. Review effective internal permissions and business need separately, using internal access analysis where available. Apply least privilege and separation of duties.')
add('train','LAB-CLOUD-EMBER','cloud_metadata','precondition','awsimds,ssrf',
 'Ember has an EC2-hosted URL fetcher with a suspected SSRF. What must be checked before claiming instance-metadata exposure?',
 'Confirm the fetcher can reach the metadata endpoint from its runtime, whether it can make the required IMDSv2 session request, and whether the instance permits IMDSv1. Do not request role credentials during a routine proof. Restrict SSRF destinations and require IMDSv2 as defense in depth.')
add('train','LAB-CLOUD-EMBER','cloud_metadata','evidence_boundary','awsimds',
 'An Ember instance requires IMDSv2 and rejects a simple metadata GET. Can the SSRF report be closed?',
 'The simple request failed, but that is only evidence against that path. Assess whether the fetcher supports methods and headers needed for a session token within the approved lab, and whether other internal destinations remain reachable. Keep the finding scoped to observed behavior.')

add('train','LAB-AD-FALCON','adcs_template','precondition','msadcs',
 'Falcon’s AD CS template lets a broad group enroll, includes client-authentication use, and lets the requester supply a subject. What is the risk question?',
 'Determine whether an unprivileged enrollee can obtain a certificate for another identity without approval or strong subject validation. Validate only with synthetic lab identities and inspect template and CA settings before claiming impersonation. Restrict enrollment, require issuance controls, and remove unsafe subject settings.')
add('train','LAB-AD-FALCON','adcs_template','evidence_boundary','msadcs',
 'Falcon has a published template with “supply in request” enabled, but only a dedicated admin group can enroll. Is arbitrary-user impersonation confirmed?',
 'No. Enrollment rights are a necessary part of the risk chain. Review the exact group membership, authentication EKU, approval requirements, and CA-wide settings. Report configuration exposure precisely and tighten rights if broader access is unnecessary.')
add('train','LAB-AD-FALCON','adcs_ca_setting','alternative','msadcs',
 'Falcon disables requester-supplied subjects on one template. Is the AD CS impersonation review complete?',
 'No. Review CA-wide subject-alternative-name settings, other published authentication templates, enrollment rights, and approval controls. A single hardened template does not describe the whole issuance surface. Document each risky combination rather than assigning a blanket result.')
add('train','LAB-AD-FALCON','adcs_ca_setting','remediation','msadcs',
 'Falcon needs custom subject names for a service certificate. What safer design should be reviewed?',
 'Use a dedicated template with narrowly scoped enrollment rights and an approval or authorized-signature process when identity can be supplied by the requester. Separate service-certificate use from client authentication where possible. Review issued certificates and CA settings after the change.')

# Held-out evaluation fixtures. Different assets, observations, and scenario groups.
add('eval','LAB-WEB-GARNET','web_sql_injection','evidence_boundary','sqli',
 'Garnet’s log shows a prepared statement for its login form, but the search page emits a SQL error on malformed input. How should the assessor report this?',
 'Treat the search path as a separate SQL injection hypothesis and the login path as evidence of parameterization there only. Validate with a benign search control and query logs, then report the exact affected endpoint. Parameterize all dynamic queries and minimize database rights.')
add('eval','LAB-WEB-GARNET','web_file_upload','bounded_validation','upload',
 'Garnet’s upload API renames files but serves them inline from the application origin. What limited check establishes remaining risk?',
 'Upload a harmless lab HTML document and inspect the response type, disposition, and browser origin behavior without accessing user data. Renaming reduces filename tricks but does not prevent active content from executing in the application origin. Serve as attachment or from an isolated origin with safe types.')
add('eval','LAB-WEB-GARNET','web_ssrf','evidence_boundary','ssrf',
 'Garnet’s fetcher returns an error for a private IP literal. Does that prove internal destinations are blocked?',
 'Only that the tested literal was rejected. Review hostname resolution, redirects, alternate address families, and the final connected address with controlled lab endpoints. Apply validation to every hop and enforce network egress restrictions.')
add('eval','LAB-WEB-GARNET','web_access_control','classification','authz',
 'Two synthetic Garnet users can view each other’s invoice PDFs by changing an invoice ID. What finding is supported?',
 'This supports broken object-level authorization if both accounts are ordinary users and the invoices are meant to be private. Preserve only synthetic IDs and responses as evidence. Enforce ownership checks on the server for each invoice request and regression-test cross-account access.')
add('eval','LAB-ENDPOINT-HARBOR','endpoint_permissions','evidence_boundary','cwe269',
 'Harbor’s service runs as LocalSystem, but its executable and loaded configuration are read-only to standard users. A scanner calls it “writable service.” What next?',
 'Inspect the exact path and ACL the scanner used, including parent directories and loaded dependencies. Do not confirm privilege escalation from the service account alone. Correct the scanner result if the consumed paths are protected, and retain evidence of effective permissions.')
add('eval','LAB-ENDPOINT-HARBOR','endpoint_app_control','evidence_interpretation','msapp',
 'Harbor records an App Control block event for a lab test binary, yet the process list later shows the same filename. Is the block ineffective?',
 'Not necessarily. Correlate file hash, path, policy event, process start time, and parent process. The later process may be a different file or an approved version. Report a bypass only if the same prohibited artifact actually executed under the tested policy.')
add('eval','LAB-IDENTITY-IRIS','identity_mfa','evidence_interpretation','mslog,msmfa',
 'Iris has repeated denied MFA challenges and no successful sign-in for a synthetic account. What conclusion and response fit the evidence?',
 'Report repeated challenge attempts without claiming account takeover. Review Authentication Details and source context, confirm the user did not initiate them, and secure the first factor if compromise is plausible. Number matching and rate limits reduce prompt abuse.')
add('eval','LAB-IDENTITY-IRIS','identity_external_service','risk','mitre_ia,mslog',
 'Iris’s VPN permits sign-in from any device after password and MFA. What is the assessment question?',
 'Determine whether device compliance or location restrictions are required by policy for that user group. Use a synthetic account and sign-in logs to compare actual Conditional Access decisions with the intended rule. The absence of a device restriction is a finding only if it violates the approved access design or risk requirement.')
add('eval','LAB-CLOUD-JADE','cloud_resource_policy','evidence_boundary','awsana',
 'Jade’s Access Analyzer shows a resource shared with an external AWS account, but the policy includes a narrow condition. How should impact be bounded?',
 'Read the principal, actions, resources, and condition together; the condition may substantially limit effective access. The analyzer finding is a policy exposure signal, not proof of use. Validate with an approved test principal if possible and report the exact permitted operation.')
add('eval','LAB-CLOUD-JADE','cloud_metadata','alternative','awsimds,ssrf',
 'Jade’s image fetcher cannot set custom headers, and EC2 requires IMDSv2. Is SSRF harmless?',
 'Metadata access through that fetcher is less likely, but SSRF can still reach other allowed internal or external services. Confirm method and redirect behavior in the lab and describe the observed boundary. Keep destination allowlisting and egress restrictions; IMDSv2 is defense in depth.')

train=[];eval=[]
for d in A:
 (eval if d['metadata']['split_group'] in {'LAB-WEB-GARNET','LAB-ENDPOINT-HARBOR','LAB-IDENTITY-IRIS','LAB-CLOUD-JADE'} else train).append(d)
for name,arr in [('train',train),('eval',eval)]:
 with (O/f'{name}.jsonl').open('w') as f:
  for x in arr: f.write(json.dumps(x,ensure_ascii=False)+'\n')
print('train',len(train),'eval',len(eval),'families',len(set(x['metadata']['scenario_family'] for x in A)))
