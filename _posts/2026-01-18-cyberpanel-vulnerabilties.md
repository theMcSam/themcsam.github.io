---
title: Multiple Vulnerabilties I Discoverd In CyberPanel
date: 2026-01-18 02:45:00 +0800
categories: [Vulnerability Research, Bug Hunting]
tags: [writeups, binary exploitation, pwn]
math: true
mermaid: true
media_subpath: /assets/posts/2026-01-18-cyberpanel
image:
  path: preview.png
---

## Technical breakdown of vulnerabilties i discovered in CyberPanel


## Introduction

During the Christmas break, my friend [@whiteov3rflow](https://github.com/whiteov3rflow) and I decided to undertake a small research project exploring the security posture of cloud hosting panels. We selected **CyberPanel** as our starting point and spent the holidays examining its features, behavior, and underlying code paths.

The research turned out to be quite productive. Between the two of us, we uncovered several interesting issues. In this post, I’ll be focusing specifically on the vulnerabilities **I discovered** during that exploration — three in particular, two of which lead to authenticated Remote Code Execution and arbitrary file read:

1. **Authenticated Remote Code Execution via Remote Backup Feature** 
2. **Command Injection via Remote Backup Feature** 
3. **Arbitrary File Read via Symlink Attack**

I’ll walk through each vulnerability, how it was identified, the technical root cause, its practical impact, and thoughts on remediation. I’ll also discuss how I approached developing proof-of-concept exploits for these issues to validate exploitation.

Later in the post, I’ll highlight the work done by [@whiteov3rflow](https://github.com/whiteov3rflow) and link to his write-up once it’s published.

Let’s get started!!

---

## Authenticated Remote Code Execution via Remote Backup Feature

CyberPanel includes a **remote backup** feature that allows a user to back up files from a remote CyberPanel server into the current instance, provided they have the IP address and password of the target server. 


### How the Remote Backup Functionality Works

The logic that implements the remote backup feature is located in `cyberpanel/backup/backupManager.py`, within the `BackupManager` class under the `submitRemoteBackups` method. 

To successfully perform a remote backup, CyberPanel carries out a multi-step workflow:

1. The user provides the IP address and password of the remote CyberPanel server they want to back up from.

In the snippet below we can see that the ip address provided by the user is directly used to craft the HTTPS request.

```python
finalData = json.dumps({'username': "admin", "password": password})

url = "https://" + ipAddress + ":8090/api/cyberPanelVersion"

r = requests.post(url, data=finalData, verify=False)

data = json.loads(r.text)
```

2. If authentication succeeds, the local CyberPanel instance requests the SSH public key from the remote server and adds it to its own `authorized_keys`.

Cyberpanel then reaches out to the remote server to retrieve the public SSH key and the write it to a temporary location.
```python
finalData = json.dumps({'username': "admin", "password": password})

url = "https://" + ipAddress + ":8090/api/fetchSSHkey"
r = requests.post(url, data=finalData, verify=False)
data = json.loads(r.text)

if data['pubKeyStatus'] == 1:
    pubKey = data["pubKey"].strip("\n")
else:
    final_json = json.dumps({'status': 0,
                              'error_message': "I am sorry, I could not fetch key from remote server. Error Message: " +
                                              data['error_message']
                              })
    return HttpResponse(final_json)
```


3. After the key exchange is completed, the remote CyberPanel server uses its SSH private key to establish a connection back to the CyberPanel instance and begins transferring files.

### Why This Functionality Is Flawed

From the design of the backup workflow, we can observe that the SSH public key retrieved from the remote CyberPanel server is written directly to `/root/.ssh/authorized_keys`. This immediately grants the remote server the ability to authenticate to the local instance as the `root` user.

There are two major security implications here:

1. **Lack of Authenticity Verification** — There is no mechanism to confirm that the remote CyberPanel server being added is genuine. Any instance that can provide a password and an SSH public key is implicitly trusted.

2. **Unbounded Trust Model** — Even if authenticity checks were introduced, an attacker could still spin up a CyberPanel instance they fully control and supply it as the “remote” server. Because the trust relationship is established automatically, the attacker gains root-level access to the system via SSH.

In other words, CyberPanel’s implementation assumes that any server participating in the backup process is inherently trusted.


There are two major security implications here:

1. **Lack of Authenticity Verification** — There is no mechanism to confirm that the remote CyberPanel server being added is genuine. Any instance that can provide password verification and an SSH public key is implicitly trusted.

2. **Unbounded Trust Model** — Even if authenticity checks were introduced, an attacker could still spin up a CyberPanel instance they fully control and supply it as the “remote” server. Because the trust relationship is established automatically, the attacker gains root-level access to the system via SSH.

In other words, CyberPanel’s implementation assumes that any server participating in the backup process is inherently trusted. 

## How this can be exploited to gain RCE
An attacked can spin up a regular HTTP server (doesn't even have to be a CyberPanel ## How This Can Be Exploited to Gain RCE

To exploit this behavior, an attacker can stand up a server they control and present it as the “remote CyberPanel” during the backup process. This server does not actually need to run CyberPanel; it only needs to respond in a way that satisfies the backup feature’s expectations and provide an SSH public key.

From the local CyberPanel instance, the attacker initiates a remote backup to the rogue server. The local instance proceeds to fetch the supplied SSH public key and writes it into its `/root/.ssh/authorized_keys` file. 

Once the key exchange completes, the attacker can authenticate directly to the local machine over SSH as the `root` user. This provides full command execution and effectively gives the attacker Remote Code Execution with the highest level of privilege.


---

## Command Injection via Remote Backup Feature

Before diving into this, we tried multiple ways to get a coammand injection vulnerability. There was a security feature that was implimented that filtered user input that flowed into OS commands making it safe from command injection. This secutrity middleware [secMiddleware.py](https://github.com/usmannasir/cyberpanel/blob/stable/CyberCP/secMiddleware.py) was applied to all endpoints to ensure full coverage. 

This security feature makes it more challenging to achieve a command injection so we had to think about other ways to get that to work. 

### How the remote backup functionality of CyberPanel works
While testing the application we came across a remote backup functionality that CyberPanel provides. The idea behind this feature is to be able to make a backup of a remote CyberPanel server once we know it's password. The process for the remote backup is as follows: 



