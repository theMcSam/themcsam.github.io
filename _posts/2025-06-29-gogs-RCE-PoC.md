---
title: CVE-2024-39930 - gogs ssh in-built server RCE
date: 2025-06-29 08:05:00 +0800
categories: [Vulnerability Research, Exploit Development]
tags: [remote code execution]
math: true
mermaid: true
media_subpath: /assets/posts/2025-06-29-gogs-RCE-PoC
image:
  path: preview.jpeg
---

# Vulnerability anaylsis and PoC Development for CVE-2024-39930
**Gogs** is a lightweight and self-hosted Git service that's simple to set up and ideal for organizations that prefer to keep their source code off third-party platforms like GitHub. While Gogs offers many of the same features as GitHub, its self-hosted nature makes it particularly attractive for internal development environments and private code repositories.

Recently, a **vulnerability was discovered in Gogs versions <= 0.13.0**, specifically in its **built-in SSH server**. This flaw allows **argument injection** via specially crafted SSH connections. An authenticated attacker can exploit this by initiating an SSH session and sending a malicious `--split-string` environment request, leading to potential command injection on the server side.

The vulnerability, tracked as [CVE-2024-39930](https://github.com/advisories/GHSA-p69r-v3h4-rj4f), is particularly dangerous when the SSH server is enabled and exposed, as it can allow attackers to execute unintended commands by manipulating environment variables passed during SSH authentication.

While the [SonarSource blog post](https://www.sonarsource.com/blog/securing-developer-tools-unpatched-code-vulnerabilities-in-gogs-1) and the [Vicarius write-up](https://www.vicarius.io/vsociety/posts/argument-injection-in-gogs-ssh-server-cve-2024-39930) provide excellent analysis and explanation of the root cause of this vulnerability, **no public proof-of-concept (PoC) exploit code had been released** at the time of this writing.

As a security researcher and exploit developer, I decided to dive deeper into this vulnerability and **craft an exploit** to make testing and validation easier for both **penetration testers and defenders**. My goal was to help teams reproduce this issue in lab environments, better understand the risks, and verify their mitigation strategies.

The exploit has been tested against vulnerable instances of Gogs (<= 0.13.0) with the SSH server enabled.