---
title: Vulnerabilities I Discovered in Simple Online Planning v1.53.00
date: 2024-03-03 11:33:00 +0800
categories: [Vulns]
tags: [writeups]
math: true
mermaid: true
media_subpath: /assets/posts/2025-03-03-so-planing-vulnerabilities
image:
  path: preview.png
---

# How I Discovered Vulnerabilities in Simple Online Planning v1.53.00  

## Introduction  

You ever come across an old vulnerability and wonder, *“What else could be lurking in there?”* That’s exactly what happened to me while looking into **Simple Online Planning (SO Planning)**. I stumbled upon a previously reported security flaw, and that got me thinking—*if one issue made it through, maybe there are more.*  

So, I grabbed the source code for **version 1.53.00**, rolled up my sleeves, and started digging. And guess what? I struck gold.  

I found **two serious vulnerabilities**:  

1. **Arbitrary File Upload** – which could allow an attacker to upload malicious files, potentially leading to remote code execution.  
2. **Arbitrary File Deletion** – which could let an attacker delete files from the server, messing things up in all sorts of ways.  

In this post, I’ll break down how I discovered these vulnerabilities, their impact, and what can be done to fix them. Let's dive in!


### Arbitrary file upload leading to RCE

So, here’s where things started getting interesting. While digging through **SO Planning v1.53.00**, I came across its **file upload functionality**. At first glance, it looked like they had some kind of security in place—certain file extensions were blocked. But, as we all know, **blacklists are like leaky buckets**—they never quite catch everything.  

Instead of taking the safer approach of using a **whitelist (allowing only known safe file types)**, the developers opted for a **blacklist**, meaning they tried to block "bad" file extensions. The problem? **Blacklists are easy to bypass** because there’s always something they miss.  

And sure enough, they missed **`.phtml` files**. For those unfamiliar, `.phtml` files are basically **PHP scripts in disguise**, meaning I could upload a simple web shell and get **Remote Code Execution (RCE)**. 😬  

Attackers can work around this restriction by uploading files with alternative extensions like `.pht`, `.phar`, or `.php3`, which can still lead to remote code execution. In my case, I tested it using a `.phtml` file.

### Where's the problem?  
The culprit? **`www/process/upload.php`**—the script handling file uploads.

![Blacklist Implementation](allowed_file_extensions_in_code.png)
*Figure 1: Implementation of blacklists*  

### Proof Of Concept
The image below shows that it's possible to upload a malicious .phtml file to the server running SOPlanning v1.53.00, bypassing the application's blacklist restrictions.

![Uploading malicious phtml file](file_upload_vuln_soplanning.png)
*Figure 2: Uploading malicious phtml file*

To make things even easier, I wrote a script to automate this attack. You can check it out on my GitHub: Link to script.
