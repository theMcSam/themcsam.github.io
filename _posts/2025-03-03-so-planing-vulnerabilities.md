---
title: Vulnerabilities I Discovered in Simple Online Planning v1.53.00
date: 2025-03-03 11:33:00 +0800
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


## Arbitrary file upload leading to RCE

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

I successfully executed code on the target by exploiting these vulnerabilities. The image below shows the execution in action.
![Executing code on the target](command_execution_from_uploaded_shell.png)
*Figure 3: Executing code on the target*

To make things even easier, I wrote a script to automate this attack. You can check it out on my GitHub: Link to script.


## Arbitrary file deletion
Ever wished you could just delete files without anyone stopping you? Well, SOPlanning v1.53.00 practically hands you the keys!  

The application doesn't properly validate user input before deleting files. This means an attacker can remove **any file** they want—whether it's critical system files, application data, or just something to break things for fun. The worst part? No authentication is required. This could lead to **service disruption, data loss, or even further exploitation**.  

#### 🔍 What's Going Wrong?  
The issue lies in how the application handles file deletion in `www/process/upload.php`.  

![Arbitrary file deletion vulnerability](file_deletion_code.png)  
*Figure 4: Unsanitized user input is concatenated with the upload directory paths*  

Specifically, user input from `$_POST['fichier_to_delete']` is **directly concatenated** with the upload directory path (`$upload_dir`). Since this value is user-controlled, attackers can **trick the application into deleting files outside the intended directory** using **directory traversal** (`../../etc/passwd`, anyone?).  

### Proof Of Concept
In the image below, you can see the directory contents listed, including a `.htaccess` file. This shows the directory state before exploiting the vulnerability.

![State of the directory before exploiting the arbitrary file deletion vuln](before_running_the_delete_request.png)
*Figure 5: State of the directory before exploiting the arbitrary file deletion vuln*

I fired up burpsuite to intercept and modify the parameter to point to the `.htaccess` file.

![Manipulating the post parameter in burpsuite](arb_file_del_request.png)
*Figure 6: Manipulating the post parameter in burpsuite*

