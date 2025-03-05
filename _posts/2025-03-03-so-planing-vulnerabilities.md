---
title: Vulnerabilities I Discovered in Simple Online Planning v1.53.00
date: 2025-03-03 11:33:00 +0800
categories: [Vulnerability Research, Bug Hunting]
tags: [file upload bypass, arbitrary file deletion]
math: true
mermaid: true
media_subpath: /assets/posts/2025-03-03-so-planing-vulnerabilities
image:
  path: preview.png
---

# How I Discovered Vulnerabilities in Simple Online Planning v1.53.00  

## Introduction  

Ever come across an old vulnerability and wonder, *“What else could be lurking in there?”* That’s exactly what happened to me while digging into **Simple Online Planning (SO Planning)**. I stumbled upon a previously reported security flaw, which got me thinking—*if one issue made it through, maybe there are more.*  

So, I grabbed the source code for **version 1.53.00**, rolled up my sleeves, and started digging. And guess what? I struck gold.  

I found **two serious vulnerabilities**:  

1. **Arbitrary File Upload** – Allows an attacker to upload malicious files, potentially leading to remote code execution.  
2. **Arbitrary File Deletion** – Lets an attacker delete files from the server, which could lead to data loss, service disruption, or further exploitation.  

In this post, I’ll break down how I discovered these vulnerabilities, their impact, and what can be done to fix them. Let's dive in!  

---

## Arbitrary File Upload Leading to RCE  

Here’s where things started getting interesting. While examining **SO Planning v1.53.00**, I came across its **file upload functionality**. At first glance, it looked like some security measures were in place—certain file extensions were blocked. But, as we all know, **blacklists are like leaky buckets**—they never quite catch everything.  

Instead of taking the safer approach of using a **whitelist (allowing only specific safe file types)**, the developers opted for a **blacklist**, meaning they tried to block "bad" file extensions. The problem? **Blacklists are easy to bypass** because there’s always something they miss.  

Sure enough, they missed **`.phtml` files**. For those unfamiliar, `.phtml` files are **PHP scripts in disguise**, meaning I could upload a simple web shell and get **Remote Code Execution (RCE)**. 😬  

Attackers can also bypass this restriction by using alternative file extensions like `.pht`, `.phar`, or `.php3`, which can still lead to RCE. In my case, I successfully uploaded a `.phtml` file.  

### Where's the Problem?  
The issue originates in **`www/process/upload.php`**, the script responsible for handling file uploads.  

![Blacklist Implementation](allowed_file_extensions_in_code.png)  
*Figure 1: Implementation of blacklists*  

### Proof of Concept  

The image below shows that it's possible to upload a malicious `.phtml` file to the server running SOPlanning v1.53.00, bypassing the application's blacklist restrictions.  

![Uploading malicious phtml file](file_upload_vuln_soplanning.png)  
*Figure 2: Uploading malicious `.phtml` file*  

I was then able to execute code on the target system, demonstrating the impact of this vulnerability.  

![Executing code on the target](command_execution_from_uploaded_shell.png)  
*Figure 3: Executing code on the target*  

To make things even easier, I wrote a script to automate this attack. You can check it out on my GitHub: [https://github.com/theMcSam/SO-Planning-RCE-Authenticated](https://github.com/theMcSam/SO-Planning-RCE-Authenticated).  
This is a script I wrote to exploit an older file upload vulnerability in SOPlanning. The same script can still be used to exploit the vulnerability by modifying the file extension to `.phtml` in the script.

---

## Arbitrary File Deletion  

Imagine being able to delete files from a web server without any restrictions—well, **SOPlanning v1.53.00** makes that possible!  

The application **fails to properly validate user input** before deleting files. This means an attacker can remove **any file** they want—critical system files, application data, or anything else that could break the system. The worst part? No authentication is required. This could lead to **service disruption, data loss, or even further exploitation**.  

### 🔍 What's Going Wrong?  
The issue lies in how the application handles file deletion in `www/process/upload.php`.  

![Arbitrary file deletion vulnerability](file_deletion_code.png)  
*Figure 4: Unsanitized user input is concatenated with the upload directory path*  

Specifically, user input from `$_POST['fichier_to_delete']` is **directly concatenated** with the upload directory path (`$upload_dir`). Since this value is user-controlled, an attacker can **trick the application into deleting files outside the intended directory** using **directory traversal** (`../../etc/passwd`, anyone?).  

### Proof of Concept  

The image below shows the contents of the directory before exploiting the vulnerability, including the presence of a `.htaccess` file.  

![State of the directory before exploiting the arbitrary file deletion vuln](before_running_the_delete_request.png)  
*Figure 5: Directory contents before exploitation*  

#### Exploiting the Vulnerability  

In the request shown in *Figure 6*, the `linkid` parameter is intentionally left blank because the application uses it to define the directory name. Looking at the code snippet below, some sanitization is applied to `$linkid`, preventing directory traversal attacks using this parameter.  

However, the `fichier_to_delete` parameter is a different story—it **lacks proper sanitization**, allowing us to inject directory traversal payloads and delete files outside the intended directory.  

```php
$linkid = preg_replace('/[^a-z0-9]+/', '0', strtolower($_POST['linkid']));
$upload_dir = UPLOAD_DIR . "$linkid/"; // Upload directory  
if (strlen(trim($linkid)) == 0) {  
    echo 'Error, please contact support';  
    die;  
}
```

An attacker can then target the `.htaccess` file for deletion, which is crucial for web server configuration. But it doesn't stop there—by using directory traversal tricks like `../../../../../` in the `fichier_to_delete` parameter, they can delete **any file** on the system.  

![Manipulating the POST parameter in BurpSuite](arb_file_del_request.png)  
*Figure 6: Manipulating the `fichier_to_delete` parameter in BurpSuite*  

After sending the request, `.htaccess` was successfully deleted from the server.  

---

## Reporting the Vulnerabilities  

After discovering and testing these vulnerabilities, I responsibly disclosed my findings to the **SOPlanning** team. They responded promptly and assured me that the issues would be fixed.  

![SO Planning](so_planning_reply_to_email.png)  
*Figure 7: Reply from SOPlanning support team*  

True to their word, they released newer versions of the application that **patched the vulnerabilities** discussed here.  

Big shoutout to the **SOPlanning team** for their quick response and for taking security seriously!

---

## Conclusion  

Security flaws like these highlight why **proper input validation and secure coding practices** are crucial. In this case, switching from a **blacklist approach** to a **whitelist approach** for file uploads and properly sanitizing user input for file deletion would have prevented these vulnerabilities.  

If you're a developer, always assume attackers will **find a way in**—so make sure to lock things down properly!  
---