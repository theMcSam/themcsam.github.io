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

The old code (highlighted in red) used a regular expression to identify and strip directory traversal sequences. It was later replaced with a newer implementation (shown in green) that handles the issue more effectively.

To better understand how this regex behaves, we can use [Regexr](https://regexr.com/) to test various payloads.

For instance, when testing the classic directory traversal pattern `../`, we immediately get a match:

![Testing Raw Directory Traversal](testing_with_regexr.png)
*Figure 1: Testing the regex filter*

Upon further examination of the regex, I realized that it only matches strings that begin with the `../` pattern. This creates an opportunity for bypassing the filter by using alternative traversal strings, such as `hack/../../../`, which the regex does not catch.

This bypass technique is demonstrated in *Figure 2*.

![Bypassing Regex](bypassing_regex_on_regexr.png)
*Figure 2: Bypassing the regex filter*s

As shown, this approach successfully bypasses the regex and allows for directory traversal, exposing the limitations of the old filtering mechanism.


## Exploit Development


## Verifying/Testing The Exploit


## References