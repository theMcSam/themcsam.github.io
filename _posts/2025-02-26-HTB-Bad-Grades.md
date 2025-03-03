---
title: Bad Grades @ HackTheBox Challenge
date: 2025-02-26 04:45:00 +0800
categories: [CTF, HackTheBox, Pwn]
tags: [writeups, binary_exploitation, pwn]
math: true
mermaid: true
media_subpath: 
image:
  path: preview.png
---

## Binary Exploitation - Bad Grades
Difficulty: Easy

Overview: This challenge presents a classic binary exploitation scenario centered on a buffer overflow vulnerability due to an out-of-bounds write. By leveraging this flaw, we can manipulate the program’s control flow and craft a Return-Oriented Programming (ROP) chain to bypass security mechanisms and spawn a shell on the target system. 

### Basic file checks
First all we do some basic file checks to see the security protections enabled on the binary. 
```
mcsam@0x32:~/Desktop/ctf/hackthebox/challenges/pwn/bad_grades$ checksec --file bad_grades
[*] '/home/mcsam/Desktop/ctf/hackthebox/challenges/pwn/bad_grades/bad_grades'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

From checksec we can see that only PIE is disabled.

### Decompiling and identifying vulnerabilties
