---
title: Quack Quack @ HackTheBox Appocalypse 2025
date: 2025-04-12 11:47:00 +0800
categories: [CTF, HackTheBox, Pwn]
tags: [writeups, binary exploitation, pwn]
math: true
mermaid: true
media_subpath: /assets/posts/2024-12-26-HTB-Quack-Quack
image:
  path: preview.png
---

## Binary Exploitation - Quack Quack
Difficulty: Very Easy

Overview: 

### Basic file checks
The challenge starts off with a zip we download from the HTB website. These are the files contained in the zip file.
```
mcsam@0x32:~/HTBAppocalypse/pwn/quack_quack$ unzip -l pwn_quack_quack.zip 
Archive:  pwn_quack_quack.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2024-05-01 23:49   challenge/
        0  2024-05-01 23:49   challenge/glibc/
  2220400  2024-05-01 23:49   challenge/glibc/libc.so.6
   240936  2024-05-01 23:49   challenge/glibc/ld-linux-x86-64.so.2
    20672  2024-05-01 23:49   challenge/quack_quack
       25  2024-05-01 23:49   challenge/flag.txt
---------                     -------
  2482033                     6 files
```

We can see that we have the quack_quack binary in the zip file. We quickly unzip and run some basic file checks on the binary.
As with any binary exploitation challenge we start off by running `checksec` on our binary to see which protections have been enabled on the binary.
```
mcsam@0x32:~/HTBAppocalypse/pwn/quack_quack/challenge$ checksec --file quack_quack
[*] '/home/mcsam/HTBAppocalypse/pwn/quack_quack/challenge/quack_quack'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'./glibc/'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

PIE is not enabled on this binary, i guess this is good news for us since we can use static memory addresses hence making the challenge easier. However, there is a stack canary which might try to stop us from shifting control :joy:. Anyways you'll see how can use knowledge of the dark arts to bypass this and shift control.

### Decompiling and identifying vulnerabilties
Now that we know the protections enabled we can go ahead to decompile it to identify possible vulnerabilties and flaws. We can spin up Ghidra and begin analysis.
![Ghidra Intial Decompilation](ghidra_decompilation_and_functions.png)

From the image we can see the decompilation of the `main` function. In the `main` function we can see that a call is made to the `duckling` function. Also in the symbol tree section we an see other functions in this binary like `duck_attack`. Let's take a quick look at the decompilation for the `duck_attack` function.

![duck_attack Function Decompilation](duck_attack_function_decompilation.png)