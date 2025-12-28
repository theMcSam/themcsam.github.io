---
title: Interpreter @ SNHT CTF '25
date: 2025-10-31 04:45:00 +0800
categories: [CTF, SNHT CTF '25]
tags: [writeups, binary exploitation, pwn]
math: true
mermaid: true
media_subpath: /assets/posts/2025-12-28-interpreter
image:
  path: preview.png
---

## Interpreter - SNHT CTF '25
Difficulty: Easy

Overview: *Interpreter* is a challenge created by a friend of mine, **0x1337 (aka blood pwn)**. If you are into pwn, you have probably come across his work. His blog is packed with really solid writeups, which you can check out [here](https://h4ckyou.github.io/).

The challenge starts off with a buffer overflow vulnerability. We take advantage of this to leak libc addresses, and from there we move on to building a ROP chain to fully exploit the binary.

### Basic File Checks
As with most binary exploitation challenges, the first step is to check what security mitigations are in place.

```
checksec --file interpreter
[*] '/home/mcsam/Desktop/ctf/hck4g/interpret/new/interpreter'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```


This already looks promising. There is no stack canary, which means we can overwrite the return address without worrying about stack protection 😅. The binary is also not stripped, so we have access to symbols, making analysis a lot easier. Honestly, this setup is pretty close to every hacker’s dream 😄.

### Decompiling and identifying vulnerabilities
Before diving into decompilation, let us first interact with the program to observe how it behaves.

```
mcsam@0x32:~/Desktop/ctf/hck4g/interpret/new$ ./interpreter
> test
Unknown command: test
> help
Available commands: help, echo, exit
> echo hi
input: hi

> exit
Exiting interpreter.
```

When we type `test`, the program rejects it as an unknown command. Since it is standard practice to try a `help` command, we do so and get a list of allowed commands. One interesting option here is the `echo` command.

Trying `echo`, we see that it simply takes our input and prints it back to the console. Finally, the `exit` command does exactly what you would expect and cleanly terminates the program.


For the next stage we dump the binary into IDA and look at the decompilation.
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s1[112]; // [rsp+10h] [rbp-B0h] BYREF
  const char *v5; // [rsp+80h] [rbp-40h]
  _QWORD v6[5]; // [rsp+88h] [rbp-38h]
  int v7; // [rsp+B4h] [rbp-Ch]
  int i; // [rsp+B8h] [rbp-8h]
  int v9; // [rsp+BCh] [rbp-4h]

  v5 = "help";
  v6[0] = cmd_help;
  v6[1] = "exit";
  v6[2] = cmd_exit;
  v6[3] = "echo";
  v6[4] = cmd_echo;
  while ( 1 )
  {
    printf("> ");
    __isoc99_scanf("%s", s1);
    v9 = 0;
    v7 = 3;
    if ( !strncmp(s1, "DEBUG", 5uLL) )
      break;
    for ( i = 0; i < v7; ++i )
    {
      if ( !strcmp(s1, (const char *)v6[2 * i - 1]) )
      {
        ((void (__fastcall *)(char *))v6[2 * i])(s1);
        v9 = 1;
        break;
      }
    }
    if ( !v9 )
      printf("Unknown command: %s\n", s1);
  }
  printf("Debug mode triggered!");
  return 0;
}
```