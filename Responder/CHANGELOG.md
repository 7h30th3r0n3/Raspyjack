*In compliance with the [GPL-3.0](https://opensource.org/licenses/GPL-3.0) license: I declare that this version of the program contains my modifications, which can be seen through the usual "git" mechanism.*  


2022-08  
Contributor(s):  
lgandx  
>Added: append .local TLD to DontRespondToNames + MDNS bug fix  
>Merge pull request #199 from gblomqvist/masterFix double logging of first hash/cleartext when CaptureMultipleHashFromSameHost = On  
>Modified wpad script  
>fixed the RespondTo/DontRespondTo issue  
>Merge pull request #210 from 0xjbb/masterAdded Quiet Mode  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2022-07  
Contributor(s):  
jb  
lgandx  
>Minor bugs and display/logging fixes + RDP srv SSLwrapping fix  
>Fixed: Warnings on python 3.10  
>Added Quiet mode  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2022-05  
Contributor(s):  
lgandx  
>removed -r reference from help msg.  
>removed -r references  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2022-04  
Contributor(s):  
Gustaf Blomqvist  
>Fix double logging of first hash or cleartext  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2022-02  
Contributor(s):  
Tom Aviv  
Andrii Nechytailov  
kitchung  
lgandx  
>Merge pull request #190 from kitchung/kitchung-patch-1DE-RPC server status not correct  
>DE-RPC server status not correct #189Line 512 should read:
print(' %-27s' % "DCE-RPC server" + (enabled if settings.Config.DCERPC_On_Off else disabled))

Instead of:
print(' %-27s' % "DCE-RPC server" + (enabled if settings.Config.RDP_On_Off else disabled))  
>MutableMapping was moved to collections.abc  
>Merge pull request #191 from Mipsters/masterMutableMapping was moved to collections.abc  
>Fixed options formating in README  
>Merge pull request #188 from Ne4istb/patch-1Fixed options formating in README  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2022-01  
Contributor(s):  
lgandx  
root  
>Updated the README and Responder help flags  
>Merge pull request #185 from ajkerley628/masterUpdated the README and Responder help flags  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2021-12  
Contributor(s):  
lgandx  
>Added IPv6 support  
>Updated the Readme file with the new options and removed some old stuff  
>Added date and time for each Responder session config log.  
>Remove analyze mode on DNS since you need to ARP to get queries  
>Removed the static certs and added automatic cert generation  
>added DHCP db & updated the report script to reflect that  
>Added DHCP DNS vs WPAD srv injection  
>Merge pull request #136 from ghost/patch-2Correct Analyze log filename  
>added support for OPT EDNS  
>Added DHCP DNS vs DHCP WPAD  
>Fixed the ON/OFF for poisoners when in Analyze mode.  
>minor display fix.  
>added the ability to provide external IP on WPAD poison via DHCP  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2021-11  
Contributor(s):  
lgandx  
>DHCP: Added auto WPADscript configuration with our IP instead of hardcoded NBT string  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2021-10  
Contributor(s):  
lgandx  
>Added DHCP server  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2021-05  
Contributor(s):  
Pixis  
lgandx  
pixis  
>minor fix  
>Add ESS disabling information  
>Add --lm switch for ESS downgrade  
>Add ESS downgrade parameter  
>Merge pull request #163 from Hackndo/masterAdd ESS downgrade parameter  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2021-04  
Contributor(s):  
lgandx  
>forgot to add packets.py  
>Added WinRM rogue server  
>Added dce-rpc module + enhancements + bug fix.  
>removed addiontional RR on SRV answers  
>Update README.md  
>Update README.mdAdded Synacktiv as major donor.  
>Added DNS SRV handling for ldap/kerberos + LDAP netlogon ping  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2021-03  
Contributor(s):  
lgandx  
>Removed donation banner  
>minor fix  
>Ported to py3  
>added a check for exec file  
>made compatible py2/py3  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2021-02  
Contributor(s):  
lgandx  
>added donation address and minor typo  
>Added donation banner.  
>added smb filetime support  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2020-12  
Contributor(s):  
lgandx  
>Merge pull request #145 from khiemdoan/fix-syntaxFix wrong syntax  
>Merge pull request #135 from LabanSkollerDefensify/patch-1Fix typos in README  
>Added SMB2 support for RunFinger and various other checks.  
>Merge pull request #138 from ThePirateWhoSmellsOfSunflowers/fix_challengefix custom challenge in python3  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2020-11  
Contributor(s):  
Khiem Doan  
>Fix wrong syntax  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2020-10  
Contributor(s):  
ThePirateWhoSmellsOfSunflowers  
>small fix  
>fix custom challenge in python3  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2020-09  
Contributor(s):  
nickyb  
Laban Sköllermark  
lgandx  
>Merge pull request #133 from NickstaDB/fix-bind-addressUse settings.Config.Bind_To as bind address.  
>Fixed LLMNR/NBT-NS/Browser issue when binding to a specific interface  
>Fix typos in README* Missing "is" in description of the tool
* s/an unique/a unique/ since it starts with a consonant sound
* Move a word to its correct place  
>Correct Analyze log filenameThe default filename for Analyze logs is Analyzer-Session.log, not
Analyze-Session.log.  
>Use settings.Config.Bind_To as bind address.  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2020-08  
Contributor(s):  
lgandx  
>python3.8 compability fix  
>py3 bugfix  
>version update  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2020-02  
Contributor(s):  
lgandx  
Sophie Brun  
>Fix encoding issue in Python 3  
>Merge pull request #117 from sbrun/masterFix encoding issue in Python 3  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2020-01  
Contributor(s):  
lgandx  
>Added py3 and py2 compatibility + many bugfix  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2019-08  
Contributor(s):  
lgandx  
>Added RDP rogue server  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2019-05  
Contributor(s):  
lgandx  
>Merge pull request #92 from Crypt0-M3lon/masterFix socket timeout on HTTP POST requests  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2019-02  
Contributor(s):  
Crypt0-M3lon  
>Fix socket timeout on HTTP POST requestsRemaining size should be checked at the end of the loop, the current implementation hang when POST request Content-Lenght is 0.
We want to check for Content-Length header only if we received full header.  
>Merge pull request #1 from Crypt0-M3lon/Crypt0-M3lon-patch-1Fix socket timeout on HTTP POST requests  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2019-01  
Contributor(s):  
Clément Notin  
lgandx  
>Merge pull request #89 from cnotin/patch-1Replace ParseSMB2NTLMv2Hash() by ParseSMBHash() to handle NTLMv1 and NTLMv2  
>Replace ParseSMB2NTLMv2Hash() by ParseSMBHash() to handle NTLMv1 and NTLMv2  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2018-11  
Contributor(s):  
lgandx  
>removed debug string  
>Merge pull request #86 from mschader/patch-1Update README.md: Fix typo  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2018-10  
Contributor(s):  
Markus  
>Update README.md: Fix typoFixed just a tiny typo.  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2018-08  
Contributor(s):  
Clément Notin  
lgandx  
>Fix version number in settings.py  
>Fix multi HTTP responses  
>Merge pull request #83 from cnotin/patch-2Fix multi HTTP responses  
>Merge pull request #80 from myst404/masterBetter handling of cleartext credentials  
>Merge pull request #82 from cnotin/patch-1Fix version number in settings.py  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2018-06  
Contributor(s):  
myst404  
>Better handling of cleartext credentials  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2017-11  
Contributor(s):  
Lionel PRAT  
lgandx  
>Add ignore case on check body for html inject  
>Merge pull request #67 from lprat/masterAdd ignore case on check body for html inject  
>Merge pull request #51 from watersalesman/masterFixed instances of "CRTL-C" to "CTRL-C"  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2017-09  
Contributor(s):  
lgandx  
>Changed the complete LDAP parsing hash algo (ntlmv2 bug).  
>Fixed various bugs and improved the LDAP module.  
>Several Bugfix  
>added support for plain auth  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2017-08  
Contributor(s):  
OJ  
lgandx  
>Pass Challenge value to the LDAP parsing function  
>Merge pull request #61 from OJ/fix-ldap-hash-parsingPass Challenge value to the LDAP parsing function  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2017-07  
Contributor(s):  
lgandx  
>Merge pull request #58 from megabug/mssql-browserAdd Microsoft SQL Server Browser responder  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2017-06  
Contributor(s):  
Matthew Daley  
>Add Microsoft SQL Server Browser responderWhen connecting to a named instance, a SQL client (at least SQL ServerNative Client) will send a request (namely a CLNT_UCAST_INST message) tothe server's SQL Server Browser service for instance connectioninformation. If it gets no response, the connection attempt fails.By adding a SQL Server Browser responder for these requests, we ensurethat connections are successfully made to the SQL Server responder forhash capture.As per the comment, this is based on the document "[MC-SQLR]: SQL ServerResolution Protocol", currently available at<https://msdn.microsoft.com/en-us/library/cc219703.aspx>.  
>Update README.md with new SQL Browser port usage  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2017-04  
Contributor(s):  
Randy Ramos  
>Fixed instances of "CRTL-C" to "CTRL-C"  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2017-03  
Contributor(s):  
lgandx  
>Fixed bug in FindSMB2UPTime  
>Removed Paypal donation link.  
>updated readme  
>MultiRelay 2.0 Release  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2017-02  
Contributor(s):  
skelsec  
lgandx  
Gifts  
>Fix for RandomChallenge function. Function getrandbits can return less than 64 bits, thus decode('hex') will crash with TypeError: Odd-length string  
>minor fix  
>Merge pull request #25 from joshuaskorich/masteradded `ip` commands in addition to ifconfig and netstat  
>SimpleSSL  
>making HTTP great again  
>Merge pull request #32 from Gifts/fix_randchallengeFix for RandomChallenge function.  
>cleaning up comments  
>Added: Hashdump, Stats report  
>fixed crash: typo.  
>Merge pull request #33 from skelsec/masterFixing HTTP header issue  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2017-01  
Contributor(s):  
thejosko  
lgandx  
>Added: Random challenge for each requests (default)  
>added `ip` commands in addition to ifconfig and netstat  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2016-12  
Contributor(s):  
lgandx  
>Added paypal button  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2016-11  
Contributor(s):  
lgandx  
>Added: BTC donation address  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2016-10  
Contributor(s):  
Nikos Vassakis  
lgandx  
>Fixed wrong challenge issue  
>Fixed the bind to interface issue (https://github.com/lgandx/Responder/issues/6)  
>Changed to executable  
>fixed bug in hash parsing.  
>updated version number  
>Patch for Android 4.x terminals that are missing some linux commands  
>Fix values for win98 and win10 (requested here: https://github.com/lgandx/Responder/pull/7/commits/d9d34f04cddbd666865089d809eb5b3d46dd9cd4)  
>Updated versions  
>Minor fix  
>Merge pull request #14 from nvssks/masterPatch for Android 4.x terminals that are missing some linux commands  
>updated to current version.  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2016-09  
Contributor(s):  
lgaffie  
lgandx  
>bug: removed loop, while connection handled by basehttpserver  
>updated version  
>Added proxy auth server + various fixes and improvements  
>Added SMBv2 support enabled by default.  
>minor fix  
>Added support for webdav, auto credz.  
>Added current date for all HTTP headers, avoiding easy detection  
>removed debug info  
>Added option -e, specify an external IP address to redirect poisoned traffic to.  
>Config dumped independently. Responder-Session.log is now a clean file.  
>Reflected recent changes.  
>Removed the config dump in Responder-Session.log. New file gets created in logs, with host network config such as dns, routes, ifconfig and config dump  
>minor bug fix  
>Fixed colors in log files  
>Firefox blacklisted on WPAD since it doesn't honors fail-over proxies. Added SO_LINGER to send RST when close() is called.  
>Added new option in Responder.conf. Capture multiple hashes from the same client. Default is On.  
>minor fixes  
>Minor fixes  
>Removed useless HTTP headers  
>Minor fix  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 

