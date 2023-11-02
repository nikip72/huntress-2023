# Bad Memory
## _Difficultty: Medium_
## _Category: Forensics_

### _Challenge code_ not included here, as it's a 600Mb archive

## Analysis

Unpacking the provided zip archive results in a huge 4.5Gb `image.bin` file. Running `strings` on the file reveals a lot of strings, unfortunately hunting down for passwords in clear text is unsuccessful.  Trying to mount the file as a raw file system is also unsuccessful. After some tinkering around it appears that the image is actually a forensic memory image, so next step is to try to analyze it with `volatility` (https://www.volatilityfoundation.org/)

```
$ vol -f image.bin windows.info                                                                                                                                              

Volatility 3 Framework 2.5.0
Progress:  100.00		PDB scanning finished
Variable	Value

Kernel Base	0xf8047e200000
DTB	0x1aa000
Symbols	file:///usr/local/Cellar/volatility/2.5.0/libexec/lib/python3.12/site-packages/volatility3/symbols/windows/ntkrnlmp.pdb/81BC5C377C525081645F9958F209C527-1.json.xz
Is64Bit	True
IsPAE	False
layer_name	0 WindowsIntel32e
memory_layer	1 FileLayer
KdVersionBlock	0xf8047ee0f2a8
Major/Minor	15.19041
MachineType	34404
KeNumberProcessors	1
SystemTime	2020-10-03 11:45:39
NtSystemRoot	C:\Windows
NtProductType	NtProductWinNt
NtMajorVersion	10
NtMinorVersion	0
PE MajorOperatingSystemVersion	10
PE MinorOperatingSystemVersion	0
PE Machine	34404
PE TimeDateStamp	Sun Aug 11 05:47:24 2069
```

and use `windows.hashdump` plugin to get password hashes

```
$ vol -f image.bin windows.hashdump

Volatility 3 Framework 2.5.0
Progress:  100.00		PDB scanning finished
User	rid	lmhash	nthash

Administrator	500	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
Guest	501	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount	503	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount	504	aad3b435b51404eeaad3b435b51404ee	4cff1380be22a7b2e12d22ac19e2cdc0
congo	1001	aad3b435b51404eeaad3b435b51404ee	ab395607d3779239b83eed9906b4fb92
```

Using online service to crack the password hash like (https://crackstation.net) reveals the password to be `goldfish#`, so the final flag is

```
$ echo flag{`echo -n goldfish#|md5`}        

flag{2eb53da441962150ae7d3840444dfdde}
```
