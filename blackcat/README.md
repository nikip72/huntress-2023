# BlackCat
## _Difficultty: Easy_
## _Category: Malware_

### _Challenge code_ (https://github.com/nikip72/huntress-2023/blob/main/blackcat/blackcat.7z)
### _password_: infected

## Analysis

BlackCat challenge contains an executable file (decryptor) and a bunch of encrypted files with .encry extension including the flag.txt.encry. Premise is files are encrypted by a ransomware gang and we need to decrypt them.

```
2023-09-26 14:10:56 D...A            0            0  victim-files
2023-09-26 14:10:56 ....A      1190420      1371632  NOTE.png
2023-09-26 14:10:56 ....A       109857               victim-files/Bliss_Windows_XP.png.encry
2023-09-26 14:10:56 ....A           74               victim-files/flag.txt.encry
2023-09-26 14:10:56 ....A         8457               victim-files/Huntress-Labs-Logo-and-Text-Black.png.encry
2023-09-26 14:10:56 ....A        13959               victim-files/my-favorite-rock.jpg.encry
2023-09-26 14:10:56 ....A       191725               victim-files/the-entire-text-of-hamlet.txt.encry
2023-09-26 14:10:56 ....A      2814464      1461536  DecryptMyFiles.exe
```

Running `strings` command on the encrypted files reveals that there is a common pattern in `victim-files/the-entire-text-of-hamlet.txt.encry`

$ strings the-entire-text-of-hamlet.txt.encry|less
```
7'6M;0..&+*M $O!""?(;NO91&=.*B /C+6#"#="iey
eyge&
ecCO0
CeBO$
AyMO*
AcCO#
CehOICOSMOBOICOSMOBOICO6
...
COBOICOSMOBOICOSMOBOICOSMOBOICOSMOBO,
LeBOICOSMOBOICOSMOBOICOSMOBOICOSMOBOICOSMOBOICOSMOBOICO6
...
]geBOICOSMOBOICOSMOBOICOS(
AheICOS/
CeICOS$H
AOO:
NhOICOSMOBOICOSMOBOICOSMOBOICOSMOBOICOSMOBOICOSMO1
...
```

That suggests that the text is XOR'd with the key 'COSMOBOI', as XOR encryption over 0 (null) returns the key due to it's truth table.
```
A | B | Y
---------
0 | 0 | 0
0 | 1 | 1
1 | 0 | 1
1 | 1 | 0
```

Checking the asumption with CyberChef (https://gchq.github.io/CyberChef/)

![] (https://github.com/nikip72/huntress-2023/blob/main/blackcat/hamlet1.png)

That reveals the text of Hamlet, although case is mismatched and space symbols are NULLs.
```
thetragedyofhamletprinceofdenmark***BYwILLIAMsHAKESPEARE****dRAMATIS
```

As ASCII code of space is 32, that suggests that before XOR'ing 32 is substracted from the ascii code, then XORd

![] (https://github.com/nikip72/huntress-2023/blob/main/blackcat/hamlet2.png)

That fixes lowercase, but messes up with some of the special chars and uppercase letters. BUT. As we know from the challenge rules, flag is only numbers, lowercase letters (a-f) and {}, so for an easy win we can try and decrypt flag.txt.encry without decrypting input anymore.

![] (https://github.com/nikip72/huntress-2023/blob/main/blackcat/flag.png)


