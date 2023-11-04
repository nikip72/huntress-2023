# Thumb Drive
## _Difficultty: Medium_
## _Category: Malware_

### _Challenge code_ (https://github.com/nikip72/huntress-2023/blob/main/thumbdrive/ADATA_128GB.lnk.download)

## Analysis

Inspecting the lnk file with a hex viewer a tinyurl link pops up

```
$ xdd ADATA_128GB.lnk.download
00000190: 0000 0011 0000 0003 0000 0076 5659 4e10  ...........vVYN.
000001a0: 0000 0000 433a 5c57 696e 646f 7773 5c53  ....C:\Windows\S
000001b0: 7973 7465 6d33 325c 636d 642e 6578 6500  ystem32\cmd.exe.
000001c0: 000b 0041 0044 0041 0054 0041 0020 0031  ...A.D.A.T.A. .1
000001d0: 0032 0038 0047 0042 0036 020d 000a 000a  .2.8.G.B.6......
....
00000620: 0020 0009 002f 0056 002f 0052 0009 0043  . .../.V./.R...C
00000630: 004d 0044 003c 0068 0074 0074 0070 0073  .M.D.<.h.t.t.p.s
00000640: 003a 002f 002f 0074 0069 006e 0079 0075  .:././.t.i.n.y.u
00000650: 0072 006c 002e 0063 006f 006d 002f 0061  .r.l...c.o.m./.a
00000660: 0037 0062 0061 0036 006d 0061 0000 0000  .7.b.a.6.m.a
....
00000680: 0000 0000 0014 0300 0001 0000 a025 7769  .............%wi
00000690: 6e64 6972 255c 5379 7374 656d 3332 5c63  ndir%\System32\c
000006a0: 6d64 2e65 7865 0000 0000 0000 0000 0000  md.exe..........
....
00000790: 0025 0077 0069 006e 0064 0069 0072 0025  .%.w.i.n.d.i.r.%
000007a0: 005c 0053 0079 0073 0074 0065 006d 0033  .\.S.y.s.t.e.m.3
000007b0: 0032 005c 0063 006d 0064 002e 0065 0078  .2.\.c.m.d...e.x
000007c0: 0065 0000 0000 0000 0000 0000 0000 0000  .e
```

Visting `https://tinyurl.com/a7ba6ma` redirects to a text file `usb.txt` (https://github.com/nikip72/huntress-2023/blob/main/thumbdrive/usb.txt) hosted on google.drive.
The file looks like it's been baseXX encoded:
```
$ cat usb.txt                                                                                                                                                                
JVNJAAADAAAAABAAAAAP77YAAC4AAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7AAAAAAOD65A4AFUBHGSDOABJTGSCVDINFZSA4DSN5TXEYLNEBRWC3TON52CAYTFEBZHK3RANFXCARCPKMQG233EMUXA2DIKEQAAAAAAAAAAAZ3NYOZSGDFN4ARQZLPAEMGK3YBKOQ7OAIIMVXQIE65M4EQQZLPAQJ52RYJJBSW6BAT3VHQSSDFN4CBHXLXBEIGK3YBXM6WOCJQMVXQCGDFM4ABQZLPA2F52JYJCBSW6BUL3VXQSEDFN4DIXWUXAEIGK3YGRPOX6CIQMVXQFE2LDNARQZLPAAAAAAAAAAAAAAUCFAAAEYAIFADLX6VTCAAAAAAAAAAAABYAAAIQQWAIODYABAAAAAAKAAAAAAAAAABIVAAAAAEAAAAACAAAAAAAAAEAACAAAAAACAAAAMAAAAAAAAAAAAYAAAAAAAAAAAADAAAAAABAAAAAAAAAAAIAEAAIAAAIAAAAQAAAAAAAQAAABAAAAAAAAAAAQAAAABUBGAAAGYAAAAA6COAAAMQAAAAAAIAAABYABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC
...
NV4G3ADMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA===
```

And by the looks of it - alphabet of capitals + '='  - most probaly base32.
CyberChef (https://gchq.github.io/CyberChef/) confirms this and decodes the provided text into an EXE Windows binary, confirmed by magic bytes `MZ` and text `This program cannot be run in DOS mode.`

![](https://github.com/nikip72/huntress-2023/blob/main/thumbdrive/cyberchef.png)

Running `speakeasy` (https://github.com/mandiant/speakeasy) reveals the flag

```
$ speakeasy -t usb_mal.exe -a amd64                                                                                                                                        

* exec: dll_entry.DLL_PROCESS_ATTACH
0x10001662: 'KERNEL32.GetSystemTimeAsFileTime(0x12fffc8)' -> None
0x10001671: 'KERNEL32.GetCurrentThreadId()' -> 0x434
0x1000167a: 'KERNEL32.GetCurrentProcessId()' -> 0x420
0x10001687: 'KERNEL32.QueryPerformanceCounter(0x12fffc0)' -> 0x1
0x10001c13: 'KERNEL32.IsProcessorFeaturePresent("PF_XMMI64_INSTRUCTIONS_AVAILABLE")' -> 0x1
0x100018cf: 'api-ms-win-crt-runtime-l1-1-0._initialize_onexit_table(0x10003364)' -> 0x0
0x100018de: 'api-ms-win-crt-runtime-l1-1-0._initialize_onexit_table(0x10003370)' -> 0x0
0x100016ed: 'KERNEL32.InitializeSListHead(0x10003340)' -> None
0x10001283: 'api-ms-win-crt-runtime-l1-1-0._initterm_e(0x10002080, 0x10002084)' -> 0x0
0x10001c13: 'KERNEL32.IsProcessorFeaturePresent("PF_XMMI64_INSTRUCTIONS_AVAILABLE")' -> 0x1
0x100012a1: 'api-ms-win-crt-runtime-l1-1-0._initterm(0x10002078, 0x1000207c)' -> 0x0
0x100011ae: 'KERNEL32.CreateThread(0x0, 0x0, 0x10001000, 0x0, 0x0, 0x0)' -> 0x220
* exec: export._DllMain@12
* exec: export._MessageBoxThread@4
0x10001171: 'USER32.MessageBoxA(0x0, "flag{0af2873a74cfa957ccb90cef814cfe3d}", "Your flag is:", 0x0)' -> 0x2
* exec: thread
0x10001171: 'USER32.MessageBoxA(0x0, "flag{0af2873a74cfa957ccb90cef814cfe3d}\t3<", "Your flag is:", 0x0)' -> 0x2
* Finished emulating
```
