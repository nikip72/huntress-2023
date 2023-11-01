# Batchfuscation
## _Difficultty: Medium_
## _Category: Malware_

### _Challenge code_ (https://github.com/nikip72/huntress-2023/blob/main/batchfuscation/batchfuscation.bat)

## Analysis

Code seems to be several stages obfuscated Windows/DOS batch file.

1st stage
```
set bdevq=set
%bdevq% grfxdh=
%bdevq%%grfxdh%mbbzmk==
%bdevq%%grfxdh%xeegh%mbbzmk%/
%bdevq%%grfxdh%jeuudks%mbbzmk%a
%bdevq%%grfxdh%rbiky%mbbzmk%c
%bdevq%%grfxdh%wzirk%mbbzmk%m
%bdevq%%grfxdh%naikpbo%mbbzmk%d
%bdevq%%grfxdh%ltevposie%mbbzmk%e
%bdevq%%grfxdh%uqcqswo%mbbzmk%x
%bdevq%%grfxdh%zvipzis%mbbzmk%i
%bdevq%%grfxdh%kquqjy%mbbzmk%t
%bdevq%%grfxdh%kmgnxdhqb%mbbzmk%
```
1st stage deobfuscated
```
set bdevq=set ; aliases set with %bdevq%
set grfxdh= ; aliases space with %grfxdh%
set mbbzmk== ; aliases = with %mbbzmk%
set xeegh=/ ; aliases / with %xeegh%
set jeuudks=a ; aliases a with %jeuudks%
set rbiky=c
set wzirk=m
set naikpbo=d
set ltevposie=e
set uqcqswo=x
set zvipzis=i
set kquqjy=t
set kmgnxdhqb=
```
That sets ground for the 2nd stage obfuscation
```
set /a bpquuu=4941956 %% 4941859 ; sets %bpquuu% with the reminder after division of 4941956/4941859 (97)
cmd /c exit %bpquuu% ; executes cmd and sets the exit code to 97
set grtoy=%=exitcodeAscii% ; sets %grtoy% to the symbol with the ascii code of the exit value (97) - small letter "a"
set /a fqumc=9273642 %% 9273544 ; sets %fqumc% with the reminder after division of 9273642/9273544 (98)
cmd /c exit %fqumc% ; executes cmd and sets the exit code to 98
set kbhoesxh=%=exitcodeAscii% ; sets %kbhoesxh% to the symbol with the ascii code of the exit value (98) - small letter "b"
...
```

2nd stage deobfuscated yelds a lot ot commented out code
```
rem set xjnhkbhki=piyyreuxgwvafwtz
:: set kyqjrobznfcjrlogdhalniqwjvxdtklyjzajcdkulwrsqrgdhcmbbpbz=dflnnmopuyiavetpibufiidl
rem set scahzpgynzthblbrgbfkzacckwkkjevkqsjkocewwpoofuxuoylvpl=dgzmfpwso
rem set yabqqisye=gsuqcaggmavfjkbeqztjwzogwqmsblfufxeyesxsbwdtpqhxhplkbtngtt
rem set ixdgycxyqjwefobdrqldsujqveastobdgbhtzsxqbegjscqjeqlsu=hfllpicdemouzjuouy
rem set kfhgehraybserbjbwhlsjqsnhatfuhtwhidejqbxmefljtd=lpmwnycvmqfjwmmviiaviacqfwlixonfagbeuvhfjjaqraidrlkzbkrgpgcbiahzpg
rem set yhtochyebnvonhegimouxwkxymzapsfptdemafjlgm=gwcxwyippxyeswpxxqdkdcwsotrquldxzwgwdrhfejohlpaqrl
rem set xzdpxkhxnjbsxwnhwjexorroputndcpmhxfdvjwrzaltthgnf=lmtddqnazznjjisbiicxqcuwypyaxqjcuzhopmbccipnywexzavuimzmivwkptiwrf
rem set mxzxuvxeesnttymlbqrymardpndjiktdgcby=gqiquumgi
rem set tuggsdldlihhsvmhwchmeteokxzvucplmjghiaeklqdxkqprs=ozxfutbmztpzrzkoarlecyhzfbv
rem set zprafh=brdjalrbmonpquembnmsprbqpdxnpzvcdyokfxooerwefrc
rem set mlisnjltrtyfqpufbywtfzlmifjaiincopuylp=mdeowweobivqxwuqaqvghlxhpwbkwycjbzuceaxwtebfq
rem set rzlfirs=teqegwxnxdrctbguyezbsnhxmytmoqfbjbg
rem set ykbmwoylnytvrixagwnnjxjfmxtdxzlbm=kprzkgxuhtxmkbifczkuwwy
rem set qfpcbxmm=wkqwxcxvjtgwmwockklpdmku
rem set syfpizuyzuexyqlgxlamuzwvbvexznqegzkiovogkbmlhiqd=wjbjdlczpwvgfudopwzjygsxdhkycjbndxxnppelc
set dfmuqbnyuhvsddyzhsxhwxlwpmwordwyfhuphvpsynweyvgehzuthiqaathjvdj=vfbemoxmalybjtxamshcbqhccbigsbccknmsacoqmwmxojidwamnufaxybytfblyqsmpr
rem set wzhsewkxkbxwsujytrqenuinbraohbw=ixjvcwkddbrgdbkozwneclbzkcccwddsx
rem set wkabhbepksynpeoxaozejvufkngvlpbxyclggpuqvqs=kflxzwjpvclvtekljlztoqcgwadrh
```

and hidden in the large volume of comments is the actual flag
```
:: set flag_character34=d
:: set flag_character20=3
:: set flag_character2=l
:: set flag_character1=f
:: set flag_character8=a
:: set flag_character10=6
:: set flag_character35=1
:: set flag_character37=a
:: set flag_character18=b
:: set flag_character32=b
:: set flag_character14=d
:: set flag_character16=b
:: set flag_character9=d
:: set flag_character6=a
:: set flag_character24=6
:: set flag_character28=3
:: set flag_character19=f
:: set flag_character33=9
:: set flag_character13=3
:: set flag_character23=c
:: set flag_character30=0
:: set flag_character22=a
:: set flag_character25=6
:: set flag_character15=0
:: set flag_character38=}
:: set flag_character27=9
:: set flag_character4=g
:: set flag_character31=d
:: set flag_character21=1
:: set flag_character36=9
:: set flag_character12=e
:: set flag_character5={
:: set flag_character7=c
:: set flag_character17=5
:: set flag_character26=3
:: set flag_character11=7
:: set flag_character3=a
:: set flag_character29=6
```

Now all that's left is to combine the flag back in the correct order 

### _Result of the provided deobfuscation script_ (https://github.com/nikip72/huntress-2023/blob/main/batchfuscation/process.sh)

```
$./process.sh                                                                                                                                                              
Filter 1: s/%bdevq%/set/g; s/%grfxdh%/ /g; s/%mbbzmk%/=/g; s/%mbbzmk%/=/g; s/%xeegh%/\//g; s/%jeuudks%/a/g; s/%rbiky%/c/g; s/%wzirk%/m/g; s/%naikpbo%/d/g; s/%ltevposie%/e/g; s/%uqcqswo%/x/g; s/%zvipzis%/i/g; s/%kquqjy%/t/g; s/%kmgnxdhqb%/ /g
Filter 2: ; s/%bpquuu%/a/g; s/%fqumc%/b/g; s/%uhtsvvtj%/c/g; s/%anbayva%/d/g; s/%sotjqqk%/e/g; s/%kefdskui%/f/g; s/%swjhnkfh%/g/g; s/%jorbiysyv%/h/g; s/%flxge%/i/g; s/%zlgzw%/j/g; s/%ftatwjg%/k/g; s/%cgxgvm%/l/g; s/%ntyoj%/m/g; s/%elclilwm%/n/g; s/%irslagq%/o/g; s/%btuppwj%/p/g; s/%gzdyksa%/q/g; s/%yiccuracj%/r/g; s/%btlsh%/s/g; s/%mxius%/t/g; s/%weqeuiwhe%/u/g; s/%tclckim%/v/g; s/%vlrqafxpd%/w/g; s/%pvghtbe%/x/g; s/%jbcipidt%/y/g; s/%owzhm%/z/g; s/%ljszdz%/A/g; s/%ifznlny%/B/g; s/%xwceeasg%/C/g; s/%gptsmr%/D/g; s/%yygufohuw%/E/g; s/%otcoj%/F/g; s/%gtdmanbtn%/G/g; s/%uixxtxsq%/H/g; s/%gozftxuja%/I/g; s/%mczpmy%/J/g; s/%jhwyfp%/K/g; s/%icjlehumi%/L/g; s/%zflmsmrp%/M/g; s/%ahetanul%/N/g; s/%efqyh%/O/g; s/%awwvnzp%/P/g; s/%nbwvzdt%/Q/g; s/%mrtvz%/R/g; s/%xlsji%/S/g; s/%vyzbsok%/T/g; s/%quuqsqur%/U/g; s/%dyylb%/V/g; s/%usdbnmgdk%/W/g; s/%ibyvajoq%/X/g; s/%viekui%/Y/g; s/%mfzvront%/Z/g; s/%zqkfqyssn%/0/g; s/%ceebiybcd%/1/g; s/%zhfigbfml%/2/g; s/%wblldl%/3/g; s/%xyhrs%/4/g; s/%idqamz%/5/g; s/%xtskgvz%/6/g; s/%inslgs%/7/g; s/%pwmerxkw%/8/g; s/%vacbwzeuf%/9/g; s/%fnmdd%/{/g; s/%mfafvc%/}/g; s/%pxzdtjp%/?/g; s/%bxefrhhlv%/:/g; s/%spagzw%/./g; s/%gfbizpau%/=/g; s/%jepfvvglt%/,/g; s/%byzlekew%/_/g
Filter3: ; s/%grtoy%/a/g; s/%kbhoesxh%/b/g; s/%fxflckau%/c/g; s/%pxesvvz%/d/g; s/%aeawgno%/e/g; s/%vdqvoyxss%/f/g; s/%mljmage%/g/g; s/%dtqahrd%/h/g; s/%xrghxw%/i/g; s/%rvrcd%/j/g; s/%cxqemy%/k/g; s/%djkxbuskp%/l/g; s/%auuhztfa%/m/g; s/%znvbyce%/n/g; s/%exoypdqzg%/o/g; s/%upogfi%/p/g; s/%xulqq%/q/g; s/%jxiczrrc%/r/g; s/%qihgjzq%/s/g; s/%ldawonn%/t/g; s/%edefpb%/u/g; s/%giknplvpv%/v/g; s/%fbvra%/w/g; s/%klerqtt%/x/g; s/%puufauef%/y/g; s/%lhuzd%/z/g; s/%iwwna%/A/g; s/%ilajhm%/B/g; s/%hzsouxmm%/C/g; s/%dqutqsgb%/D/g; s/%jkkvc%/E/g; s/%ioexkmd%/F/g; s/%jmcpbpld%/G/g; s/%udpmq%/H/g; s/%rbijdi%/I/g; s/%qzpkv%/J/g; s/%ikedxdamk%/K/g; s/%stcjm%/L/g; s/%majmn%/M/g; s/%utjscfnmq%/N/g; s/%bpxroxnqg%/O/g; s/%hrleb%/P/g; s/%wzprdlp%/Q/g; s/%fikmapqe%/R/g; s/%lwuwiovpd%/S/g; s/%lftuiqz%/T/g; s/%vogsuisdx%/U/g; s/%bsslmcgic%/V/g; s/%oyyfmilg%/W/g; s/%lhniwqwff%/X/g; s/%nvfosjl%/Y/g; s/%ajexk%/Z/g; s/%flopojsse%/0/g; s/%tqjmbt%/1/g; s/%wpwjwymw%/2/g; s/%wxkugd%/3/g; s/%fxqik%/4/g; s/%zygcfg%/5/g; s/%remydays%/6/g; s/%ztvra%/7/g; s/%yqdie%/8/g; s/%lzyqwgi%/9/g; s/%koimdqluu%/{/g; s/%tleci%/}/g; s/%vgysuv%/t/g; s/%xpjaysvii%/:/g; s/%nvsna%/./g; s/%vrzatob%/=/g; s/%orutn%/,/g; s/%hmjhafbu%/_/g

The flag is: flag{acad67e3d0b5bf31ac6639360db9d19a}
```

