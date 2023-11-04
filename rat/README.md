# RAT
## _Difficultty: Medium_
## _Category: Malware_

### _Challenge code_ (https://github.com/nikip72/huntress-2023/blob/main/rat.7z)
### _password: infected_


## Analysis

Now, I'm almost ashamed of solving this challange the way I did. Almost.
First step after receiving any malware sample for me is to load it into any (or all) of the excellent analysis tools provided by the community to check if the sample is already seen, comments about it, any obvious behaviour etc.

Some of the tools I use, in no particular order:

- speakeasy (offline) (https://github.com/mandiant/speakeasy)
- VirusTotal (online) (https://www.virustotal.com)
- Any.Run (online)  (https://any.run)
- Hybrid Analysis (online) (https://www.hybrid-analysis.com)
- Tria.ge (online) (https://tria.ge)

Uploading the sample to `VirusTotal` shows quite some detections (at the moment).

![](https://github.com/nikip72/huntress-2023/blob/main/rat/VT1.png)

Checking the `BEHAVIOR` tab. at the bottom there is a section `Decoded text` that contains some strings automatically extracted that were `input or output of an encoding operations while the file was studied`.

![](https://github.com/nikip72/huntress-2023/blob/main/rat/VT2.png)
...
![](https://github.com/nikip72/huntress-2023/blob/main/rat/VT3.png)


So the flag is revealed.
