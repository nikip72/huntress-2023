# Rogue Inbox
## _Difficultty: Medium_
## _Category: Forensics_

### _Challenge code_ (https://github.com/nikip72/huntress-2023/blob/main/rogueinbox/purview.csv)

## Analysis

Purview.csv is an exported comma-separated log file from Microsoft Purview.

First thing is to get all entries for the suspected user `Debra`

```
$ grep -i debra purview.csv > debra.csv
```

Importing the resulting file in Excel reveals quite some lines with `New-InboxRule`. 
Looking at them they all appear to hold a value of `flag@ctf.com`. 

Grepping the file for `flag@ctf.com`

![](https://github.com/nikip72/huntress-2023/blob/main/rogueinbox/flag.png)

{""Name"":""From"",""Value"":""flag@ctf.com""},{""Name"":""MoveToFolder"",""Value"":""Conversation History""},{""Name"":""Name"",""Value"":`""f""`}
{""Name"":""From"",""Value"":""flag@ctf.com""},{""Name"":""MoveToFolder"",""Value"":""Conversation History""},{""Name"":""Name"",""Value"":`""l""`}
{""Name"":""From"",""Value"":""flag@ctf.com""},{""Name"":""MoveToFolder"",""Value"":""Conversation History""},{""Name"":""Name"",""Value"":`""a""`}
{""Name"":""From"",""Value"":""flag@ctf.com""},{""Name"":""MoveToFolder"",""Value"":""Conversation History""},{""Name"":""Name"",""Value"":`""g""`}
{""Name"":""From"",""Value"":""flag@ctf.com""},{""Name"":""MoveToFolder"",""Value"":""Conversation History""},{""Name"":""Name"",""Value"":`""{""`}
{""Name"":""From"",""Value"":""flag@ctf.com""},{""Name"":""MoveToFolder"",""Value"":""Conversation History""},{""Name"":""Name"",""Value"":`""2""`}

A small one-liner to extract the flag:

```
$ cat purview.csv|grep flag@ctf.com|cut -d":" -f 40|sed "s/\"\"//g; s/},{Name//g"|tr -d "\n"
flag{24c4230fa7d50eef392b2c850f74b0f6}
```
