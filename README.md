# COBALTBREW

## Description:

This is a simple python script that allows the user to get multiple hashes for a local file on their system, or a remote file on the internet. Then the added option to check if that hash exists on Virustotal. The main objective here, was a quick simple way of getting multiple hashes, and confirming if someone has uploaded the file to Virustotal for anti-virus checks.<br />

<b>[+] Author:</b> xakep<br />
<b>[+] Language:</b> Python 2.*<br />
<b>[+] OS:</b> Linux<br />

![alt text](https://i.imgur.com/97RTcVE.gif "Strikewriter")

## Requirements:

Virustotal API Key - OPTIONAL - https://www.virustotal.com/
Python dependencies see below.

## Install:

```
$ git clone https://github.com/xakepnz/COBALTBREW.git
```

```
$ cd COBALTBREW
```

```
$ pip install -r requirements.txt
```

```
$ chmod +x cobaltbrew
```

```
$ ./cobaltbrew -f ~/Desktop/myfiles/unknown.pdf
$ ./cobaltbrew -r https://www.suspicious.site/odd.pdf -c
```
