# COBALTBREW

## Description:

Obtain file hashes of any local file. Optional search against Virustotal with hash results found. Multi-file support.<br />

## Requirements:

<b>OPTIONAL</b> Virustotal API Key - https://www.virustotal.com/<br />

## Install:

```
git clone https://github.com/xakepnz/COBALTBREW.git
cd COBALTBREW
nano cobaltbrew #Edit API Key (optional)
chmod +x cobaltbrew
cp cobaltbrew /usr/local/bin
```


## Usage:

<b>Single file, no Virustotal check:</b>
```
cobaltbrew -f /path/to/my/localfile
```
<b>Multiple files, no Virustotal check:</b>
```
cobaltbrew -m /path/to/new-line/separated/file/paths.txt
```
<b>With Virustotal check, add your API key in the source, and add the flag -s</b><br />

```
cobaltbrew -f /some/file -s
cobaltbrew -m /path/to/multi.txt -s
```
