#!/usr/bin/python

import virustotal, argparse, os, sys, hashlib

############################################################################################
# Virustotal API Key: (Optional)
############################################################################################

VIRUSTOTALKEY = ''

############################################################################################
# Variables:
############################################################################################

buffer = 65536
url = None
localfile = None
check = False
platform = False
md5 = hashlib.md5()
sha1 = hashlib.sha1()
sha256 = hashlib.sha256()
sha512 = hashlib.sha512()
trash = 'trash'
agent = ('"COBALTBREW - https://www.github.com/xakepnz/COBALTBREW"')
v = virustotal.VirusTotal(VIRUSTOTALKEY)

############################################################################################
# Local files Function, no check:
############################################################################################

def localfiles():
    try:
        if os.path.isfile(localfile) is False:
           print bcolors.WARNING,'[?] Does: ' + file + ' Exist?',bcolors.ENDC
           print bcolors.FAIL,'[!] Error: File not found...\n',bcolors.ENDC
           exit(0)
        with open(localfile, 'rb') as f:
                while True:
                    data = f.read(buffer)
                    if not data:
                        break
                    md5.update(data)
                    sha1.update(data)
                    sha256.update(data)
                    sha512.update(data)
        print bcolors.BOLD,'\n[+] Hash Results:\n',bcolors.ENDC
        print bcolors.OKBLUE,(' File:   ' + localfile + '\n'),bcolors.ENDC
        print bcolors.OKGREEN,(' MD5:    {0}'.format(md5.hexdigest())),bcolors.ENDC
        print bcolors.OKGREEN,(' SHA1:   {0}'.format(sha1.hexdigest())),bcolors.ENDC
        print bcolors.OKGREEN,(' SHA256: {0}'.format(sha256.hexdigest())),bcolors.ENDC
        print bcolors.OKGREEN,(' SHA512: {0}'.format(sha512.hexdigest())) + '\n',bcolors.ENDC
        exit (0)
    except Exception as e:
        print bcolors.FAIL,'[!] Error: Unable to computate hashes...',e,bcolors.ENDC

############################################################################################
# Local files hash, with check:
############################################################################################

def localfilescheck():
    try:
        if os.path.isfile(localfile) is False:
           print bcolors.WARNING,'[?] Does: ' + file + ' Exist?',bcolors.ENDC
           print bcolors.FAIL,'[!] Error: File not found...\n',bcolors.ENDC
           exit(0)
        with open(localfile, 'rb') as f:
                while True:
                    data = f.read(buffer)
                    if not data:
                        break
                    md5.update(data)
                    sha1.update(data)
                    sha256.update(data)
                    sha512.update(data)
        print bcolors.BOLD,'[+] Hash Results:\n',bcolors.ENDC
        print bcolors.OKBLUE,(' File:   ' + localfile + '\n'),bcolors.ENDC
        print bcolors.OKGREEN,(' MD5:    {0}'.format(md5.hexdigest())),bcolors.ENDC
        print bcolors.OKGREEN,(' SHA1:   {0}'.format(sha1.hexdigest())),bcolors.ENDC
        print bcolors.OKGREEN,(' SHA256: {0}'.format(sha256.hexdigest())),bcolors.ENDC
        print bcolors.OKGREEN,(' SHA512: {0}'.format(sha512.hexdigest())) + '\n',bcolors.ENDC
        localsha = sha256.hexdigest()
        report = v.get(localsha)
        if report is None:
            print bcolors.FAIL,'\n[!] Failed: SHA256 Hash does not exist on Virustotal!\n',bcolors.ENDC
            exit(0)
        else:
            pass
        if report.done:
            print bcolors.BOLD,'[+] Virustotal Report:',bcolors.ENDC
            print bcolors.OKBLUE,'[+] - Link:',report.permalink,'\n',bcolors.ENDC
            print bcolors.BOLD,' [+] Results:\n',bcolors.ENDC
            print bcolors.OKGREEN,' [+] Resource Status:',report.status,bcolors.ENDC
            print bcolors.OKGREEN,' [+] Antivirus Total:',report.total,bcolors.ENDC
            print bcolors.OKGREEN,' [+] Antivirus Positives:',report.positives,'\n',bcolors.ENDC
            for antivirus, malware in report:
                if malware is not None:
                    print bcolors.OKGREEN,'[+]Antivirus:',antivirus[0],bcolors.ENDC
                    print bcolors.OKGREEN,'Antivirus Version:',antivirus[1],bcolors.ENDC
                    print bcolors.OKGREEN,'Antivirus Update:',antivirus[2],bcolors.ENDC
                    print bcolors.OKGREEN,'Malware:',malware,bcolors.ENDC
                    exit(0)
    except Exception as e:
        print bcolors.FAIL,'[!] Error: Unable to computate hashes...',e,bcolors.ENDC

############################################################################################
# Remote files hash, no check:
############################################################################################

def remotefiles():
    try:
        print bcolors.BOLD,'\n[+] Downloading:',url,bcolors.ENDC
        if sys.platform == 'darwin':
                platform = True
                remotefile = os.system('curl ' + url + ' -o ' + trash + ' -A ' + agent + ' -f' + ' -k' + ' -s')
        if sys.platform == 'linux2':
                platform = True
                remotefile = os.system('wget ' + ' -q' + ' -c' + ' -U ' + agent + ' --no-check-certificate ' + url + ' -O ' + trash)
        if sys.platform == 'win32':
                platform = True
                print bcolors.FAIL,'\n[!] Error. This feature does not work on Windows.\n',bcolors.ENDC
                exit (0)
        if sys.platform == 'cygwin':
                platform = True
                print bcolors.FAIL,'\n[!] Error. This feature does not work on Cygwin.\n',bcolors.ENDC
                exit(0)
        if platform == False:
                print bcolors.FAIL,'\n[!] Error. Unknown OS.\n',bcolors.ENDC
                exit(0)
        print bcolors.OKGREEN,'\n [+] Temporarily saved as: ' + '"'+trash+'"',bcolors.ENDC
    except Exception as e:
           print bcolors.FAIL,'\n[!] Error: Unable to download remote file...\n',e,bcolors.ENDC
           exit(0)

    try:
        with open(trash, 'rb') as f:
            while True:
                data = f.read(buffer)
                if not data:
                    break
                md5.update(data)
                sha1.update(data)
                sha256.update(data)
                sha512.update(data)
        os.system('rm ' + trash)
        
        print bcolors.BOLD,'\n[+] Hash Results:\n',bcolors.ENDC
        print bcolors.OKBLUE,(' URL:   ' + str(url)) + '\n',bcolors.ENDC
        print bcolors.OKGREEN,(' MD5:    {0}'.format(md5.hexdigest())),bcolors.ENDC
        print bcolors.OKGREEN,(' SHA1:   {0}'.format(sha1.hexdigest())),bcolors.ENDC
        print bcolors.OKGREEN,(' SHA256: {0}'.format(sha256.hexdigest())),bcolors.ENDC
        print bcolors.OKGREEN,(' SHA512: {0}'.format(sha512.hexdigest())) + '\n',bcolors.ENDC
        print bcolors.OKGREEN,'[+] Temporary file was deleted.\n',bcolors.ENDC
        exit(0)
    except Exception as e:
           print bcolors.FAIL,'\n[!] Error: There was an issue hashing remotely...\n',e,bcolors.ENDC
           exit(0)


############################################################################################
# Remote files hash, with check:
############################################################################################

def remotefilescheck():
    try:
        print bcolors.BOLD,'\n[+] Downloading:',url,bcolors.ENDC
        if sys.platform == 'darwin':
                platform = True
                remotefile = os.system('curl ' + url + ' -o ' + trash + ' -A ' + agent + ' -f' + ' -k' + ' -s')
        if sys.platform == 'linux2':
                platform = True
                remotefile = os.system('wget ' + ' -q' + ' -c' + ' -U ' + agent + ' --no-check-certificate ' + url + ' -O ' + trash)
        if sys.platform == 'win32':
                platform = True
                print bcolors.FAIL,'\n[!] Error. This feature does not work on Windows.\n',bcolors.ENDC
                exit (0)
        if sys.platform == 'cygwin':
                platform = True
                print bcolors.FAIL,'\n[!] Error. This feature does not work on Cygwin.\n',bcolors.ENDC
                exit(0)
        if platform == False:
                print bcolors.FAIL,'\n[!] Error. Unknown OS.\n',bcolors.ENDC
                exit(0)
        print bcolors.OKGREEN,'\n [+] Temporarily saved as: ' + '"'+trash+'"',bcolors.ENDC
    except Exception as e:
           print bcolors.FAIL,'\n[!] Error: Unable to download remote file...\n',e,bcolors.ENDC
           exit(0)

    try:
        with open(trash, 'rb') as f:
            while True:
                data = f.read(buffer)
                if not data:
                    break
                md5.update(data)
                sha1.update(data)
                sha256.update(data)
                sha512.update(data)
        os.system('rm ' + trash)
        print bcolors.BOLD,'\n[+] Hash Results:\n',bcolors.ENDC
        print bcolors.OKBLUE,(' URL:   ' + str(url)) + '\n',bcolors.ENDC
        print bcolors.OKGREEN,(' MD5:    {0}'.format(md5.hexdigest())),bcolors.ENDC
        print bcolors.OKGREEN,(' SHA1:   {0}'.format(sha1.hexdigest())),bcolors.ENDC
        print bcolors.OKGREEN,(' SHA256: {0}'.format(sha256.hexdigest())),bcolors.ENDC
        print bcolors.OKGREEN,(' SHA512: {0}'.format(sha512.hexdigest())) + '\n',bcolors.ENDC
        print bcolors.OKGREEN,'[+] Temporary file was deleted.\n',bcolors.ENDC
        remotesha = sha256.hexdigest()
        report = v.get(remotesha)
        if report is None:
            print bcolors.FAIL,'\n[!] Failed: SHA256 Hash does not exist on Virustotal!\n',bcolors.ENDC
            exit(0)
        else:
            pass
        if report.done:
            print bcolors.BOLD,'[+] Virustotal Report:',bcolors.ENDC
            print bcolors.OKBLUE,'[+] - Link:',report.permalink,'\n',bcolors.ENDC
            print bcolors.BOLD,' [+] Results:\n',bcolors.ENDC
            print bcolors.OKGREEN,' [+] Resource Status:',report.status,bcolors.ENDC
            print bcolors.OKGREEN,' [+] Antivirus Total:',report.total,bcolors.ENDC
            print bcolors.OKGREEN,' [+] Antivirus Positives:',report.positives,'\n',bcolors.ENDC
            for antivirus, malware in report:
                if malware is not None:
                    print bcolors.OKGREEN,'[+]Antivirus:',antivirus[0],bcolors.ENDC
                    print bcolors.OKGREEN,'Antivirus Version:',antivirus[1],bcolors.ENDC
                    print bcolors.OKGREEN,'Antivirus Update:',antivirus[2],bcolors.ENDC
                    print bcolors.OKGREEN,'Malware:',malware,bcolors.ENDC
                    exit(0)
    except Exception as e:
           print bcolors.FAIL,'\n[!] Error: There was an issue hashing remotely...\n',e,bcolors.ENDC
           exit(0)

############################################################################################
# Main:
############################################################################################

def main():
    print bcolors.OKGREEN,'\n  /######   /######  /#######   /######  /##    /########',bcolors.ENDC
    print bcolors.OKGREEN,' /##__  ## /##__  ##| ##__  ## /##__  ##| ##   |__  ##__/',bcolors.ENDC
    print bcolors.OKGREEN,'| ##  \__/| ##  \ ##| ##  \ ##| ##  \ ##| ##      | ##',bcolors.ENDC
    print bcolors.OKGREEN,'| ##      | ##  | ##| ####### | ########| ##      | ##',bcolors.ENDC
    print bcolors.OKGREEN,'| ##      | ##  | ##| ##__  ##| ##__  ##| ##      | ##',bcolors.ENDC
    print bcolors.OKGREEN,'| ##    ##| ##  | ##| ##  \ ##| ##  | ##| ##      | ##',bcolors.ENDC
    print bcolors.OKGREEN,'|  ######/|  ######/| #######/| ##  | ##| ########| ##',bcolors.ENDC
    print bcolors.OKGREEN,' \______/  \______/ |_______/ |__/  |__/|________/|__/\n',bcolors.ENDC
    print bcolors.OKGREEN,'      /#######  /#######  /######## /##      /##',bcolors.ENDC
    print bcolors.OKGREEN,'     | ##__  ##| ##__  ##| ##_____/| ##  /# | ##',bcolors.ENDC
    print bcolors.OKGREEN,'     | ##  \ ##| ##  \ ##| ##      | ## /###| ##',bcolors.ENDC
    print bcolors.OKGREEN,'     | ####### | #######/| #####   | ##/## ## ##',bcolors.ENDC
    print bcolors.OKGREEN,'     | ##__  ##| ##__  ##| ##__/   | ####_  ####',bcolors.ENDC
    print bcolors.OKGREEN,'     | ##  \ ##| ##  \ ##| ##      | ###/ \  ###',bcolors.ENDC
    print bcolors.OKGREEN,'     | #######/| ##  | ##| ########| ##/   \  ##',bcolors.ENDC
    print bcolors.OKGREEN,'     |_______/ |__/  |__/|________/|__/     \__/\n',bcolors.ENDC
    print bcolors.OKBLUE,'   Link: https://www.github.com/xakepnz/COBALTBREW',bcolors.ENDC
    print bcolors.OKGREEN,'------------------------------------------------------',bcolors.ENDC

############################################################################################
# Start:
############################################################################################

if __name__ == "__main__":

    class bcolors:
        OKBLUE = '\033[94m'
        OKGREEN = '\033[92m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'

    main()

############################################################################################
# Argument Function:
############################################################################################

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='Specify a file name, and get its hash.', required=False)
    parser.add_argument('-r', '--remote', help='Specify a URL to download a file, and get its hash.', required=False)
    parser.add_argument('-c', '--check', help='Check to see if hash exists on VirusTotal.', required=False, action='store_true')
    args = parser.parse_args()
    url = args.remote
    localfile = args.file
    check = args.check

############################################################################################
# Error checking:
############################################################################################

    if localfile is None and url is None:
        print bcolors.WARNING,'\n[?] Warning: Nothing to hash. Try -r (--remote) or -f (--file).',bcolors.ENDC
        print bcolors.OKGREEN,'[+] Example: ./cobaltbrew -r https://www.nsa.gov/s3cr3t.pdf',bcolors.ENDC
        print bcolors.OKGREEN,'[+] Example: ./cobaltbrew -l ~/Downloads/s3cr3t.pdf',bcolors.ENDC
        print bcolors.FAIL,'[!] Error: Nothing submitted...\n',bcolors.ENDC
        exit(0)

############################################################################################
# Check localfile, and get hashes:
############################################################################################

    if localfile is not None and check is True:
        print bcolors.OKGREEN,'\n[+] Virustotal Hash Check Enabled.\n',bcolors.ENDC
        if VIRUSTOTALKEY is '':
            print bcolors.FAIL,'[!] Error: You did not specify your Virus Total API Key in the source.',bcolors.ENDC
            print bcolors.FAIL,'[!] Exiting.\n',bcolors.ENDC
            exit (0)
        else:
            localfilescheck()

############################################################################################
# Just get localfile hashes:
############################################################################################

    if localfile is not None and check is False:
        localfiles()

############################################################################################
# Just get remote file hashes:
############################################################################################
    if url is not None and check is False:
        remotefiles()

############################################################################################
# Check remotefile, and get hashes:
############################################################################################

    if url is not None and check is True:
        print bcolors.OKGREEN,'[+] Virustotal Hash Check Enabled.\n',bcolors.ENDC
    if VIRUSTOTALKEY is '':
        print bcolors.FAIL,'[!] Error: You did not specify your Virus Total API Key in the source.',bcolors.ENDC
        print bcolors.FAIL,'[!] Exiting.\n',bcolors.ENDC
        exit (0)
    else:
        remotefilescheck()

