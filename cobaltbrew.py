#!/usr/bin/python

import argparse
import os
import sys
import hashlib

buffer = 65536
url = ""
file = ""
md5 = hashlib.md5()
sha1 = hashlib.sha1()
sha256 = hashlib.sha256()
sha512 = hashlib.sha512()
trash = 'tra.sh'
agent = 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'

parser = argparse.ArgumentParser()
parser.add_argument('-u', '--url', help='Specify a URL to download a file, and get its hash.', required=False)
parser.add_argument('-f', '--file', help='Specify a file name, and get its hash.', required=False)
args = parser.parse_args()
url = args.url
localfile = args.file

if localfile is None and url is None:
        print '[!] Nothing to hash. Try -h or --help?'
        print '[!] Exiting.'
        exit(0)

def localfiles():
    try:
        if os.path.isfile(localfile) is False:
           print '[?] Does: ' + file + ' Exist? Try the full path. (/Im/noob/tra.sh)'
           print '[!] Exiting.'
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

        print ''
        print 'Hash Results:'
        print ''
        print (' File:    ' + localfile)
        print (' MD5:    {0}'.format(md5.hexdigest()))
        print (' SHA1:   {0}'.format(sha1.hexdigest()))
        print (' SHA256: {0}'.format(sha256.hexdigest()))
        print (' SHA512: {0}'.format(sha512.hexdigest()))
        print ''

    except Exception as e:
        print '[!] There was a weird error.',e

def remotefiles():
    try:
        print ''
        print '[+] Firing Canons...'
        print '[+] Downloading: ' + url
        if sys.platform == 'darwin':
                remotefile = os.system('curl ' + url + ' -o ' + trash ' -A ' + agent + ' -f' + ' -k' + ' -s')
        if sys.platform == 'linux' or 'linux32':
                remotefile = os.system('wget ' + ' -q' + ' -c' + ' -U ' + url + ' --no-check-certificate' + ' -O ' + trash)
        if sys.platform = 'win32':
                print '[!] Error. This feature does not work on Windows platforms yet.'
                exit (0)
        print '[+] Temporarily saved as: ' + trash

    except Exception as e:
           print '[!] Something failed.',e
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
        
        print ''
        print 'Hash Results:'
        print ''
        print (' URL:    ' + localfile)
        print (' MD5:    {0}'.format(md5.hexdigest()))
        print (' SHA1:   {0}'.format(sha1.hexdigest()))
        print (' SHA256: {0}'.format(sha256.hexdigest()))
        print (' SHA512: {0}'.format(sha512.hexdigest()))
        print ''

    except Exception as e:
           print '[!] There was an issue hashing remotely...',e
           exit(0)

if args.file is not None:
        localfiles()

if args.url is not None:
        remotefiles()
