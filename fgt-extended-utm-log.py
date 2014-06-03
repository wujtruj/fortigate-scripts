#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import paramiko
import time

HOST = '192.168.178.50'
USER = 'admin'
PASS = 'admin1'
sleepTime = 0.2
recvSize = 1024 # max nr of bytes to read

#=====================================Connection
#===============================================
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, port=22, username=USER, password=PASS)
chan = ssh.invoke_shell()

#========================Get list of AV profiles
#===============================================
chan.send('conf antivirus profile\n')
time.sleep(sleepTime)
resp = chan.recv(recvSize)
chan.send('get | grep name:\n')
time.sleep(sleepTime)
resp = chan.recv(recvSize)
avTemp = resp.splitlines()
avTemp = [ x for x in avTemp if "name: " in x ]

avList = []
for i in range(len(avTemp)):
    avList.extend(avTemp[i].split(':'))

avList = [ x for x in avList if "name" not in x ]

for i in range(len(avList)):
    avList[i] = avList[i].strip()

chan.send('end\n')
time.sleep(sleepTime)
resp = chan.recv(recvSize)

#=====================Enable Security Log for AV
#===============================================
for i in range(len(avList)):
    chan.send('conf antivirus profile\n')
    time.sleep(sleepTime)
    resp = chan.recv(recvSize)
    chan.send('edit %s\n' % avList[i])
    time.sleep(sleepTime)
    resp = chan.recv(recvSize)
    chan.send('get | grep extended-utm-log\n')
    time.sleep(sleepTime)
    resp = chan.recv(recvSize)
    if "enable" not in resp:
        chan.send('set extended-utm-log enable\n')
        time.sleep(sleepTime)
        chan.send('set av-virus-log enable\n')
        time.sleep(sleepTime)
        chan.send('set av-block-log enable\n')
        time.sleep(sleepTime)
        chan.send('end\n')
        time.sleep(sleepTime)
        print ('%s - enabled security log' % avList[i])
    else:
        chan.send('end\n')
        time.sleep(sleepTime)
        print ('%s - security log was already enabled' % avList[i])

chan.close()
ssh.close()
