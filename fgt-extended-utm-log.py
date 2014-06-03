#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import paramiko
import time

HOST = '192.168.178.50'
USER = 'admin'
PASS = 'admin1'
sleepTime = 0.2
recvSize = 1024 # max nr of bytes to read

def connect(host, user, passw):
    # Connect to FGT device.
    global ssh
    global chan

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=user, password=passw)
    chan = ssh.invoke_shell()

def disconnect():
    # Disconnect from FGT device
    chan.close()
    ssh.close()

def exeCommand(command):
    # Execute command on FGT device.
    chan.send('%s\n' % command)
    time.sleep(sleepTime)
    resp = chan.recv(recvSize)
    return resp

def getAvProfiles():
    # Get list of AV profiles.
    exeCommand('conf antivirus profile')
    avTemp = exeCommand('get | grep name:').splitlines()
    avTemp = [ x for x in avTemp if "name: " in x ]

    avList = []
    for i in range(len(avTemp)):
        avList.extend(avTemp[i].split(':'))

    avList = [ x for x in avList if "name" not in x ]

    for i in range(len(avList)):
        avList[i] = avList[i].strip()

    exeCommand('end')
    return avList

def enAvUTMlog(avList):
    # Enable Security Log for AV.
    print ('====Antivirus====')
    for i in range(len(avList)):
        exeCommand('conf antivirus profile')
        exeCommand('edit %s' % avList[i])
        resp = exeCommand('get | grep extended-utm-log')
        if "enable" not in resp:
            exeCommand('set extended-utm-log enable')
            exeCommand('set av-virus-log enable')
            exeCommand('set av-block-log enable')
            exeCommand('end')
            print ('  * %s - enabled security log' % avList[i])
        else:
            exeCommand('end')
            print ('  * %s - security log was already enabled' % avList[i])

def main():
    # Main function of this program.

    connect(HOST, USER, PASS)
    avList = getAvProfiles()
    enAvUTMlog(avList)
    disconnect()

if __name__ == "__main__":
    main()
