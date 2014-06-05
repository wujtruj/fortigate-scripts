#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import paramiko
import time

HOST = '192.168.111.104'
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

def checkVDOMs():
    resp = exeCommand('conf vdom')
    if "Command fail" in resp:
        enabled = 0
    else:
        enabled = 1
    return enabled

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

def getWfProfiles():
    # Get list of WF profiles.
    exeCommand('conf webfilter profile')
    wfTemp = exeCommand('get | grep name:').splitlines()
    wfTemp = [ x for x in wfTemp if "name: " in x ]

    wfList = []
    for i in range(len(wfTemp)):
        wfList.extend(wfTemp[i].split(':'))

    wfList = [ x for x in wfList if "name" not in x ]

    for i in range(len(wfList)):
        wfList[i] = wfList[i].strip()

    exeCommand('end')
    return wfList
    
def enWfUTMlog(wfList):
    # Enable Security Log for WF.
    print ('====Web Filter====')
    for i in range(len(wfList)):
        exeCommand('conf webfilter profile')
        exeCommand('edit %s' % wfList[i])
        resp = exeCommand('get | grep extended-utm-log')
        if "enable" not in resp:
            resp = exeCommand('get | grep inspection-mode')
            exeCommand('set extended-utm-log enable')
            exeCommand('set web-url-log enable')
            if "dns" not in resp:
                exeCommand('set web-content-log enable')
                exeCommand('set web-filter-activex-log enable')
                exeCommand('set web-filter-command-block-log enable')
                exeCommand('set web-filter-cookie-log enable')
                exeCommand('set web-filter-applet-log enable')
                exeCommand('set web-filter-jscript-log enable')
                exeCommand('set web-filter-js-log enable')
                exeCommand('set web-filter-vbs-log enable')
                exeCommand('set web-filter-unknown-log enable')
                exeCommand('set web-filter-referer-log enable')
                exeCommand('set web-filter-cookie-removal-log enable')
                exeCommand('set web-invalid-domain-log enable')
                exeCommand('set web-ftgd-err-log enable')
                exeCommand('set web-ftgd-quota-usage enable')
            exeCommand('end')
            print ('  * %s - enabled security log' % wfList[i])
        else:
            exeCommand('end')
            print ('  * %s - security log was already enabled' % wfList[i])

def getAcProfiles():
    # Get list of AC profiles.
    exeCommand('conf application list')
    acTemp = exeCommand('get | grep name:').splitlines()
    acTemp = [ x for x in acTemp if "name: " in x ]

    acList = []
    for i in range(len(acTemp)):
        acList.extend(acTemp[i].split(':'))

    acList = [ x for x in acList if "name" not in x ]

    for i in range(len(acList)):
        acList[i] = acList[i].strip()

    exeCommand('end')
    return acList

def enAcUTMlog(acList):
    # Enable Security Log for AC.
    print ('====Application Control====')
    for i in range(len(acList)):
        exeCommand('conf application list')
        exeCommand('edit %s' % acList[i])
        resp = exeCommand('get | grep extended-utm-log')
        if "enable" not in resp:
            exeCommand('set extended-utm-log enable')
            exeCommand('set log enable')
            exeCommand('set other-application-log enable')
            # exeCommand('set unknown-application-log enable') # it generates huge amount of logs
            exeCommand('end')
            print ('  * %s - enabled security log' % acList[i])
        else:
            exeCommand('end')
            print ('  * %s - security log was already enabled' % acList[i])

def getSfProfiles():
    # Get list of SF profiles.
    exeCommand('conf spamfilter profile')
    sfTemp = exeCommand('get | grep name:').splitlines()
    sfTemp = [ x for x in sfTemp if "name: " in x ]

    sfList = []
    for i in range(len(sfTemp)):
        sfList.extend(sfTemp[i].split(':'))

    sfList = [ x for x in sfList if "name" not in x ]

    for i in range(len(sfList)):
        sfList[i] = sfList[i].strip()

    exeCommand('end')
    return sfList

def enSfUTMlog(sfList):
    # Enable Security Log for SF.
    print ('====SPAM Filter====')
    for i in range(len(sfList)):
        exeCommand('conf spamfilter profile')
        exeCommand('edit %s' % sfList[i])
        resp = exeCommand('get | grep extended-utm-log')
        if "enable" not in resp:
            exeCommand('set extended-utm-log enable')
            exeCommand('set spam-log enable')
            resp = exeCommand('get | grep spam-filtering')
            if "enable" in resp:
                protocol = ['imap', 'pop3', 'smtp', 'mapi', 'msn-hotmail', 'yahoo-mail', 'gmail']
                for j in range(len(protocol)):
                    exeCommand('config %s' % protocol[j])
                    exeCommand('set log enable')
                    exeCommand('end')
            exeCommand('end')
            print ('  * %s - enabled security log' % sfList[i])
        else:
            exeCommand('end')
            print ('  * %s - security log was already enabled' % sfList[i])

def main():
    # Main function of this program.

    connect(HOST, USER, PASS)
    if checkVDOMs() == 0:
        avList = getAvProfiles()
        enAvUTMlog(avList)
        wfList = getWfProfiles()
        enWfUTMlog(wfList)
        acList = getAcProfiles()
        enAcUTMlog(acList)
        sfList = getSfProfiles()
        enSfUTMlog(sfList)
    else:
        print("Sorry, I don't know which VDOM to edit.")
    disconnect()

if __name__ == "__main__":
    main()
