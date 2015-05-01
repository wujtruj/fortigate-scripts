#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import paramiko
import argparse
from ConfigParser import SafeConfigParser
import time

sleepTime = 0.2
recvSize = 1024 # max nr of bytes to read

def parseArgs():
    # Parse arguments and display help
    parser = argparse.ArgumentParser(description='Tool that enables extended UTM logging on FortiGate devices')
    parser.add_argument('-v', '--vdom', help='select VDOM')
    parser.add_argument('-av', help='enable extended UTM logging for antivirus module', action='store_true')
    parser.add_argument('-wf', help='enable extended UTM logging for web filter module', action='store_true')
    parser.add_argument('-ac', help='enable extended UTM logging for application control module', action='store_true')
    parser.add_argument('-sf', help='enable extended UTM logging for spam filter module', action='store_true')
    args = parser.parse_args()
    return args

def configParser(parser, args, location):
    vdom = None
    av = None
    wf = None
    ac = None
    sf = None
    DEVICE = parser.get(location, 'device')
    USER = parser.get(location, 'user')
    PASS = parser.get(location, 'pass')
    if parser.has_option(location, 'vdom'):
        vdom = parser.get(location, 'vdom')
    if args.vdom:
        vdom = args.vdom
    if parser.has_option(location, 'av'):
        av = parser.get(location, 'av')
    if args.av:
        av = args.av
    if parser.has_option(location, 'wf'):
        wf = parser.get(location, 'wf')
    if args.wf:
        wf = args.wf
    if parser.has_option(location, 'ac'):
        ac = parser.get(location, 'ac')
    if args.ac:
        ac = args.ac
    if parser.has_option(location, 'sf'):
        sf = parser.get(location, 'sf')
    if args.sf:
        sf = args.sf
    return (DEVICE, USER, PASS, vdom, av, wf, ac, sf)

def connect(device, user, passw):
    # Connect to FGT device.
    global ssh
    global chan

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(device, username=user, password=passw)
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

def checkVDOMs(vdom):
    # Check if VDOMs are enabled and if script can edit selected VDOM
    stop = 0
    resp = exeCommand('conf vdom')
    if "Command fail" not in resp:
        if vdom:
            resp = exeCommand('edit %s' % vdom)
            if "Command fail" in resp:
                print("Could not edit or create VDOM %s." % vdom)
                stop = 1
        else:
            print("Sorry, VDOMs are enabled on this device. You have to choose one.")
            stop = 1
    return stop

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
    print ('---Antivirus---')
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
    print ('---Web Filter---')
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
    print ('---Application Control---')
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
    print ('---SPAM Filter---')
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
    args = parseArgs()
    parser = SafeConfigParser()
    parser.read('config.cfg')
    for location in parser.sections():
        DEVICE, USER, PASS, vdom, av, wf, ac, sf = configParser(parser, args, location)
        print("===DEVICE: %s===" % location)
        connect(DEVICE, USER, PASS)
        stop = checkVDOMs(vdom)
        if not stop == 1:
            if not (av or wf or ac or sf):
                avList = getAvProfiles()
                enAvUTMlog(avList)
                wfList = getWfProfiles()
                enWfUTMlog(wfList)
                acList = getAcProfiles()
                enAcUTMlog(acList)
                sfList = getSfProfiles()
                enSfUTMlog(sfList)
            else:
                if av:
                    avList = getAvProfiles()
                    enAvUTMlog(avList)
                if wf:
                    wfList = getWfProfiles()
                    enWfUTMlog(wfList)
                if ac:
                    acList = getAcProfiles()
                    enAcUTMlog(acList)
                if sf:
                    sfList = getSfProfiles()
                    enSfUTMlog(sfList)
        disconnect()

if __name__ == "__main__":
    main()
