#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import paramiko
import argparse
from ConfigParser import SafeConfigParser
import time
import getpass

sleepTime = 0.2
recvSize = 1024 # max nr of bytes to read

def parseArgs():
    # Parse arguments and display help
    parser = argparse.ArgumentParser(description='Tool that copies You publickey to FortiGate devices')
    # parser.add_argument('-d', help='IP address of configured device', action="store_const", const="192.168.1.99")
    # parser.add_argument('-u', help='username', action='store_const', const="admin")
    # parser.add_argument('-p', help='password', action='store')
    # parser.add_argument('-c', help='config file', action='store')
    parser.add_argument('-d', help='IP address of configured device', default="192.168.1.99")
    parser.add_argument('-u', help='username', default="admin")
    parser.add_argument('-p', help='password', default="")
    parser.add_argument('-c', help='config file')
    args = parser.parse_args()
    return args

def configParser(parser, args, location):
    if parser.has_option(location, 'device'):
        device = parser.get(location, 'device')
    else:
        device = "192.168.1.99"
    if parser.has_option(location, 'user'):
        user = parser.get(location, 'user')
    else:
        user = "admin"
    if parser.has_option(location, 'pass'):
        password = parser.get(location, 'pass')
    else:
        password = ""
    return (device, user, password)

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

def checkVDOMs():
    # Check if VDOMs are enabled
    vdoms = 0
    resp = exeCommand('conf global')
    if "Command fail" not in resp:
        vdoms = 1
    return vdoms

def checkSSHkeys(user):
    # Check if script can upload new SSH public key
    keyNr = 0
    exeCommand('config system admin')
    exeCommand('edit %s' % user)
    resp = exeCommand('show full-configuration | grep ssh-public-key')
    if "unset ssh-public-key1" in resp:
        keyNr = 1
    elif "unset ssh-public-key2" in resp:
        keyNr = 2
    elif "unset ssh-public-key3" in resp:
        keyNr = 3
    return keyNr

def uploadKey(keyNr, user):
    username = getpass.getuser()
    try:
        f = open('/home/%s/.ssh/id_rsa.pub' % username, 'r')
        pubKey = f.readline()
        f.close()
    except:
        print('Could not open file /home/%s/.ssh/id_rsa.pub' % username)
    newKey = str('set ssh-public-key%s "%s"' % (keyNr, pubKey))
    newKey = newKey.replace('\n', '')
    resp = exeCommand(newKey)
    if "Key value already exist" in resp:
        print("Sorry, Your key is already added to admin account: %s" % user)


def main():
    # Main function of this program.
    args = parseArgs()
    if args.c:
        parser = SafeConfigParser()
        parser.read('%s' % args.c)
        for location in parser.sections():
            device, user, password = configParser(parser, args, location)
            print("===DEVICE: %s===" % location)
            connect(device, user, password)
            checkVDOMs()
            keyNr = checkSSHkeys(user)
            if keyNr == 0:
                print("Sorry, there isn't any free key slot, I can't overwrite existing key")
            else:
                uploadKey(keyNr, user)
    else:
        device = args.d
        user = args.u
        password = args.p
        connect(device, user, password)
        checkVDOMs()
        keyNr = checkSSHkeys(user)
        if keyNr == 0:
            print("Sorry, there isn't any free key slot, I can't overwrite existing key")
        else:
            uploadKey(keyNr, user)
    disconnect()

if __name__ == "__main__":
    main()
