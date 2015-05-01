# A bunch of Fortigate scripts

## fgt-pubkey-upload.py

Tool that copies your publickey to FortiGate devices

### config.cfg

File with configuration of FortiGate devices.

1. Variables:
  * `device` - IP addess, if not set, default is: `192.168.1.99`
  * `user` - username, if not set, default is: `admin`
  * `pass` - password, if not set, default is blank

You can configure many devices with 1 simple command:

```
./fgt-pubkey-upload.py -c config.cfg
```

Sample file with configuration of two FortiGates:

```
[FortiGate1]
device: 192.168.111.105

[FortiGate2]
device: 192.168.111.106
user: wujtruj
pass: 123456
```

### Switches

You can invoke scipt using switches insted of config file:
* `-d` - IP address, if not set, default is: `192.168.1.99`
* `-u` - username, if not set, default is: `admin`
* `-p` - password, if not set, default is blank

## fgt-extended-utm-log.py

Enables UTM logging into separate section for:

1. Antivirus
2. Web Filter
3. Application Control
4. Spam Filter

### config.cfg

File with configuration of FortiGate devices.

1. Mandatory variables are:
  * `device` - IP address
  * `user` - username
  * `pass` - password
2. Optional variables are:
  * vdom - VDOM
  * `av` - antivirus
  * `wf` - web filter
  * `ac` - application control
  * `sf` - spam filter

Sample file with configuration of one devies with many VDOMs:

```
[Fortigate-VDOM-guests]
device: 192.168.111.105
vdom: guests
user: admin
pass: admin1

[Fortigate-VDOM-office]
device: 192.168.111.105
user: admin
pass: admin1
vdom: office
av: True
wf: True
ac: True
```

**Important:** if no security modules are selected in config file or using switches, script will enable logging for all of security modules.

### Switches

Switches are optional and they can overrite settings in config file. Avaiable switches:
* `-v` or `--vdom` - accepts argument, a VDOM name
* `-av` - enable extended logging for antivirus
* `-wf` - enable extended logging for web filter
* `-ac` - enable extended logging for application control
* `-sf` - enable extended logging for spam filter
