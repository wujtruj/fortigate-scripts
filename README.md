# A bunch of Fortigate scripts

## fgt-extended-utm-log.py

Enables UTM logging into separate section for:

1. Antivirus
2. Web Filter
3. Application Control
4. Spam Filter

## config.cfg

File with configuration of FortiGate devices.

1. Mandatory variables are:
  * `host` - IP address
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
host: 192.168.111.105
vdom: guests
user: admin
pass: admin1

[Fortigate-VDOM-office]
host: 192.168.111.105
user: admin
pass: admin1
vdom: office
av: True
wf: True
ac: True
```

**Important:** if no security modules are selected in config file or using switches, script will enable logging for all of security modules.

## Switches

Switches are optional and they can overrite settings in config file. Avaiable switches:
* `-v` or `--vdom` - accepts argument, a VDOM name
* `-av` - enable extended logging for antivirus
* `-wf` - enable extended logging for web filter
* `-ac` - enable extended logging for application control
* `-sf` - enable extended logging for spam filter
