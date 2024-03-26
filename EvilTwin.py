from __future__ import print_function
from __future__ import absolute_import
from builtins import input
from builtins import range
from scapy.all import *
import os
import socket
import netifaces
import shutil
import psutil
import subprocess
import logging
import json
import sys
import time

wlan='wlp4s0'
ip='input your IP'
netmask='255.255.255.0'
inet='input spoof IP'
hostapd_config_path = '/etc/accesspoint/hostapd.conf'
def _execute_shell(command_string):
    p = subprocess.Popen(command_string, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

    if p.returncode != 0:
        logging.error("Command failed: %s", command_string)
        logging.error("Stdout: %s", stdout.decode())
        logging.error("Stderr: %s", stderr.decode())
    else:
        logging.debug("Command succeeded: %s", command_string)
        logging.debug("Stdout: %s", stdout.decode())

    return stdout.decode()
def _start_router():
        _pre_start()
        #ssid=input("what SSID?")
        s = 'ifconfig ' + wlan + ' up ' + ip + ' netmask ' + netmask
        logging.debug('created interface: mon.' + wlan + ' on IP: ' + ip)
        r = _execute_shell(s)
        logging.debug(r)
        print('sleeping for 2 seconds.')
        logging.debug('wait..')
        _execute_shell('sleep 2')
        i = ip.rindex('.')
        ipparts = ip[0:i]

        # enable forwarding in sysctl.
        logging.debug('enabling forward in sysctl.')
        r = _execute_shell('sysctl -w net.ipv4.ip_forward=1')
        logging.debug(r.strip())

        if inet is not None:
            # enable forwarding in iptables.
            logging.debug('creating NAT using iptables: {} <-> {}'.format(wlan, inet))
            _execute_shell('iptables -P FORWARD ACCEPT')

            # add iptables rules to create the NAT.
            _execute_shell('iptables --table nat --delete-chain')
            _execute_shell('iptables --table nat -F')
            r = _execute_shell('iptables --table nat -X')
            if len(r.strip()) > 0:
                logging.debug(r.strip())
            _execute_shell('iptables -t nat -A POSTROUTING -o {} -j MASQUERADE'.format(inet))
            _execute_shell(
                'iptables -A FORWARD -i {} -o {} -j ACCEPT -m state --state RELATED,ESTABLISHED'
                    .format(inet, wlan))
            _execute_shell('iptables -A FORWARD -i {} -o {} -j ACCEPT'.format(wlan, inet))

        # allow traffic to/from wlan
        _execute_shell('iptables -A OUTPUT --out-interface {} -j ACCEPT'.format(wlan))
        _execute_shell('iptables -A INPUT --in-interface {} -j ACCEPT'.format(wlan))

        # start dnsmasq
        s = 'dnsmasq --dhcp-authoritative --interface={} --dhcp-range={}.20,{}.100,{},4h'\
            .format(wlan, ipparts, ipparts, netmask)

        logging.debug('running dnsmasq')
        logging.debug(s)
        r = _execute_shell(s)
        logging.debug(r)

        # ~ f = open(os.getcwd() + '/hostapd.tem','r')
        # ~ lout=[]
        # ~ for line in f.readlines():
        # ~ lout.append(line.replace('<SSID>',SSID).replace('<PASS>',password))
        # ~
        # ~ f.close()
        # ~ f = open(os.getcwd() + '/hostapd.conf','w')
        # ~ f.writelines(lout)
        # ~ f.close()

        # writelog('created: ' + os.getcwd() + '/hostapd.conf')
        # start hostapd
        # s = 'hostapd -B ' + os.path.abspath('run.conf')
        s = 'hostapd -B {}'.format(hostapd_config_path)
        logging.debug(s)
        logging.debug('running hostapd')
        # print('sleeping for 2 seconds.')
        logging.debug('wait..')
        _execute_shell('sleep 2')
        r = _execute_shell(s)
        logging.debug(r)
        logging.debug('hotspot is running.')
        return True
def _pre_start():
    try:
        _execute_shell('killall wpa_supplicant')

        result = _execute_shell('nmcli radio wifi off')
        if "error" in result.lower():
            _execute_shell('nmcli nm wifi off')
        _execute_shell('rfkill unblock wlan')
        _execute_shell('sleep 1')
    except:
        pass
def _stop_router():
        # bring down the interface
        _execute_shell('ifconfig mon.' + wlan + ' down')

        # stop hostapd
        logging.debug('stopping hostapd')
        _execute_shell('pkill hostapd')

        # stop dnsmasq
        logging.debug('stopping dnsmasq')
        _execute_shell('killall dnsmasq')

        # disable forwarding in iptables.
        logging.debug('disabling forward rules in iptables.')
        _execute_shell('iptables -P FORWARD DROP')

        # delete iptables rules that were added for wlan traffic.
        if wlan != None:
            _execute_shell('iptables -D OUTPUT --out-interface {} -j ACCEPT'.format(wlan))
            _execute_shell('iptables -D INPUT --in-interface {} -j ACCEPT'.format(wlan))
        _execute_shell('iptables --table nat --delete-chain')
        _execute_shell('iptables --table nat -F')
        _execute_shell('iptables --table nat -X')

        # disable forwarding in sysctl.
        logging.debug('disabling forward in sysctl.')
        r = _execute_shell('sysctl -w net.ipv4.ip_forward=0')
        logging.debug(r.strip())
        # execute_shell('ifconfig ' + wlan + ' down'  + IP + ' netmask ' + Netmask)
        # execute_shell('ip addr flush ' + wlan)
        logging.debug('hotspot has stopped.')
        return True
def keep_running():
    while True:
        try:
            
            # Here, implement logic to check if the AP is running
            # For simplicity, we're just calling _start_router()
            # But ideally, you should check if the AP is running and only call _start_router() if it's not.
            _start_router()
            time.sleep(1000)  # Check every 100 seconds
        except KeyboardInterrupt:
            logging.info("Stopping the access point.")
            _stop_router()
            break
def send_beacon(bssid):
    # Construct a beacon frame with the specified BSSID
    beacon = RadioTap() / Dot11(type=0, subtype=8, addr1="b4:19:74:b0:44:67", addr2=bssid, addr3=bssid) / Dot11Beacon(cap='ESS') / Dot11Elt(ID='SSID', info='SpoofedNetwork') / Dot11Elt(ID='Rates', info='\x82\x84\x0b\x16') / Dot11Elt(ID='DSset', info='\x03')

    # Send the beacon frame
    sendp(beacon, iface="wlp4s0mon", verbose=1)

# Replace "00:11:22:33:44:55" with the desired BSSID


# Send beacon frames periodically to advertise the spoofed access point


if __name__ == "__main__":
    while True:
        spoofed_bssid = "9a:9d:5d:dc:39:1a"
        time.sleep(0.1)  # Adjust the interval as needed
        logging.basicConfig(level=logging.DEBUG)
        keep_running() and send_beacon(spoofed_bssid)
