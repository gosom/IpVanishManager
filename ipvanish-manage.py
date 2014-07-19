#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import logging
import subprocess
import urllib2
import re
import time
import glob
import os
import os.path
import random
import socket

"""
Inspired from https://code.google.com/p/hma-manager/

Starts a vpn connection and periodically checks that it is up.

In the next version it will block all traffic except the one to the
vpn server with iptables. This will make sure that we do not have
any leaks without VPN.

"""

log = logging.getLogger('ipvanish-manager')


class CannotGetIpException(Exception):
    pass


class CannotFindOvpnException(Exception):
    pass


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True,
                        help='The folder containing the configuration files',)
    parser.add_argument('--auth-user-pass', dest='auth_user_pass',
                        required=True, help='Filename containing the username'\
                        ' and password for the ip vanish vpn provider'\
                        '(first line username & second line password')
    parser.add_argument('--ca', required=True, help='Certificate file DEFAULT ')
    parser.add_argument('--country', required=False,
                        help='Picks a random server from the specified'\
                        ' country selected. If not specified just selects'\
                        ' a random server')
    parser.add_argument('-l', '--logfile', default='/var/log/ip-vanish.log',
                        help='Logfile Default /var/log/ip-vanish.log')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='Use for more verbose output')
    parser.add_argument('-p', '--persist', default=False,
                        help='If the script stops it starts it again DEFAULT False')
    return parser.parse_args()


def get_external_ip():
    """
    :returns current external ip using:http://www.ipvanish.com/checkIP.php
    :raises CannotGetIpException
    """
    service_url = 'http://www.ipvanish.com/checkIP.php'
    start_time = time.time()
    ip_pattern = re.compile('(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', re.U)
    external_ip = None
    while True:
        try:
            sock = urllib2.urlopen(service_url)
            content = sock.read().decode('ISO-8859-1')
            m = ip_pattern.search(content)
            external_ip = m.group(0)
        except Exception:
            log.exception('Exception fetching ip')
            if time.time() - start_time > 30:
                raise CannotGetIpException('Cannot fetch ip on time!')
            time.sleep(2)
        else:
            break

    if not external_ip:
        raise CannotGetIpException('External ip could not be fetched')
    return external_ip


def get_ovpn_conf(config_path, country=None):
    """Returns a random ovpnd conf file and the remote ip of the vpn server
    :config_path (str): The path the ovpn files line
    :country (str): 2 letter country code DEFAULT None
    :returns (str): a random file that matches the criteria
    :raises : CannotFindOvpnException"""
    if country:
        pathname = os.path.join(config_path, 'ipvanish-%s*.ovpn' % country.upper())
    else:
        pathname = os.path.join(config_path, 'ipvanish-*.ovpn')

    candidates = glob.glob(pathname)

    if not candidates:
        raise CannotFindOvpnException('Cannot find file matching %s', pathname)

    fname = random.choice(candidates)
    host = None
    with open(fname) as f:
        for l in f:
            if l.startswith('remote'):
                _, host, port = l.split(' ')
                port = int(port)
                o = socket.getaddrinfo(host, port)
                if not o:
                    raise CannotFindOvpnException('Cannot get ip from host')
                ip = o[0][4][0]
                return fname, ip

    raise CannotFindOvpnException('Cannot get ip from file')


def restart_program():
    """Restarts the current program.
    Note: this function does not return. Any cleanup action (like
    saving data) must be done before calling this function."""

    python = sys.executable
    os.execl(python, python, * sys.argv)


def vpn_running(openvpn_cmd, my_ip, duration):
    '''Runs open vpn in a loop until an error or stop contition occurs

    :openvpn_cmd: opnevpn cmd
    :my_ip: ISP IP address
    :duration: Length of time (seconds) to run before switching to new server

    :my_ip: string
    :cur_version: string
    :duration: integer

    Lreturn: Returns the start and end times as well as vpn IP address
             and disconnect reason
    '''
    prog = subprocess.Popen(openvpn_cmd, stdout=subprocess.PIPE)

    start = time.time()
    while prog.poll() == None:
        log.debug('Polling OpenVPN')
        time.sleep(30)

        # restart if unable to verify IP
        try:
            vpn_ip = get_external_ip()
        except CannotGetIpException:
            err = 'Unable to get external ip'
            end = time.time()
            prog.kill()
            break

        # Restart if IP address is not hidden
        if vpn_ip == my_ip:
            log.critical('vpn ip == my_ip (%s)', vpn_ip)
            err = 'VPN Not Connected'
            end = time.time()
            prog.kill()
            break

        # Stop service if time limit hit
        elif time.time() - start > duration:
            log.warning('Time limit hit, selecting new server.')
            end = time.time()
            err = 'Server Switch'
            prog.kill()
            break
        else:
            err = 'OpenVPN Terminated'
            end = time.time()

        time.sleep(200)

    log.error(err)
    return start, end, vpn_ip, err


def main():
    """
    1. Starts the openvpn client
    2. Create iptables rules to disallow traffic that goes not through vpn
    3. Monitors the connection and restarts if needed
    """
    args = parse_args()
    log.info('Starting ipvanish-manager')
    # first kill openvpn if it runs
    p = subprocess.Popen(['killall', 'openvpn'], stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
    out, err = p.communicate()
    if p.returncode == 0:
        log.debug('Killed running openvpn process')
    else:
        log.debug(err.strip())

    try:
        isp_ip = get_external_ip()
    except CannotGetIpException:
        log.exception(str(e))
        raise

    log.info('Isp ip is: %s', isp_ip)

    try:
        fname, host = get_ovpn_conf(config_path=args.config,
                                    country=args.country)
    except Exception as e:
        log.exception(str(e))

    log.info('Ovpn: %s Remote Ip: %s', fname, host)

    # Runs openvpn and returns info if it stops running
    # Selects a new random server every 2 days
    openvpn_cmd = ['openvpn', '--config', fname, '--auth-user-pass',
                   args.auth_user_pass, '--ca', args.ca]
    log.debug('command:\n%s', ' '.join(openvpn_cmd))
    start, end, vpn_ip, err = vpn_running(openvpn_cmd, isp_ip, 86400)

    # never returns
    if args.persist:
        restat_program()

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
