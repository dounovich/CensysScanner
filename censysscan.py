#!/usr/bin/env python
# -*- coding: utf-8 -*-

from termcolor import colored
import argparse
import json
import requests
import locale
import sys


API_URL = "https://www.censys.io/api/v1"
UID = "check your own"
SECRET = "check your own"


def main():
    parser = argparse.ArgumentParser(description='Censys.io Search')
    parser.add_argument('-c', '--city', help='Add location.city')
    parser.add_argument('-C', '--country', help='Add location.country')
    parser.add_argument('-d', '--domain', help='Search in website')
    parser.add_argument('-s', '--search', help='Globale search')
    args = parser.parse_args()
    arg = ""

    if args.city:
        arg += args.city + " "
    if args.country:
        arg += args.country + " "
    if args.domain:
        arg += args.domain + " "
    if args.search:
        arg += args.search + " "

    search(arg)


def search(arg):
    pages = float('inf')
    page = 1
    while page <= pages:
        params = {'query': arg,
                  'page': page,
                  'fields': ["ip", "protocols"]
        }
        response = requests.post(API_URL + "/search/ipv4", json=params, auth=(UID, SECRET))
        payload = response.json()
        for element in payload['results']:
            ip = element["ip"]
            proto = element["protocols"]
            details(ip, proto)

        pages = payload['metadata']['pages']
        page += 1


def details(ip, proto):
    print '[%s] IP: %s' % (colored('*', 'red'), ip)
    response = requests.get(API_URL + ("/view/ipv4/%s" % ip), auth=(UID, SECRET))
    payload = response.json()

    if '80/http' in proto:
        print '   [+] Port 80 ouvert !'
        http(payload)

    if '443/https' in proto:
        print '   [+] port 443 ouvert !'
        heartbleed(payload)
        poodle(payload)
        certificat(payload)

    if '21/ftp' in proto:
        print '   [+] port 21 ouvert !'
        ftp(payload)

    if '22/ssh' in proto:
        print '   [+] port 22 ouvert !'
        ssh(payload)

    if '53/dns' in proto:
        print '   [+] port 53 ouvert !'
        #dns(payload)


def http(payload):
    try:
        if 'title' in payload['80']['http']['get'].keys():
            print "      [-] Title: %s" % payload['80']['http']['get']['title']
        if 'server' in payload['80']['http']['get']['headers'].keys():
            print "      [-] Type: %s" % payload['80']['http']['get']['headers']['server']
    except:
        pass


def heartbleed(payload):
    try:
        if 'heartbleed' in payload['443']['https'].keys():
            if payload['443']['https']['heartbleed']['heartbleed_vulnerable'] == True:
                print '      [-] Heartbleed: %s ' % colored('Vulnerable', 'red')
            else:
                print '      [-] Heartbleed: %s' % colored('not Vulnerable', 'green')
    except:
        pass

def poodle(payload):
    try:
        if 'ssl_3' in payload['443']['https']:
            if payload['443']['https']['ssl_3']['support'] == True:
                print '      [-] Poodle: %s ' % colored('Vulnerable', 'red')
        else:
            if 'tls' in payload['443']['https']:
                print '      [-] Poodle: %s ' % colored('not Vulnerable', 'green')

    except:
        pass
def certificat(payload):
    try:
        if 'tls' in payload['443']['https'].keys():
            end_cert = payload['443']['https']['tls']['certificate']['parsed']['validity']['end']
            print '      [-] End validity certificate: %s' % end_cert[:10]
            print '      [-] Cypher: %s ' %  payload['443']['https']['tls']['cipher_suite']['name']	
    except:
        pass

def ftp(payload):
    try:
        print '      [-] Banner: %s' % payload['21']['ftp']['banner']['banner']
        print '      [-] Description: %s' % payload['21']['ftp']['banner']['metadata']['description']
    except:
        pass


def ssh(payload):
    try:
        if 'raw_banner' in payload['22']['ssh']['banner'].keys():
            print '      [-] Banner: %s' % payload['22']['ssh']['banner']['raw_banner']
        if 'software_version' in payload['22']['ssh']['banner'].keys():
            print '      [-] Version: %s' % payload['22']['ssh']['banner']['software_version']
    except:
        pass

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
