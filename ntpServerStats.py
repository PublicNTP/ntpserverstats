#!/usr/bin/env python

# Copyright (c) 2016 Terry D. Ott
#
#   You may use, distribute, and modify this code under the terms
#   of the MIT License.
#
#   You should have received a copy of the MIT License with this
#   file. If not, please visit:
#
#   https://github.com/TerryOtt/ntpserverstats/blob/master/LICENSE
#
#   or
#
#   https://opensource.org/licenses/MIT


import logging
import scapy.all
import datetime
import argparse
import pprint


def startCapture(captureSeconds):
    log = logging.getLogger(__name__)
    log.info('Start NTP packet capture @ ' + timestampString(datetime.datetime.utcnow()) + \
        ', end @ ' + 
        timestampString(datetime.datetime.utcnow() + datetime.timedelta(0, captureSeconds)) + \
        " ({0} seconds)".format(captureSeconds))

    return scapy.all.sniff(filter="udp port ntp", 
        timeout=captureSeconds )


def timestampString(startTimestamp):
    return datetime.datetime.strftime(startTimestamp, "%Y-%m-%d %H:%M:%S")


def analyzeCapturedPackets(ntpPackets, serverIP, captureSeconds):
    log = logging.getLogger(__name__)
    log.debug("Found {0} packets in capture".format(len(ntpPackets)))

    ntpStats = { 'client': {}, 'server': {} }

    for currPacket in ntpPackets:
        if scapy.all.UDP not in currPacket:
            continue
        # log.debug(currPacket.sprintf("%.time%: %15s,IP.src%:%-5s,UDP.sport% -> %15s,IP.dst%:%-5s,UDP.dport%"))

        #log.debug(currPacket.show())
        
        # Is it client query to our server?
        if currPacket[scapy.all.IP].dst == serverIP and \
                currPacket[scapy.all.UDP].sport != 123 and \
                currPacket[scapy.all.UDP].dport == 123:
            # log.debug("NTP  request: {0}".format(
            #    currPacket.sprintf("%.time%: %15s,IP.src%:%-5s,UDP.sport% -> %15s,IP.dst%:%-5s,UDP.dport%")))

            if 'count' not in ntpStats['client']:
                ntpStats['client']['count'] = 1
            else:
                ntpStats['client']['count'] = ntpStats['client']['count'] + 1

            if 'bytes' not in ntpStats['client']:
                ntpStats['client']['bytes'] = currPacket[scapy.all.IP].len
            else:
                ntpStats['client']['bytes'] = ntpStats['client']['bytes'] + \
                    currPacket[scapy.all.IP].len
                

        # Is it our server to a client?
        elif currPacket[scapy.all.IP].src == serverIP and currPacket[scapy.all.UDP].dport != 123:
            # log.debug("NTP response: {0}".format(
            #    currPacket.sprintf("%.time%: %15s,IP.src%:%-5s,UDP.sport% -> %15s,IP.dst%:%-5s,UDP.dport%")))
            if 'count' not in ntpStats['server']:
                ntpStats['server']['count'] = 1
            else:
                ntpStats['server']['count'] = ntpStats['server']['count'] + 1


            if 'bytes' not in ntpStats['server']:
                ntpStats['server']['bytes'] = currPacket[scapy.all.IP].len
            else:
                ntpStats['server']['bytes'] = ntpStats['server']['bytes'] + \
                    currPacket[scapy.all.IP].len


    print("\n  Client queries:\n")
    print("\t     Requests: {0:10d}".format(ntpStats['client']['count']))
    print("\t Request Rate: {0:10d} requests/sec".format(ntpStats['client']['count'] / captureSeconds))
    print("\t        Bytes: {0:10d}".format(ntpStats['client']['bytes']))
    print("\t    Byte Rate: {0:10d} bytes/sec".format(ntpStats['client']['bytes'] / captureSeconds))

    print("\nServer responses:\n")
    print("\t    Responses: {0:10d}".format(ntpStats['server']['count']))
    print("\tResponse Rate: {0:10d} responses/sec".format(ntpStats['server']['count'] / captureSeconds))
    print("\t        Bytes: {0:10d}".format(ntpStats['server']['bytes']))
    print("\t    Byte Rate: {0:10d} bytes/sec".format(ntpStats['server']['bytes'] / captureSeconds))

    print("")


def parseArgs():
    parser = argparse.ArgumentParser(description="Monitor incoming and outgoing traffic of an NTP server")
    parser.add_argument('serverIP', help='IP address of the NTP server, e.g. 192.168.0.1')
    parser.add_argument('sampleSeconds', nargs='?', type=int,
        help='Number of seconds to sample traffic', default=60)
    return parser.parse_args()


def main():
    args = parseArgs()
    logging.basicConfig(level=logging.DEBUG)
    log = logging.getLogger(__name__)
    ntpPackets = startCapture(args.sampleSeconds)
    analyzeCapturedPackets(ntpPackets, args.serverIP, args.sampleSeconds)



if __name__ == '__main__':
    main()
