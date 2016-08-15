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
import os.path
import pyrrd.rrd


def verifyRRDOutputDir(outputDir):
    return os.path.isdir(outputDir)


def startCapture(serverIP, captureSeconds):
    log = logging.getLogger(__name__)
    log.info('Start NTP packet capture @ ' + timestampString(datetime.datetime.utcnow()))
    log.info('  End NTP packet capture @ ' + 
        timestampString(datetime.datetime.utcnow() + datetime.timedelta(0, captureSeconds))) 
    log.info("Capture duration: {0} seconds".format(captureSeconds))

    return scapy.all.sniff(filter=
        "(src host {0} and udp and src port ntp and not dst port ntp) ".format(serverIP) +
        "or " +
        "(dst host {0} and udp and not src port ntp and dst port ntp)".format(serverIP), 
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

    return ntpStats


def createRRDFiles(rrdDirectory):
    packetsRRDFile = os.path.join(rrdDirectory, 'ntpserverstats-packets.rrd') 
    if not os.path.isfile(packetsRRDFile):
        createRRD(packetsRRDFile, "requests_in", "responses_out")

    bytesRRDFile = os.path.join(rrdDirectory, 'ntpserverstats-bytes.rrd')
    if not os.path.isfile(bytesRRDFile):
        createRRD(bytesRRDFile, "bytes_in", "bytes_out")


def createRRD(packetsRRDFile, inputDataSourceName, outputDataSourceName):
    log = logging.getLogger(__name__)
    log.debug("Creating RRD file {0}".format(packetsRRDFile))
    roundRobinArchives = []
    dataSources = [ 
        pyrrd.rrd.DataSource(dsName=inputDataSourceName,  dsType="GAUGE", heartbeat="10m"),
        pyrrd.rrd.DataSource(dsName=outputDataSourceName, dsType="GAUGE", heartbeat="10m")
    ]

    # Samples every 5 minutes
    roundRobinArchives = [
        # Daily archive 
        #  1 day = 1,440 mins
        #  1 day = 1,440 mins / 5 mins/consolidated entry = 288 5-min points
        pyrrd.rrd.RRA(cf='MAX', xff=0.5, steps="5m", rows="1d"), 

        # Weekly archive 
        #
        #  1 week = 10,080 minutes
        #  10,080 mins / 15 mins/consolidated point = 672 consolidated 15-min points
        pyrrd.rrd.RRA(cf='MAX', xff=0.5, steps="15m", rows="7d"),

        # Monthly archive
        # 
        # 1 month = 31 days * 1,440 mins/day = 44,640 mins
        # 44,640 mins / 60 mins/consolidated point = 774 consolidated 60-min points
        pyrrd.rrd.RRA(cf='MAX', xff=0.5, steps="60m", rows="31d"),

        # Yearly archive
        #
        # 1 year = 365 days * 1,440 mins/day = 525,600 mins
        # 12 hours = 720 mins
        # 525,600 mins / 720 mins/consolidated point = 730 consolidated 12-hour points
        pyrrd.rrd.RRA(cf='MAX', xff=0.5, steps="12h", rows="1y"),

        # Decade archive
        #
        # 1 week = 1,440 mins/week * 7 days/week = 10,080 mins
        # 10 years = 520 weeks
        # 520 weeks / 1 week/consolidated point = 520 consolidated 1 week points 
        pyrrd.rrd.RRA(cf='MAX', xff=0.5, steps="1w", rows="520w") 
    ]

    myRRD = pyrrd.rrd.RRD(
        packetsRRDFile, 
        ds=dataSources, 
        rra=roundRobinArchives,
        start="now" )

    myRRD.create()


def parseArgs():
    parser = argparse.ArgumentParser(description="Monitor incoming and outgoing traffic of an NTP server")
    parser.add_argument('serverIP', help='IP address of the NTP server, e.g. 192.168.0.1')
    parser.add_argument('rrdDir', help="Directory to store output Round-Robin Databases (RRD's)")
    parser.add_argument('sampleSeconds', nargs='?', type=int,
        help='Number of seconds to sample traffic', default=60)
    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.DEBUG)
    args = parseArgs()
    if verifyRRDOutputDir(args.rrdDir) is False:
        raise Exception('Could not open output directory for RRD files {0}'.format(
            args.rrdDir) )
    createRRDFiles(args.rrdDir)
    ntpStats = analyzeCapturedPackets( startCapture(args.serverIP, args.sampleSeconds), 
        args.serverIP, args.sampleSeconds )
    # updateRRD(ntpStats, args.rrdDir)


if __name__ == '__main__':
    main()
