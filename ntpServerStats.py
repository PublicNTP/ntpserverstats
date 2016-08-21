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
import datetime
import argparse
import pprint
import pyrrd.rrd
import calendar
import time
import subprocess
import scapy.all
import tempfile
import os
import datetime

serverIP = ""

# Global stats data
ntpStats = {
    'client': { 
        'count': 0,
        'bytes': 0 },

    'server': {
        'count': 0,
        'bytes': 0
    }
}


def verifyRRDOutputDir(outputDir):
    return os.path.isdir(outputDir)


def updateCounts(currPacket):
    log = logging.getLogger(__name__)

    if scapy.all.UDP not in currPacket:
        return
    # log.debug(currPacket.sprintf("%.time%: %15s,IP.src%:%-5s,UDP.sport% -> %15s,IP.dst%:%-5s,UDP.dport%"))

    #log.debug(currPacket.show())

    global ntpStats

    # Is it client query to our server?
    if currPacket[scapy.all.IP].dst == serverIP:
        # log.debug("NTP  request: {0}".format(
        #    currPacket.sprintf("%.time%: %15s,IP.src%:%-5s,UDP.sport% -> %15s,IP.dst%:%-5s,UDP.dport%")))
        ntpStats['client']['count'] += 1
        ntpStats['client']['bytes'] += currPacket[scapy.all.IP].len 

    # Is it our server to a client?
    elif currPacket[scapy.all.IP].src == serverIP:
        # log.debug("NTP response: {0}".format(
        #    currPacket.sprintf("%.time%: %15s,IP.src%:%-5s,UDP.sport% -> %15s,IP.dst%:%-5s,UDP.dport%")))
        ntpStats['server']['count'] += 1 
        ntpStats['server']['bytes'] += currPacket[scapy.all.IP].len

    else:
        log.warn("Got packet in update counts that we shouldn't have")
    


def startCapture(serverIP, captureSeconds, maxPackets):
    log = logging.getLogger(__name__)
    log.info('Start NTP packet capture @ ' + timestampString(datetime.datetime.utcnow()))
    log.info('  End NTP packet capture @ ' + 
        timestampString(datetime.datetime.utcnow() + datetime.timedelta(0, captureSeconds))) 
    log.info("Capture duration: {0} seconds".format(captureSeconds))

    # Do not go into promiscuous mode for sniffing
    scapy.all.conf.promisc = False

    # Terminate sniffing when we hit the specified seconds OR packet count, whichever is first
    scapy.all.sniff(
        filter="udp port ntp",
        count=maxPackets,
        timeout=captureSeconds,
        prn=updateCounts,
        store=False )


def timestampString(startTimestamp):
    return datetime.datetime.strftime(startTimestamp, "%Y-%m-%d %H:%M:%S")


def computeStats(captureSeconds):
    log = logging.getLogger(__name__)

    # Determine per-second stats
    ntpStats['client']['reqs_per_second']      = \
        ntpStats['client']['count'] / captureSeconds
    ntpStats['client']['bytes_per_second']     = \
        ntpStats['client']['bytes'] / captureSeconds
    ntpStats['server']['responses_per_second'] = \
        ntpStats['server']['count'] / captureSeconds
    ntpStats['server']['bytes_per_second'] = \
        ntpStats['server']['bytes'] / captureSeconds

    print("\n  Client queries:\n")
    print("\t     Requests: {0:10.0f}".format(ntpStats['client']['count']))
    print("\t Request Rate: {0:10.0f} requests/sec".format(ntpStats['client']['reqs_per_second']))
    print("\t        Bytes: {0:10.0f}".format(ntpStats['client']['bytes']))
    print("\t    Byte Rate: {0:10.0f} bytes/sec".format(ntpStats['client']['bytes_per_second']))

    print("\nServer responses:\n")
    print("\t    Responses: {0:10.0f}".format(ntpStats['server']['count']))
    print("\tResponse Rate: {0:10.0f} responses/sec".format(ntpStats['server']['responses_per_second']))
    print("\t        Bytes: {0:10.0f}".format(ntpStats['server']['bytes']))
    print("\t    Byte Rate: {0:10.0f} bytes/sec".format(ntpStats['server']['bytes_per_second']))

    print("")

    return ntpStats


def getRRDFilename(rrdDirectory, serverIP):
    return os.path.join( rrdDirectory, 
        'ntpserverstats-{0}.rrd'.format(serverIP) )


def createRRDFile(rrdDirectory, serverIP):
    log = logging.getLogger(__name__)
    rrdFilename = getRRDFilename(rrdDirectory, serverIP)

    if os.path.isfile(rrdFilename):
        return

    log = logging.getLogger(__name__)
    log.info("Creating RRD file {0}".format(rrdFilename))
    roundRobinArchives = []
    dataSources = [ 
        pyrrd.rrd.DataSource(dsName="requests_in",   dsType="GAUGE", heartbeat="10m"),
        pyrrd.rrd.DataSource(dsName="responses_out", dsType="GAUGE", heartbeat="10m"),
        pyrrd.rrd.DataSource(dsName="bytes_in",      dsType="GAUGE", heartbeat="10m"),
        pyrrd.rrd.DataSource(dsName="bytes_out",     dsType="GAUGE", heartbeat="10m")
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

    pyrrd.rrd.RRD(
        rrdFilename, 
        ds=dataSources, 
        rra=roundRobinArchives ).create()


def updateRRD(ntpStats, rrdDirectory, serverIP):
    log = logging.getLogger(__name__)
    rrdFilename = getRRDFilename(rrdDirectory, serverIP) 

    rrdFile = pyrrd.rrd.RRD(rrdFilename)

    # Get seconds since UTC epoch 
    secondsSinceUtcEpoch = calendar.timegm(time.gmtime())
    log.debug("Time in seconds since UTC epoch: {0}".format(
        secondsSinceUtcEpoch))

    # Add new data row (buffered)
    rrdFile.bufferValue(secondsSinceUtcEpoch, 
        ntpStats['client']['reqs_per_second'], 
        ntpStats['server']['responses_per_second'],
        ntpStats['client']['bytes_per_second'],
        ntpStats['server']['bytes_per_second'])

    # Write buffered update to disk
    rrdFile.update()
    

def parseArgs():
    parser = argparse.ArgumentParser(description="Monitor incoming and outgoing traffic of an NTP server")
    parser.add_argument('serverIP', help='IP address of the NTP server, e.g. 192.168.0.1')
    parser.add_argument('rrdDir', help="Directory to store output Round-Robin Databases (RRD's)")
    parser.add_argument('sampleSeconds', nargs='?', type=int,
        help='Number of seconds to sample traffic', default=60)
    parser.add_argument('maxPackets', nargs='?', type=int,
        help='Maximum number of packets to sample', default=1000)
    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.DEBUG)
    log = logging.getLogger(__name__)

    args = parseArgs()
    if verifyRRDOutputDir(args.rrdDir) is False:
        raise Exception('Could not open output directory for RRD files {0}'.format(
            args.rrdDir) )
    createRRDFile(args.rrdDir, args.serverIP)

    # Note server IP so it can be used in callback
    global serverIP
    serverIP = args.serverIP

    # Get time before/after capture, may stop early if we hit packet count
    startCaptureTime = datetime.datetime.now()
    startCapture(args.serverIP, args.sampleSeconds, args.maxPackets)
    endCaptureTime = datetime.datetime.now()

    captureSeconds = (endCaptureTime-startCaptureTime).total_seconds()
    #log.debug(captureSeconds)
    
    ntpStats = computeStats(captureSeconds)
    updateRRD(ntpStats, args.rrdDir, args.serverIP)


if __name__ == '__main__':
    main()
