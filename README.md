# Introduction

ntpserverstats monitors traffic to/from a Network Time Protocol (NTP) 
server, keeping historical data in a database, and generates usage
graphs based on the usage patterns. 

# Installation

    apt-get -y install git python python-scapy python-rrdtool python-pyrrd
    git clone https://github.com/TerryOtt/ntpserverstats
    cd ntpserverstats
    mkdir ./rrd
    sudo bash
    cd /root
    echo "*/5 * * * * `which python` /path/to/ntpserverstats/ntpServerStats.py `/bin/hostname -I` /path/to/ntpserverstats/rrd/" > /root/crontab.root
    crontab crontab.root
    exit

After the cron entry has run once and created the .rrd file, run the following

    sudo chown ubuntu:ubuntu /path/to/ntpserverstats/rrd/*.rrd
    

# Licensing

segmentcsv2kml is licensed under the 
[MIT License](https://en.wikipedia.org/wiki/MIT_License). Refer to 
[LICENSE](https://github.com/TerryOtt/ntpserverstats/blob/master/LICENSE) 
for the full license text.
