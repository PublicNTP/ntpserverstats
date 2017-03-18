#!/usr/bin/env python

# Copyright (c) 2016-2017 Terry D. Ott
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

import boto3        # AWS SDK for Python
import logging      # AWS kindly puts anything logged into CloudWatch
import tempfile     # Used for reading RRD, writing of PNG


# Set up global logging
logger = logging.getLogger()
logger.setLevel(level=logging.DEBUG)


def s3_RRDWriteHandler(event, context):
  for currWriteEvent in event['Records']:
    _processS3Write(currWriteEvent['s3'])


def _processS3Write( s3WriteRecord ):
  s3_sourceBucket = s3WriteRecord['bucket']['name']
  s3_sourceRRD    = s3WriteRecord['object']['key']

  logging.info( "S3 write; bucket: {0}, rrd: {1}".format(
    s3_sourceBucket, s3_sourceRRD) )

  # Pull the RRD down


