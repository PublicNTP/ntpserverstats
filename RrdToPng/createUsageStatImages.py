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

import boto3                        # AWS SDK for Python
import logging                      # AWS kindly puts anything logged into CloudWatch
import tempfile                     # Used for writing RRD and PNG to disk
import pyrrd.graph                  # Python RRD interface
from pyrrd.backend import bindings  # Have to specify bindings backend, as lambda doesn't have cmdline tool installed
from pyrrd.graph import ColorAttributes


# Set up global logging
logger = logging.getLogger()
logger.setLevel(level=logging.INFO)


def s3_RRDWriteHandler(event, context):
  s3Client = boto3.client('s3')
  for currWriteEvent in event['Records']:
    _processS3Write(currWriteEvent['s3'], s3Client)


def _processS3Write( s3WriteRecord, s3Client ):
  s3_sourceBucket = s3WriteRecord['bucket']['name']
  s3_sourceRRD    = s3WriteRecord['object']['key']

  logger.info( "S3 write; bucket: {0}, rrd: {1}".format(
    s3_sourceBucket, s3_sourceRRD) )

  # Host ID will be source RRD minus file extension
  hostID = s3_sourceRRD[ len("rrd/"):(len(s3_sourceRRD)-len(".rrd")) ]
  logger.debug("Got host ID {} out of file {}".format(hostID, s3_sourceRRD) )

  # Create tempfile where contents should be written,
  #   file will automatically be deleted as soon as returned
  #   filehandle is closed (which happens automatically when it
  #   goes out of cope
  rrdTempfile = tempfile.NamedTemporaryFile(suffix='.rrd')
  logger.info("RRD is being stored in file {}".format(rrdTempfile.name))

  s3Client.download_file( s3_sourceBucket, s3_sourceRRD, rrdTempfile.name )

  # Generate host-specific stats graphs
  _generateHostStatsGraphs( hostID, rrdTempfile.name, s3Client, s3_sourceBucket )

  # Regenerate cumulative stats graphs


  # RRD tempfile go out of scope, so files are closed and deleted


def _generateHostStatsGraphs( hostID, rrdFilename, s3Client, s3BucketName ):
  ca = ColorAttributes()
  ca.back = '#FFFFFF'
  ca.canvas = '#FFFFFF'
  ca.shadea = '#FFFFFF'
  ca.shadeb = '#FFFFFF'
  ca.axis = '#FFFFFF'
  ca.font = '#383535'
  ca.frame = '#FFFFFF'
  ca.arrow = '#FFFFFF'
  ca.mgrid = '#95989A'

  for numDays in [ "0001d", "0007d", "0030d", "0364d", "3640d" ]:

    # Create packet graph

    rrdDef_RequestsIn   = pyrrd.graph.DEF(
      rrdfile=rrdFilename,
      vname= "requests_in",
      dsName="requests_in",
      cdef="MAX" )
    rrdDef_ResponsesOut = pyrrd.graph.DEF(
      rrdfile=rrdFilename,
      vname ="responses_out",
      dsName="responses_out",
      cdef="MAX" )
    rrdArea_In          = pyrrd.graph.AREA(
      defObj=rrdDef_RequestsIn,
      color="#7FBA90",
      legend="Inbound" )
    rrdArea_Out         = pyrrd.graph.AREA(
      defObj=rrdDef_ResponsesOut,
      color="#A07EB5",
      legend="Outbound" )

    # Create graph
    pngTempfile = tempfile.NamedTemporaryFile(suffix='.png')
    logger.info("PNG being stored in {}".format(pngTempfile.name))
    graph = pyrrd.graph.Graph(
      pngTempfile.name,
      title="{0} packets".format(hostID),
      vertical_label="Packets/sec",
      imgformat="PNG",
      font="DEFAULT:0:Roberto",
      end="now",
      start="end-{}".format(numDays),
      width=640,
      height=240,
      lower_limit=0,
      color=ca,
      no_legend=True,
      backend=bindings )

    graph.data.extend( [ rrdDef_RequestsIn, rrdDef_ResponsesOut,
      rrdArea_In, rrdArea_Out ] )

    graph.write()

    # Now that graph is created, let's upload it to our PNG dir in the S3 bucket
    s3GraphKey = "png/{}-{}-packets.png".format(hostID, numDays)
    logger.info("Creating packet graph {}".format(s3GraphKey) )

    s3Client.upload_file( pngTempfile.name, s3BucketName, s3GraphKey )
