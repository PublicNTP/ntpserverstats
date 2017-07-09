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
import logging                      # Nice debug logging
import tempfile                     # Used for writing RRD and PNG to disk
import pyrrd.graph                  # Python RRD interface
import json                         # Parsing data from SQS notifications
import pprint                       # Pretty printing, debug only


def main(logger):

  sqsService = boto3.resource('sqs')
  rrdWriteQueue = sqsService.get_queue_by_name(QueueName='PublicNTP_S3_Stats_RRD_Write')

  s3Client = boto3.client('s3')

  # Purge the queue to start fresh
  _purgeSqsQueue(logger, rrdWriteQueue)
  
  while True:
    sqsMessages = _waitForSQSWrite(logger, rrdWriteQueue)

    s3Records = _parseS3RecordsFromSqsMessages(sqsMessages)

    for currRecord in s3Records:

      _processS3Write(currRecord, s3Client, logger )

    #break


def _purgeSqsQueue(logger, rrdWriteQueue):
  # Purge the queue to start fresh
  logger.debug("Purging SQS queue to start fresh")
  try:
    rrdWriteQueue.purge()
    logger.debug("SQS queue purged")
  except Exception as e:
    logger.debug("Exception when purging SQS queue: {0}".format(e))


  
def _waitForSQSWrite(logger, queue):
  receivedMsgs = []

  logger.info("Waiting for new RRD file writes")
  while len(receivedMsgs) == 0:
    for currMessage in queue.receive_messages(
        MaxNumberOfMessages=10,   
        WaitTimeSeconds=20):

      receivedMsgs.append( json.loads( json.loads(currMessage.body)['Message']) )

      # Let queue know message is successfully received
      currMessage.delete()

  logger.info("Received {0} notifications of SQS writes".format(len(receivedMsgs)))

  return receivedMsgs


def _parseS3RecordsFromSqsMessages(sqsMessages):
  s3Records = []
  for currSqsMessage in sqsMessages:
    for currRecord in currSqsMessage['Records']:
      s3Records.append(currRecord['s3'])

  return s3Records
    

def _processS3Write( s3WriteRecord, s3Client, logger):
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

  # Forcibly remove reference to RRD tempfile, ensuring files are closed and deleted
  rrdTempfile = None


def _generateHostStatsGraphs( hostID, rrdFilename, s3Client, s3BucketName ):
  ca = pyrrd.graph.ColorAttributes()
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
    logger.info("PNG being stored in {0}".format(pngTempfile.name))
    graph = pyrrd.graph.Graph(
      pngTempfile.name,
      title=hostID,
      vertical_label="Packets/sec",
      imgformat="PNG",
      font="DEFAULT:0:Roboto",
      end="now",
      start="end-{0}".format(numDays),
      width=640,
      height=240,
      lower_limit=0,
      color=ca,
      no_legend=True )

    graph.data.extend( [ rrdDef_RequestsIn, rrdDef_ResponsesOut,
      rrdArea_In, rrdArea_Out ] )

    graph.write()

    # Now that graph is created, let's upload it to our PNG dir in the S3 bucket
    s3GraphKey = "png/{0}-{1}-packets.png".format(hostID, numDays)
    logger.info("Creating packet graph {0}".format(s3GraphKey) )

    s3Client.upload_file( pngTempfile.name, s3BucketName, s3GraphKey )


if __name__ == "__main__":
  # Set up global logging
  logging.basicConfig()
  logger = logging.getLogger(__name__)
  logger.setLevel(logging.INFO)
  main(logger)

