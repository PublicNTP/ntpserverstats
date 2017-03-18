#!/usr/bin/env python

import argparse
import json
#import pprint
import boto3

def main():
  args = _parseArgs()

  credentials = _readCredentials(args.aws_creds)

  s3Client = boto3.client( 
    's3', 
    aws_access_key_id=credentials['aws_access_key_id'],
    aws_secret_access_key=credentials['aws_secret_access_key'] )

  s3Client.upload_file( args.rrd_file, "stats.publicntp.org", "rrd/{0}.rrd".format(args.host_id) )


def _parseArgs():
  parser = argparse.ArgumentParser("Upload stats images to S3")
  parser.add_argument("rrd_file", help="The RRD file to upload")
  parser.add_argument("host_id", help="Unique host ID, e.g., \"stratum2-02.xyz03\"")
  parser.add_argument("aws_creds", help="AWS credentials file")

  return parser.parse_args()


def _readCredentials(credsFilename):
  with open(credsFilename) as credsFile:
    return json.load(credsFile)
  

if __name__ == '__main__':
  main()
