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

import logging

logger = logging.getLogger()
logger.basicConfig(level=logging.DEBUG)

def s3_RRDWriteHandler(event, context):
  logger.info("Got event: {0}".format(format(event))
  return "Hello, world"
