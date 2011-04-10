# -*- coding: utf-8 -*-
# This file is part of Giskard.
#
# Copyright(c) 2010-2011 Simone Margaritelli
# evilsocket@gmail.com
# http://www.evilsocket.net
# http://www.backbox.org
#
# This file may be licensed under the terms of of the
# GNU General Public License Version 2 (the ``GPL'').
#
# Software distributed under the License is distributed
# on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
# express or implied. See the GPL for the specific language
# governing rights and limitations.
#
# You should have received a copy of the GPL along with this
# program. If not, go to http://www.gnu.org/licenses/gpl.html
# or write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
from core.Configuration import Config
import re

class NetworkParser:
  """ The regular expression used to extract data from each /proc/net/tcp line. """
  STAT_EXTRACTOR = re.compile(r"""^\s*
                                   (\d+):\s                                     # sl                        -  0
                                   ([\dA-F]{8}(?:[\dA-F]{24})?):([\dA-F]{4})\s  # local address and port    -  1 y  2
                                   ([\dA-F]{8}(?:[\dA-F]{24})?):([\dA-F]{4})\s  # remote address and port   -  3 y  4
                                   ([\dA-F]{2})\s                               # st                        -  5
                                   ([\dA-F]{8}):([\dA-F]{8})\s                  # tx_queue and rx_queue     -  6 y  7
                                   (\d\d):([\dA-F]{8}|(?:F{9,}))\s              # tr and tm->when           -  8 y  9
                                   ([\dA-F]{8})\s+                              # retrnsmt                  - 10
                                   (\d+)\s+                                     # uid                       - 11
                                   (\d+)\s+                                     # timeout                   - 12
                                   (\d+)\s+                                     # inode                     - 13
                                   (\d+)\s+                                     # ref count                 - 14
                                   ((?:[\dA-F]{8}){1,2})                        # memory address            - 15
                                   (?:
                                       \s+
                                       (\d+)\s+                                 # retransmit timeout        - 16
                                       (\d+)\s+                                 # predicted tick            - 17
                                       (\d+)\s+                                 # ack.quick                 - 18
                                       (\d+)\s+                                 # sending congestion window - 19
                                       (-?\d+)                                  # slow start size threshold - 20
                                   )?
                                   \s*
                                   (.*)                                         # more                      - 21
                              $""", re.X | re.IGNORECASE)
                              
  """ Pretty self explainatory. """
  NETSTATS_FILE = '/proc/net/tcp'

  """ Listener status code. """
  LISTENER_STATUS = 0x0A

  @classmethod
  def long2address(cls, l):
    """ Converts a little endian long integer to a dotted ip address. """
    return '.'.join([
                    str(l       & 0xFF),
                    str(l >> 8  & 0xFF),
                    str(l >> 16 & 0xFF),
                    str(l >> 24 & 0xFF)
                    ])

  @classmethod
  def address2long(cls, address):
    """ Converts a dotted ip address to a little endian long integer """
    bytes = address.split('.')
    bytes = map(lambda b: int(b), bytes)
    return bytes[0] | bytes[1] << 8 | bytes[2] << 16 | bytes[3] << 24;

  def __init__(self):
    self.config      = Config.getInstance()
    self.connections = []
    self.listeners   = {}
    self.load        = {}
    self.whitelist   = map( lambda address: NetworkParser.address2long(address), self.config.whitelist )
    self.rules       = self.config.rules.keys()

  def run(self):
    """ Performs network stats and load computations. """
    # reset status
    self.connections = []
    self.listeners   = {}
    self.load        = {}

    fd = open(NetworkParser.NETSTATS_FILE)

    for line in iter(fd):
      line  = line.strip()
      match = NetworkParser.STAT_EXTRACTOR.findall(line)
      # skip non matching lines
      if match != []:
        match = match[0]
        # cast matches to unsigned long integers
        l_address = long(match[1], 16)
        l_port    = long(match[2], 16)
        r_address = long(match[3], 16)
        r_port    = long(match[4], 16)
        status    = long(match[5], 16)

        # found a listener with a rule available
        if status == NetworkParser.LISTENER_STATUS and l_port in self.rules:
          self.listeners[l_port] = l_address
        # inbound connection not whitelisted triggering a user defined rule
        elif r_address not in self.whitelist and l_port in self.rules:
          connection = {
            'l_address' : l_address,
            'l_port'    : l_port,
            'r_address' : r_address,
            'r_port'    : r_port,
            'status'    : status
          }
          self.connections.append(connection)

    fd.close()

    # compute server load
    for connection in self.connections:
      port = connection['l_port']
      # inbound connection
      if port in self.listeners:
        remote = connection['r_address']
        # known address
        if self.load.has_key(remote):
          # known port, just increment hits
          if self.load[remote].has_key(port):
            self.load[remote][port] += 1
          # first hit found on this port
          else:
            self.load[remote][port] = 1
        # new address found
        else:
          self.load[remote] = {}
          self.load[remote][port] = 1
