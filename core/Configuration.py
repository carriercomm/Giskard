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
from core.Rule import Rule
import ConfigParser
import os

class Config:
  __instance = None;
  __path     = os.path.realpath( os.path.dirname( os.path.realpath(__file__) ) + "/../" )
  __filename = "giskard.ini"
  
  def __init__( self ):
    self.rules  = {}
    self.parser = ConfigParser.ConfigParser()

    self.parser.read( Config.__path + '/' + Config.__filename )

    self.logging      = self.parser.getboolean( 'DEFAULT', 'logging' ) if self.parser.has_option( 'DEFAULT', 'logging' ) else True
    self.logfile      = self.parser.get( 'DEFAULT', 'logfile' ) if self.parser.has_option( 'DEFAULT', 'logfile' ) else '/var/log/giskard'
    self.logflushrate = self.parser.getint( 'DEFAULT', 'logflushrate' ) if self.parser.has_option( 'DEFAULT', 'logflushrate' ) else 0
    self.pidfile      = self.parser.get( 'DEFAULT', 'pidfile' ) if self.parser.has_option( 'DEFAULT', 'pidfile' ) else '/var/run/giskard.pid'
    self.whitelist    = self.parser.get( 'DEFAULT', 'whitelist', ',' ).split(',') if self.parser.has_option( 'DEFAULT', 'whitelist' ) else []
    self.whitelist    = map( lambda s: s.strip(), self.whitelist )
    self.sleep        = self.parser.getint( 'DEFAULT', 'sleep' ) if self.parser.has_option( 'DEFAULT', 'sleep' ) else 60

    for port in self.parser.sections():      
      threshold = self.parser.getint( port, 'threshold' )
      timeout   = self.parser.getint( port, 'timeout' )
      rule      = self.parser.get( port, 'rule' )
      undo      = self.parser.get( port, 'undo' ) if self.parser.has_option( port, 'undo' ) else None
      port      = int(port)
      
      self.rules[port] = Rule( port, threshold, timeout, rule, undo )

    if len(self.rules) <= 0:
      raise Exception( "No rule specified." )

  @classmethod
  def getInstance(cls):
    if cls.__instance is None:
      cls.__instance = Config()
    return cls.__instance
