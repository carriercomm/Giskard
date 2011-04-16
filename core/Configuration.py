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

class Config(object):
  __slots__  = ( 'rules', 'parser', 'logfile', 'pidfile', 'whitelist', 'sleep', 'email_alerts', 'email_to', 'email_from', 'email_subj' )
  __instance = None;
  __path     = os.path.realpath( os.path.dirname( os.path.realpath(__file__) ) + "/../" )
  __filename = "giskard.ini"
  
  def __init__( self ):
    self.rules  = {}
    self.parser = ConfigParser.ConfigParser()

    self.parser.read( Config.__path + '/' + Config.__filename )

    self.logfile      = self.get( 'DEFAULT', 'logfile', '/var/log/giskard' )
    self.pidfile      = self.get( 'DEFAULT', 'pidfile', '/var/log/giskard.pid' ) 
    self.whitelist    = [ s.strip() for s in self.get( 'DEFAULT', 'whitelist', ',' ).split(',') ]
    self.email_alerts = self.getboolean( 'DEFAULT', 'email_alerts', False )
    self.email_to     = self.get( 'DEFAULT', 'email_to',   'root@localhost' )
    self.email_from   = self.get( 'DEFAULT', 'email_from', 'root@localhost' )
    self.email_subj   = self.get( 'DEFAULT', 'email_subj', 'Giskard Alarm' ) 
    self.sleep        = self.getint( 'DEFAULT', 'sleep', 60 ) 
    
    # except for the undo action, every field is mandatory so it's ok to raise
    # an exception when something is missing
    for name in self.parser.sections():
      port      = self.parser.getint( name, 'port' )
      threshold = self.parser.getint( name, 'threshold' )
      timeout   = self.parser.getint( name, 'timeout' )
      rule      = self.parser.get( name, 'rule' )
      undo      = self.get( name, 'undo', None ) 
      # initialize or get rule set for this port and append the new rule object
      self.rules[port] = self.rules.get( port, [] )
      self.rules[port].append( Rule( name, port, threshold, timeout, rule, undo ) )

    if len(self.rules) <= 0:
      raise Exception( "No rule specified." )
  
  def getint( self, section, option, default ):
    return self.parser.getint( section, option ) if self.parser.has_option( section, option ) else default

  def getboolean( self, section, option, default ):
    return self.parser.getboolean( section, option ) if self.parser.has_option( section, option ) else default

  def get( self, section, option, default ):
    return self.parser.get( section, option ) if self.parser.has_option( section, option ) else default

  @classmethod
  def getInstance(cls):
    if cls.__instance is None:
      cls.__instance = Config()
    return cls.__instance
