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
import datetime

class Log:
  __instance = None
  
  def __init__( self ):
    self.enabled   = Config.getInstance().logging
    self.filename  = Config.getInstance().logfile
    self.flushrate = Config.getInstance().logflushrate
    self.fd        = open( self.filename, "w+" )
    self.logs      = 0

  @classmethod
  def instance(cls):
    if cls.__instance is None:
      cls.__instance = Log()
    return cls.__instance

  @classmethod
  def raw( cls, type, message ):
    log = Log.instance()
    if log.enabled:
      log.fd.write( "[%s] [%s] %s\n" % ( datetime.datetime.now().strftime("%d/%b %H:%M:%S"), type, message ) )

      log.logs += 1
      if log.logs >= log.flushrate:
        log.fd.flush()
        log.logs = 0

  @classmethod
  def error( cls, message ):
    Log.instance().raw( 'ERROR', message )

  @classmethod
  def warning( cls, message ):
    Log.instance().raw( 'WARNING', message )
  
  @classmethod
  def info( cls, message ):
    Log.instance().raw( 'INFO', message )