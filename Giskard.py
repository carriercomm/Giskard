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
from core.Daemon        import Daemon
from core.NetworkParser import NetworkParser
from email.mime.text    import MIMEText

import logging
import os 
import time
import threading
import gc
import smtplib

class TriggerUndoScheduler( threading.Thread, object ):
  __slots__ = ( 'rulename', 'address', 'undo', 'timeout', 'daemon' )

  def __init__( self, rulename, address, undo, timeout, daemon ):
    threading.Thread.__init__(self)
    self.rulename = rulename
    self.address  = address
    self.undo     = undo
    self.timeout  = timeout
    self.daemon   = daemon

  def run(self):
    try:
      time.sleep( self.timeout )
      logging.info( "Undoing '%s' for address %s" % ( self.rulename, NetworkParser.long2address( self.address ) ) )
      os.system( self.undo )
    except Exception as e:
      logging.error( e )
    finally:
      self.daemon.remove_trigger( self.address )
                 
class Giskard(Daemon,object):
  __slots__ = ( 'config', 'netstat', 'triggers', 'lock' )

  def __init__( self, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null', openLog = True ):
    Daemon.__init__( self, Config.getInstance().pidfile, stdin, stdout, stderr )

    # Set the threshold for the first generation to 3
    gc.set_threshold( 3 )

    self.config   = Config.getInstance()
    self.netstat  = NetworkParser()
    self.triggers = []
    self.lock     = threading.Lock()
    
    # Initialize logging
    if openLog is True:
      logging.basicConfig( level    = logging.INFO,
                           format   = '[%(asctime)s] [%(levelname)s] %(message)s',
                           filename = self.config.logfile,
                           filemode = 'a' )


  def start(self):
    logging.info( "Giskard daemon started." )
    Daemon.start( self )

  def stop(self):
    logging.info( "Giskard daemon stopped." )
    Daemon.stop( self )

  def stats(self):
    self.netstat.run()
    
    print "Listeners     :\n"
    for port, address in self.netstat.listeners.iteritems():
      print "\t%s on port %d" % ( self.netstat.long2address(address), port )

    print "\nServer Load   :\n"
    for address, hits in self.netstat.load.iteritems():
      print "\t%s :" % self.netstat.long2address(address)
      for port, nhits in hits.iteritems():
        print "\t\t%d hits on port %d" % ( nhits, port )

    print "\nRuleset       :\n"
    for port, set in self.config.rules.iteritems():
      print "\tRules for port %d :" % port
      for rule in set:
        print "\t\t%s" % rule

  def remove_trigger( self, address ):
    self.lock.acquire()
    self.triggers.remove(address)
    self.lock.release()

  def add_trigger( self, rulename, address, trigger, undo, timeout ):
    try:
      os.system( trigger )
      self.lock.acquire()
      self.triggers.append(address)

      if undo is not None:
        TriggerUndoScheduler( rulename, address, undo, timeout, self ).start()
      
    except Exception as e:
      logging.error( e )
    finally:
      self.lock.release()
  
  def run(self):
    logging.info( "Giskard is now running ." )
    
    while True:
      logging.debug( "Running new check ..." )
      self.netstat.run()

      for address, hits in self.netstat.load.iteritems():
        for port, nhits in hits.iteritems():
          rule_set = self.config.rules[ port ]
          for rule in rule_set:
            # if exceeded the threshold and still doesn't have an active trigger
            if nhits > rule.threshold and address not in self.triggers:
              saddress = self.netstat.long2address(address)
              trigger  = rule.rule % saddress
              undo     = rule.undo % saddress if rule.undo is not None else None

              self.add_trigger( rule.name, address, trigger, undo, rule.timeout )
              
              alarm = "Address %s has exceeded the threshold of %d concurrent requests on port %d with %d hits, triggering rule '%s' for %d seconds." % (
                        saddress,
                        rule.threshold,
                        port,
                        nhits,
                        rule.name,
                        rule.timeout
                      )

              logging.warning( alarm ) 

              if self.config.email_alerts is True:
                smtp  = smtplib.SMTP('localhost') 
                email = MIMEText( alarm )
                
                email['From']    = self.config.email_from
                email['To']      = self.config.email_to
                email['Subject'] = self.config.email_subj

                smtp.sendmail( self.config.email_from, [self.config.email_to], email.as_string() )  
                smtp.quit()
                
      # Force garbage collection before going to sleep :)
      freed = gc.collect()
      if freed != 0:
        logging.debug( "Freed %d objects during garbage collection." % freed )

      time.sleep( self.config.sleep )
