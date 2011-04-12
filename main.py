#!/usr/bin/python -OO
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
from Giskard import Giskard
import os
import sys

if __name__ == "__main__":  
  if not os.geteuid() == 0:
    sys.exit("Only root can run this script\n")

  print "Giskard 2.1.2 - Copyleft Simone Margaritelli http://www.evilsocket.net <evilsocket@gmail.com>\n";
  
  giskard = Giskard( stderr = '/dev/stderr' )

  if len(sys.argv) == 2:
    if 'start' == sys.argv[1]:
      giskard.start()
    elif 'stop' == sys.argv[1]:
      giskard.stop()
    elif 'restart' == sys.argv[1]:
      giskard.restart()
    elif 'stats' == sys.argv[1]:
      giskard.stats()
    else:
      print "Unknown command"
      sys.exit(2)

    sys.exit(0)
    
  else:
    print "usage: %s start|stop|restart|stats" % sys.argv[0]
    sys.exit(2)
