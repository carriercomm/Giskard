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
class Rule(object):
  __slots__ = ( 'name', 'port', 'threshold', 'timeout', 'rule', 'undo' )

  def __init__( self, name, port, threshold, timeout, rule, undo ):
    self.name      = name
    self.port      = port
    self.threshold = threshold
    self.timeout   = timeout
    self.rule      = rule
    self.undo      = undo

  def __str__(self):
    return "[%s] '%s' for %s seconds if connections on port %d are more than %d, then run '%s' to undo." % (
      self.name, self.rule, self.timeout, self.port, self.threshold, self.undo
    )