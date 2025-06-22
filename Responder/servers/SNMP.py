#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from utils import *

if settings.Config.PY2OR3 == "PY3":
    from socketserver import BaseRequestHandler
else:
    from SocketServer import BaseRequestHandler

from pyasn1.codec.der.decoder import decode


class SNMP(BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        received_record, rest_of_substrate = decode(data)

        snmp_version = int(received_record['field-0'])

        if snmp_version > 1:
            # TODO: Add support for SNMPv3 (which will have a field-0 value of 2)
            print(text("[SNMP] Unsupported SNMPv3 request received from %s" % self.client_address[0].replace("::ffff:","")))
            return

        community_string = str(received_record['field-1'])

        SaveToDb(
            {
                "module": "SNMP",
                "type": "Cleartext",
                "client": self.client_address[0],
                "user": community_string,
                "cleartext": community_string,
                "fullhash": community_string,
            }
        )
