#!/usr/bin/env python3
#
# Copyright (C) 2016 g10 Code GmbH
# Copyright (C) 2004,2008 Igor Belyi <belyi@users.sourceforge.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

# Sample of export and import of keys
# It uses keys for joe+pyme@example.org generated by genkey.py script

import sys
import os
import pyme

user = "joe+pyme@example.org"

with pyme.Context(armor=True) as c, pyme.Data() as expkey:
    print(" - Export %s's public keys - " % user)
    c.op_export(user, 0, expkey)

    # print out exported data to see how it looks in armor.
    expkey.seek(0, os.SEEK_SET)
    expstring = expkey.read()
    if expstring:
        sys.stdout.buffer.write(expstring)
    else:
        sys.exit("No %s's keys to export!" % user)

# delete keys to ensure that they came from our imported data.  Note
# that if joe's key has private part as well we can only delete both
# of them.
with pyme.Context() as c:
    # Note: We must not modify the key store during iteration,
    # therfore, we explicitly make a list.
    keys = list(c.keylist(user))

    for k in keys:
        c.op_delete(k, True)

with pyme.Context() as c:
    print(" - Import exported keys - ")
    c.op_import(expstring)
    result = c.op_import_result()
    if result:
        print(result)
    else:
        sys.exit(" - No import result - ")
