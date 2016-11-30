#!/usr/bin/env python

# Copyright (C) 2016 Tobias Mueller <muelli@cryptobitch.de>
#
# This file is part of GPGME.
#
# GPGME is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# GPGME is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General
# Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, print_function, unicode_literals
del absolute_import, print_function, unicode_literals

import shutil
import tempfile
import os
import gpg
import support

class TempContext(gpg.Context):
    def __init__(self):
        super(TempContext, self).__init__()
        self.homedir = tempfile.mkdtemp()
        self.set_engine_info(gpg.constants.protocol.OpenPGP,
            None, self.homedir)

    def __del__(self):
        shutil.rmtree(self.homedir)

c = TempContext()

before = list(c.keylist("", secret=True))
params = """<GnupgKeyParms format="internal">
%transient-key
Key-Type: RSA
Key-Length: 1024
Name-Real: Joe Genkey Tester
Name-Comment: with stupid passphrase
Name-Email: joe+gpg@example.org
Passphrase: Crypt0R0cks
#Expire-Date: 2020-12-31
</GnupgKeyParms>
"""
c.op_genkey(params, None, None)
# We should also have a result
result = c.op_genkey_result()
assert result.primary, "%r" % result
assert result.uid
after = list(c.keylist("", secret=True))
assert len(before) < len(after)


# With no passphrase
before = list(c.keylist("", secret=True))
params = """<GnupgKeyParms format="internal">
%transient-key
Key-Type: RSA
Key-Length: 1024
Name-Real: Joe Genkey Tester
Name-Comment: with stupid passphrase
Name-Email: joe+gpg@example.org
%no-protection
#Passphrase: Crypt0R0cks
#Expire-Date: 2020-12-31
</GnupgKeyParms>
"""
c.op_genkey(params, None, None)
after = list(c.keylist("", secret=True))
assert len(before) < len(after)



# Also with no pubkey and seckey argument
before = list(c.keylist("", secret=True))
params = """<GnupgKeyParms format="internal">
%transient-key
Key-Type: RSA
Key-Length: 1024
Name-Real: Joe Genkey Tester
Name-Comment: with stupid passphrase
Name-Email: joe+gpg@example.org
%no-protection
#Passphrase: Crypt0R0cks
#Expire-Date: 2020-12-31
</GnupgKeyParms>
"""
c.op_genkey(params)
after = list(c.keylist("", secret=True))
assert len(before) < len(after)
