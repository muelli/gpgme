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

import os

import gpg

c = gpg.Context()
# We just want to get any existing key
fpr = next(c.keylist()).fpr

# We test the export() function for a pattern
bytes = c.export(fpr)
assert bytes

# The export function also takes a mode argument
minimal = c.export(fpr, mode=gpg.constants.EXPORT_MODE_MINIMAL)
assert len(minimal) < len(bytes)

# We can also provide a sink of our liking
sink = gpg.Data()
c.export(fpr, sink=sink)
sink.seek(0, os.SEEK_SET)
data = sink.read()
assert data

try:
    nonexisting_mode = 9999
    c.export(fpr, mode=nonexisting_mode)
    assert False, "Export should raise!"
except gpg.errors.GPGMEError as e:
    pass
