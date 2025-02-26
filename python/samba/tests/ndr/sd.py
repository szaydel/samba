# Unix SMB/CIFS implementation.
# Copyright © Douglas Bagnall <dbagnall@samba.org> 2025
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import samba
from samba.tests import TestCase, DynamicTestCase
from samba.ndr import ndr_pack, ndr_unpack
from samba.dcerpc import security


class BaseSDTestCase(TestCase):
    maxDiff = 10000
    _cases = {
        # subclasses should have a mapping of test names to binhex
        # strings, as readable by bytes.fromhex().
        #
        # note, in Python 3.7+ that means hex pairs separated by any
        # amount of whitespace, but in Python 3.6 it means any number
        # of spaces. For example;
        #
        # 'ok_in_36': ("01 0203  04      05"
        #              "   06"),
        # 'ok_in_37': """
        #               01 02\t03
        #                04
        #               05 06"""
    }

    @classmethod
    def setUpDynamicTestCases(cls):
        for k, v in cls._cases.items():
            cls.generate_dynamic_test('test_sd', k, v)

    def _test_sd_with_args(self, v):
        packed = bytes.fromhex(v)
        try:
            sd = ndr_unpack(security.descriptor, packed)
        except (TypeError, ValueError, RuntimeError) as e:
            self.fail(f"raised {e}")
        try:
            repack = ndr_pack(sd)
        except (TypeError, ValueError) as e:
            self.fail(f"raised {e}")

        sd2 = ndr_unpack(security.descriptor, repack)
        self.assertEqual(sd, sd2)


@DynamicTestCase
class SDTestCase(BaseSDTestCase):
    _cases = {
        "sd_01": (
            # this one is manually annotated, but not because it is
            # especially interesting.
            "01 "            # version
            "00 "            #
            "17 8c "         # control: SR,RM,PS,SI,SD,SP,DP
            "14 00 00 00 "   # owner offset (20)
            "30 00 00 00 "   # group offset (48)
            "4c 00 00 00 "   # sacl offset  (76)
            "c4 00 00 00 "   # dacl offset  (196)
            "01 05 "                 # S-1- (5 sub auths)
            "00 00 00 00 00 05 "     #     5-
            "15 00 00 00 "           #       21-
            "51 d7 cf 86 "
            "f9 1b ef 93 "
            "c3 53 ea 70 "
            "00 02 00 00 "
            "01 05 "               # group: S-1-5-21-b-c-d-e
            "00 00 00 00 00 05 "
            "15 00 00 00 "
            "51 d7 cf 86 "
            "f9 1b ef 93 "
            "c3 53 ea 70 "
            "00 02 00 00 "
            # SACL
            "04 00 "        # sacl v4
            "78 00 "        # sacl size (92)
            "02 00 "        # ace count (2)
            "00 00 "
            "07 "           # sacl ACE, SYSTEM_AUDIT_OBJECT_ACE_TYPE
            "5a "           # flags
            "38 00 "        # ace size
            "20 00 00 00 "  # mask
            "03 00 00 00 "  # flags
            "be 3b 0e f3 f0 9f d1 11 "  # object type GUID
            "b6 03 00 00 f8 03 67 c1 "
            "a5 7a 96 bf e6 0d d0 11 "  # inherited type GUID
            "a2 85 00 aa 00 30 49 e2 "
            "01 01 "              # S-1-  (1 subauth)
            "00 00 00 00 00 01 "  #     1-
            "00 00 00 00 "        #       0
            "07 "           # sacl ACE, SYSTEM_AUDIT_OBJECT_ACE_TYPE
            "5a "           # flags
            "38 00 "        # size
            "20 00 00 00 "  # mask
            "03 00 00 00 "  #flags
            "bf 3b 0e f3 f0 9f d1 11 " # objct GUID
            "b6 03 00 00 f8 03 67 c1 "
            "a5 7a 96 bf e6 0d d0 11 " # inherited GUID
            "a2 85 00 aa 00 30 49 e2 "
            "01 01 "              # S-1-  (1 subauth)
            "00 00 00 00 00 01 "  #     1-
            "00 00 00 00 "        #       0
            # DACL
            "04 00 "        # dacl v4
            "10 02 "        # dacl size (528)
            "0d 00 "        # 13 aces
            "00 00 "
            "00 "           # ACCESS_ALLOWED_ACE_TYPE
            "00 "           # flags
            "24 00 "        # size
            "ff 01 0f 00 "  # mask
            "01 05 "                # S-1- (5 subauth)
            "00 00 00 00 00 05 "    #     5-
            "15 00 00 00 "          #       21-
            "51 d7 cf 86 "
            "f9 1b ef 93 "
            "c3 53 ea 70 "
            "00 02 00 00 "
            "00 "           # ACCESS_ALLOWED_ACE_TYPE
            "00 "
            "14 00 "
            "ff 01 0f 00 "
            "01 01 "                # S-1-5-18
            "00 00 00 00 00 05 "
            "12 00 00 00 "
            "00 "           # ACCESS_ALLOWED_ACE_TYPE
            "00 "
            "14 00 "
            "94 00 02 00 "
            "01 01 "                # S-1-5-11
            "00 00 00 00 00 05 "
            "0b 00 00 00 "
            "00 "           # ACCESS_ALLOWED_ACE_TYPE
            "12 "           # flags
            "24 00 "
            "ff 01 0f 00 "
            "01 05 "              # S-1-5-a-b-c-d-e
            "00 00 00 00 00 05 "
            "15 00 00 00 "
            "51 d7 cf 86 "
            "f9 1b ef 93 "
            "c3 53 ea 70 "
            "07 02 00 00 "
            "00 "           # ACCESS_ALLOWED_ACE_TYPE
            "12 "           # flags
            "18 00 "
            "bd 01 0f 00 "
            "01 02 "              # S-1-5-32-544
            "00 00 00 00 00 05 "
            "20 00 00 00 "
            "20 02 00 00 "
            "00 "           # ACCESS_ALLOWED_ACE_TYPE
            "12 "           # flags
            "18 00 "
            "04 00 00 00 "
            "01 02 "             # S-1-5-32-554
            "00 00 00 00 00 05 "
            "20 00 00 00 "
            "2a 02 00 00 "
            "05 "           # ACCESS_ALLOWED_OBJECT_ACE_TYPE
            "1a "
            "38 00 "        # size 56
            "08 00 00 00 "  # mask
            "03 00 00 00 "  # flags: object and inherited present
            "a6 6d 02 9b 3c 0d 5c 46 "  # object GUID
            "8b ee 51 99 d7 16 5c ba "
            "86 7a 96 bf e6 0d d0 11 "  # inherited GUID
            "a2 85 00 aa 00 30 49 e2 "
            "01 01 "                   # S-1-3-0
            "00 00 00 00 00 03 "
            "00 00 00 00 "
            "05 "           # ACCESS_ALLOWED_OBJECT_ACE_TYPE
            "12 "
            "28 00 "        # size 40
            "30 00 00 00 "  # mask
            "01 00 00 00 "  # flags: object present
            "e5 c3 78 3f 9a f7 bd 46 "  # object GUID
            "a0 b8 9d 18 11 6d dc 79 "
            "01 01 "                    # S-1-5-10
            "00 00 00 00 00 05 "
            "0a 00 00 00 "
            "05 "
            "12 "
            "28 00 "
            "30 01 00 00 "
            "01 00 00 00 "   # flags: object present
            "de 47 e6 91 6f d9 70 4b "  # object GUID
            "95 57 d6 3f f4 f3 cc d8 "
            "01 01 "                  # S-1-5-10
            "00 00 00 00 00 05 "
            "0a 00 00 00 "
            "05 "
            "1a "
            "38 00 "          # size 56
            "08 00 00 00 "
            "03 00 00 00 "    # flags both present
            "a6 6d 02 9b 3c 0d 5c 46 "
            "8b ee 51 99 d7 16 5c ba "
            "86 7a 96 bf e6 0d d0 11 "
            "a2 85 00 aa 00 30 49 e2 "
            "01 01 "                # S-1-5-10
            "00 00 00 00 00 05 "
            "0a 00 00 00 "
            "05 "
            "1a "
            "38 00 "              # size 56
            "20 00 00 00 "
            "03 00 00 00 "
            "93 7b 1b ea 48 5e d5 46 "
            "bc 6c 4d f4 fd a7 8a 35 "
            "86 7a 96 bf e6 0d d0 11 "
            "a2 85 00 aa 00 30 49 e2 "
            "01 01 "                # S-1-5-10
            "00 00 00 00 00 05 "
            "0a 00 00 00 "
            "05 "
            "12 "
            "38 00 "        # size 56
            "30 00 00 00 "
            "01 00 00 00 "  # only object GUI present
            "0f d6 47 5b 90 60 b2 40 "
            "9f 37 2a 4d e8 8f 30 63 "
            "01 05 "               # S-1-5-21-b-c-d-e
            "00 00 00 00 00 05 "
            "15 00 00 00 "
            "51 d7 cf 86 "
            "f9 1b ef 93 "
            "c3 53 ea 70 "
            "0e 02 00 00 "
            "05 "
            "12 "
            "38 00 "           # size 56
            "30 00 00 00 "
            "01 00 00 00 "
            "0f d6 47 5b 90 60 b2 40 "
            "9f 37 2a 4d e8 8f 30 63 "
            "01 05 "               # S-1-5-21-b-c-d-e
            "00 00 00 00 00 05 "
            "15 00 00 00 "
            "51 d7 cf 86 "
            "f9 1b ef 93 "
            "c3 53 ea 70 "
            "0f 02 00 00"
        ),
        "sd_02": (
            "01 00 17 99 14 00 00 00 30 00 00 00 4c 00 00 00 "
            "c4 00 00 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 00 02 00 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 04 00 78 00 "
            "02 00 00 00 07 5a 38 00 20 00 00 00 03 00 00 00 "
            "be 3b 0e f3 f0 9f d1 11 b6 03 00 00 f8 03 67 c1 "
            "a5 7a 96 bf e6 0d d0 11 a2 85 00 aa 00 30 49 e2 "
            "01 01 00 00 00 00 00 01 00 00 00 00 07 5a 38 00 "
            "20 00 00 00 03 00 00 00 bf 3b 0e f3 f0 9f d1 11 "
            "b6 03 00 00 f8 03 67 c1 a5 7a 96 bf e6 0d d0 11 "
            "a2 85 00 aa 00 30 49 e2 01 01 00 00 00 00 00 01 "
            "00 00 00 00 04 00 60 01 0a 00 00 00 00 0a 14 00 "
            "ff 00 0f 00 01 01 00 00 00 00 00 03 00 00 00 00 "
            "00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "0b 00 00 00 00 02 14 00 ff 00 0f 00 01 01 00 00 "
            "00 00 00 05 12 00 00 00 00 02 24 00 ff 00 0f 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 00 02 24 00 "
            "ff 00 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 07 02 00 00 "
            "00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "09 00 00 00 05 00 38 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 05 02 28 00 "
            "00 01 00 00 01 00 00 00 8f fd ac ed b3 ff d1 11 "
            "b4 1d 00 a0 c9 68 f9 39 01 01 00 00 00 00 00 05 "
            "0b 00 00 00 05 00 28 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 01 00 00 00 00 00 05 12 00 00 00 05 00 38 00 "
            "00 01 00 00 01 00 00 00 8f fd ac ed b3 ff d1 11 "
            "b4 1d 00 a0 c9 68 f9 39 01 05 00 00 00 00 00 05 "
            "15 00 00 00 51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 "
            "07 02 00 00"
        ),
        "sd_03": (
            "01 00 17 8c 14 00 00 00 30 00 00 00 4c 00 00 00 "
            "c4 00 00 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 00 02 00 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 04 00 78 00 "
            "02 00 00 00 07 5a 38 00 20 00 00 00 03 00 00 00 "
            "be 3b 0e f3 f0 9f d1 11 b6 03 00 00 f8 03 67 c1 "
            "a5 7a 96 bf e6 0d d0 11 a2 85 00 aa 00 30 49 e2 "
            "01 01 00 00 00 00 00 01 00 00 00 00 07 5a 38 00 "
            "20 00 00 00 03 00 00 00 bf 3b 0e f3 f0 9f d1 11 "
            "b6 03 00 00 f8 03 67 c1 a5 7a 96 bf e6 0d d0 11 "
            "a2 85 00 aa 00 30 49 e2 01 01 00 00 00 00 00 01 "
            "00 00 00 00 04 00 38 01 0b 00 00 00 00 00 24 00 "
            "ff 01 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 00 02 00 00 "
            "00 00 14 00 ff 01 0f 00 01 01 00 00 00 00 00 05 "
            "12 00 00 00 00 00 14 00 94 00 02 00 01 01 00 00 "
            "00 00 00 05 0b 00 00 00 00 10 24 00 ff 00 0f 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 00 1a 14 00 "
            "ff 00 0f 00 01 01 00 00 00 00 00 03 00 00 00 00 "
            "00 12 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "0b 00 00 00 00 12 14 00 ff 00 0f 00 01 01 00 00 "
            "00 00 00 05 12 00 00 00 00 12 24 00 ff 00 0f 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 00 12 24 00 "
            "ff 00 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 07 02 00 00 "
            "00 12 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "09 00 00 00 05 12 28 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 01 00 00 00 00 00 05 0b 00 00 00"
        ),
        "sd_04_object_ace_with_trailing_zeros": (
            "01 00 04 91 00 00 00 00 00 00 00 00 00 00 00 00 "
            "14 00 00 00 04 00 d0 01 0a 00 00 00 00 0a 14 00 "
            "ff 00 0f 00 01 01 00 00 00 00 00 03 00 00 00 00 "
            "00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "0b 00 00 00 00 02 14 00 ff 00 0f 00 01 01 00 00 "
            "00 00 00 05 12 00 00 00 00 02 24 00 ff 00 0f 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 00 02 24 00 "
            "ff 00 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 07 02 00 00 "
            "00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "09 00 00 00 "
            "05 "     # ACCESS_ALLOWED_OBJECT_ACE_TYPE
            "00 "     # zero flags
            "48 00 "  # size 72
            "00 01 00 00 "  # mask
            "01 00 00 00 "  # flags: object present, no inherit
            "8f fd ac ed b3 ff d1 11 "  # GUID
            "b4 1d 00 a0 c9 68 f9 39 "
            "01 01 "                    # S-1-3-0
            "00 00 00 00 00 03 "
            "00 00 00 00 "
            # next 4 rows are 32 extra bytes
            "00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 "
            "05 02 48 00 " # next ACE starts
            "00 01 00 00 01 00 00 00 8f fd ac ed b3 ff d1 11 "
            "b4 1d 00 a0 c9 68 f9 39 01 01 00 00 00 00 00 05 "
            "0b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 05 00 48 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 01 00 00 00 00 00 05 12 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 05 00 58 00 "
            "00 01 00 00 01 00 00 00 8f fd ac ed b3 ff d1 11 "
            "b4 1d 00 a0 c9 68 f9 39 01 05 00 00 00 00 00 05 "
            "15 00 00 00 51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 "
            "07 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00"
        ),
        "sd_05": (
            "01 00 17 8c 14 00 00 00 30 00 00 00 4c 00 00 00 "
            "c4 00 00 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 00 02 00 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 04 00 78 00 "
            "02 00 00 00 07 5a 38 00 20 00 00 00 03 00 00 00 "
            "be 3b 0e f3 f0 9f d1 11 b6 03 00 00 f8 03 67 c1 "
            "a5 7a 96 bf e6 0d d0 11 a2 85 00 aa 00 30 49 e2 "
            "01 01 00 00 00 00 00 01 00 00 00 00 07 5a 38 00 "
            "20 00 00 00 03 00 00 00 bf 3b 0e f3 f0 9f d1 11 "
            "b6 03 00 00 f8 03 67 c1 a5 7a 96 bf e6 0d d0 11 "
            "a2 85 00 aa 00 30 49 e2 01 01 00 00 00 00 00 01 "
            "00 00 00 00 04 00 38 01 0b 00 00 00 00 00 24 00 "
            "ff 01 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 00 02 00 00 "
            "00 00 14 00 ff 01 0f 00 01 01 00 00 00 00 00 05 "
            "12 00 00 00 00 00 14 00 94 00 02 00 01 01 00 00 "
            "00 00 00 05 0b 00 00 00 00 10 24 00 ff 00 0f 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 00 1a 14 00 "
            "ff 00 0f 00 01 01 00 00 00 00 00 03 00 00 00 00 "
            "00 12 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "0b 00 00 00 00 12 14 00 ff 00 0f 00 01 01 00 00 "
            "00 00 00 05 12 00 00 00 00 12 24 00 ff 00 0f 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 00 12 24 00 "
            "ff 00 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 07 02 00 00 "
            "00 12 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "09 00 00 00 05 12 28 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 01 00 00 00 00 00 05 0b 00 00 00"
        ),
        "sd_06": (
            "01 00 17 99 14 00 00 00 30 00 00 00 4c 00 00 00 "
            "c4 00 00 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 00 02 00 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 04 00 78 00 "
            "02 00 00 00 07 5a 38 00 20 00 00 00 03 00 00 00 "
            "be 3b 0e f3 f0 9f d1 11 b6 03 00 00 f8 03 67 c1 "
            "a5 7a 96 bf e6 0d d0 11 a2 85 00 aa 00 30 49 e2 "
            "01 01 00 00 00 00 00 01 00 00 00 00 07 5a 38 00 "
            "20 00 00 00 03 00 00 00 bf 3b 0e f3 f0 9f d1 11 "
            "b6 03 00 00 f8 03 67 c1 a5 7a 96 bf e6 0d d0 11 "
            "a2 85 00 aa 00 30 49 e2 01 01 00 00 00 00 00 01 "
            "00 00 00 00 04 00 28 01 09 00 00 00 00 0a 14 00 "
            "ff 00 0f 00 01 01 00 00 00 00 00 03 00 00 00 00 "
            "00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "0b 00 00 00 00 02 14 00 ff 00 0f 00 01 01 00 00 "
            "00 00 00 05 12 00 00 00 00 02 24 00 ff 00 0f 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 00 02 24 00 "
            "ff 00 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 07 02 00 00 "
            "00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "09 00 00 00 05 02 28 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 01 00 00 00 00 00 05 0b 00 00 00 05 00 28 00 "
            "00 01 00 00 01 00 00 00 8f fd ac ed b3 ff d1 11 "
            "b4 1d 00 a0 c9 68 f9 39 01 01 00 00 00 00 00 05 "
            "12 00 00 00 05 00 38 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 07 02 00 00"
        ),
        "sd_07_object_ace_with_trailing_zeros": (
            "01 00 04 91 00 00 00 00 00 00 00 00 00 00 00 00 "
            "14 00 00 00 04 00 88 01 09 00 00 00 00 0a 14 00 "
            "ff 00 0f 00 01 01 00 00 00 00 00 03 00 00 00 00 "
            "00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "0b 00 00 00 00 02 14 00 ff 00 0f 00 01 01 00 00 "
            "00 00 00 05 12 00 00 00 00 02 24 00 ff 00 0f 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 00 02 24 00 "
            "ff 00 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 07 02 00 00 "
            "00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "09 00 00 00 05 02 48 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 01 00 00 00 00 00 05 0b 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 05 00 48 00 "
            "00 01 00 00 01 00 00 00 8f fd ac ed b3 ff d1 11 "
            "b4 1d 00 a0 c9 68 f9 39 01 01 00 00 00 00 00 05 "
            "12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 05 00 58 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 07 02 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00"
        ),
        "sd_08": (
            "01 00 17 99 14 00 00 00 30 00 00 00 4c 00 00 00 "
            "c4 00 00 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 00 02 00 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 04 00 78 00 "
            "02 00 00 00 07 5a 38 00 20 00 00 00 03 00 00 00 "
            "be 3b 0e f3 f0 9f d1 11 b6 03 00 00 f8 03 67 c1 "
            "a5 7a 96 bf e6 0d d0 11 a2 85 00 aa 00 30 49 e2 "
            "01 01 00 00 00 00 00 01 00 00 00 00 07 5a 38 00 "
            "20 00 00 00 03 00 00 00 bf 3b 0e f3 f0 9f d1 11 "
            "b6 03 00 00 f8 03 67 c1 a5 7a 96 bf e6 0d d0 11 "
            "a2 85 00 aa 00 30 49 e2 01 01 00 00 00 00 00 01 "
            "00 00 00 00 04 00 88 01 0b 00 00 00 00 0a 14 00 "
            "ff 00 0f 00 01 01 00 00 00 00 00 03 00 00 00 00 "
            "00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "0b 00 00 00 00 02 14 00 ff 00 0f 00 01 01 00 00 "
            "00 00 00 05 12 00 00 00 00 02 24 00 ff 00 0f 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 00 02 24 00 "
            "ff 00 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 07 02 00 00 "
            "00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "09 00 00 00 05 02 28 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 01 00 00 00 00 00 05 0b 00 00 00 05 00 28 00 "
            "00 01 00 00 01 00 00 00 8f fd ac ed b3 ff d1 11 "
            "b4 1d 00 a0 c9 68 f9 39 01 01 00 00 00 00 00 05 "
            "12 00 00 00 05 00 38 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 05 00 38 00 "
            "00 01 00 00 01 00 00 00 8f fd ac ed b3 ff d1 11 "
            "b4 1d 00 a0 c9 68 f9 39 01 05 00 00 00 00 00 05 "
            "15 00 00 00 51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 "
            "07 02 00 00 05 00 28 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 01 00 00 00 00 00 05 09 00 00 00"
        ),

        "sd_09": (
            "01 00 17 99 14 00 00 00 30 00 00 00 4c 00 00 00 "
            "c4 00 00 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 00 02 00 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 04 00 78 00 "
            "02 00 00 00 07 5a 38 00 20 00 00 00 03 00 00 00 "
            "be 3b 0e f3 f0 9f d1 11 b6 03 00 00 f8 03 67 c1 "
            "a5 7a 96 bf e6 0d d0 11 a2 85 00 aa 00 30 49 e2 "
            "01 01 00 00 00 00 00 01 00 00 00 00 07 5a 38 00 "
            "20 00 00 00 03 00 00 00 bf 3b 0e f3 f0 9f d1 11 "
            "b6 03 00 00 f8 03 67 c1 a5 7a 96 bf e6 0d d0 11 "
            "a2 85 00 aa 00 30 49 e2 01 01 00 00 00 00 00 01 "
            "00 00 00 00 04 00 60 01 0a 00 00 00 00 0a 14 00 "
            "ff 00 0f 00 01 01 00 00 00 00 00 03 00 00 00 00 "
            "00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "0b 00 00 00 00 02 14 00 ff 00 0f 00 01 01 00 00 "
            "00 00 00 05 12 00 00 00 00 02 24 00 ff 00 0f 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 00 02 24 00 "
            "ff 00 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 07 02 00 00 "
            "00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "09 00 00 00 05 02 28 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 01 00 00 00 00 00 05 0b 00 00 00 05 00 28 00 "
            "00 01 00 00 01 00 00 00 8f fd ac ed b3 ff d1 11 "
            "b4 1d 00 a0 c9 68 f9 39 01 01 00 00 00 00 00 05 "
            "12 00 00 00 05 00 38 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 05 00 38 00 "
            "00 01 00 00 01 00 00 00 8f fd ac ed b3 ff d1 11 "
            "b4 1d 00 a0 c9 68 f9 39 01 05 00 00 00 00 00 05 "
            "15 00 00 00 51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 "
            "07 02 00 00"
        ),
        "sd_10_object_ace_with_trailing_zeros": (
            "01 00 04 91 00 00 00 00 00 00 00 00 00 00 00 00 "
            "14 00 00 00 04 00 28 02 0b 00 00 00 00 0a 14 00 "
            "ff 00 0f 00 01 01 00 00 00 00 00 03 00 00 00 00 "
            "00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "0b 00 00 00 00 02 14 00 ff 00 0f 00 01 01 00 00 "
            "00 00 00 05 12 00 00 00 00 02 24 00 ff 00 0f 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 00 02 24 00 "
            "ff 00 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 07 02 00 00 "
            "00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "09 00 00 00 05 02 48 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 01 00 00 00 00 00 05 0b 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 05 00 48 00 "
            "00 01 00 00 01 00 00 00 8f fd ac ed b3 ff d1 11 "
            "b4 1d 00 a0 c9 68 f9 39 01 01 00 00 00 00 00 05 "
            "12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 05 00 58 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 05 00 58 00 "
            "00 01 00 00 01 00 00 00 8f fd ac ed b3 ff d1 11 "
            "b4 1d 00 a0 c9 68 f9 39 01 05 00 00 00 00 00 05 "
            "15 00 00 00 51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 "
            "07 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 05 00 48 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 01 00 00 00 00 00 05 09 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00"
        ),
        "sd_11": (
            "01 00 17 99 14 00 00 00 30 00 00 00 4c 00 00 00 "
            "c4 00 00 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 00 02 00 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 04 00 78 00 "
            "02 00 00 00 07 5a 38 00 20 00 00 00 03 00 00 00 "
            "be 3b 0e f3 f0 9f d1 11 b6 03 00 00 f8 03 67 c1 "
            "a5 7a 96 bf e6 0d d0 11 a2 85 00 aa 00 30 49 e2 "
            "01 01 00 00 00 00 00 01 00 00 00 00 07 5a 38 00 "
            "20 00 00 00 03 00 00 00 bf 3b 0e f3 f0 9f d1 11 "
            "b6 03 00 00 f8 03 67 c1 a5 7a 96 bf e6 0d d0 11 "
            "a2 85 00 aa 00 30 49 e2 01 01 00 00 00 00 00 01 "
            "00 00 00 00 04 00 28 01 09 00 00 00 00 0a 14 00 "
            "ff 00 0f 00 01 01 00 00 00 00 00 03 00 00 00 00 "
            "00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "0b 00 00 00 00 02 14 00 ff 00 0f 00 01 01 00 00 "
            "00 00 00 05 12 00 00 00 00 02 24 00 ff 00 0f 00 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 00 02 00 00 00 02 24 00 "
            "ff 00 0f 00 01 05 00 00 00 00 00 05 15 00 00 00 "
            "51 d7 cf 86 f9 1b ef 93 c3 53 ea 70 07 02 00 00 "
            "00 02 14 00 94 00 02 00 01 01 00 00 00 00 00 05 "
            "09 00 00 00 05 02 28 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 01 00 00 00 00 00 05 0b 00 00 00 05 00 28 00 "
            "00 01 00 00 01 00 00 00 8f fd ac ed b3 ff d1 11 "
            "b4 1d 00 a0 c9 68 f9 39 01 01 00 00 00 00 00 05 "
            "12 00 00 00 05 00 38 00 00 01 00 00 01 00 00 00 "
            "8f fd ac ed b3 ff d1 11 b4 1d 00 a0 c9 68 f9 39 "
            "01 05 00 00 00 00 00 05 15 00 00 00 51 d7 cf 86 "
            "f9 1b ef 93 c3 53 ea 70 07 02 00 00"
        ),
    }


if __name__ == '__main__':
    import unittest
    unittest.main()
