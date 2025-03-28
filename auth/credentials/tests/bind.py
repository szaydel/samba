#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This is unit with tests for LDAP access checks

import optparse
import sys
import base64
import copy

sys.path.insert(0, "bin/python")
import samba
from samba.tests.subunitrun import SubunitOptions, TestProgram

import samba.getopt as options

from ldb import SCOPE_BASE, SCOPE_SUBTREE, LdbError, ERR_INVALID_CREDENTIALS

from samba import gensec
import samba.tests
from samba.tests import delete_force
from samba.credentials import Credentials

def create_credential(lp, other):
    c = Credentials()
    c.guess(lp)
    c.set_gensec_features(other.get_gensec_features())
    return c

parser = optparse.OptionParser("bind [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)
opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]
lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)
creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

creds_machine = create_credential(lp, creds)
creds_virtual = create_credential(lp, creds)
creds_user1 = create_credential(lp, creds)
creds_user2 = create_credential(lp, creds)
creds_user3 = create_credential(lp, creds)
creds_user4 = create_credential(lp, creds)
creds_user5 = create_credential(lp, creds)
creds_user6 = create_credential(lp, creds)
creds_user7 = create_credential(lp, creds)

class BindTests(samba.tests.TestCase):

    info_dc = None

    def setUp(self):
        super(BindTests, self).setUp()
        # fetch rootDSEs

        self.ldb = samba.tests.connect_samdb(host, credentials=creds, lp=lp, ldap_only=True)

        if self.info_dc is None:
            res = self.ldb.search(base="", expression="", scope=SCOPE_BASE, attrs=["*"])
            self.assertEqual(len(res), 1)
            BindTests.info_dc = res[0]
        # cache some of RootDSE props
        self.schema_dn = self.info_dc["schemaNamingContext"][0]
        self.domain_dn = self.info_dc["defaultNamingContext"][0]
        self.config_dn = self.info_dc["configurationNamingContext"][0]
        self.realm = self.info_dc["ldapServiceName"][0].split(b'@')[1].decode('utf-8')
        self.computer_dn = "CN=centos53,CN=Computers,%s" % self.domain_dn
        self.virtual_user_dn = "CN=frednurk@%s,CN=Computers,%s" % (self.realm, self.domain_dn)
        self.password = "P@ssw0rd"
        self.username = "BindTestUser"

    def tearDown(self):
        delete_force(self.ldb, self.virtual_user_dn)
        super(BindTests, self).tearDown()

    def test_virtual_email_account_style_bind(self):
        # create a user in the style often deployed for authentication
        # of virtual email account at a hosting provider
        #
        # The userPrincipalName must not match the samAccountName for
        # this test to detect when the LDAP DN is being double-parsed
        # but must be in the user@realm style to allow the account to
        # be created
        try:
            self.ldb.add_ldif("""
dn: """ + self.virtual_user_dn + """
cn: frednurk@""" + self.realm + """
displayName: Fred Nurk
sAMAccountName: frednurk@""" + self.realm + """
userPrincipalName: frednurk@NOT.""" + self.realm + """
countryCode: 0
objectClass: computer
objectClass: organizationalPerson
objectClass: person
objectClass: top
objectClass: user
""")
        except LdbError as e:
            (num, msg) = e.args
            self.fail(f"Failed to create e-mail user: {msg}")

        self.addCleanup(delete_force, self.ldb, self.virtual_user_dn)
        try:
            self.ldb.modify_ldif("""
dn: """ + self.virtual_user_dn + """
changetype: modify
replace: unicodePwd
unicodePwd:: """ + base64.b64encode(u"\"P@ssw0rd\"".encode('utf-16-le')).decode('utf8') + """
""")
        except LdbError as e:
            (num, msg) = e.args
            self.fail(f"Failed to set password on e-mail user: {msg}")

        self.ldb.enable_account('distinguishedName=%s' % self.virtual_user_dn)

        # do a simple bind and search with the machine account
        creds_virtual.set_bind_dn(self.virtual_user_dn)
        creds_virtual.set_password(self.password)
        print("BindTest with: " + creds_virtual.get_bind_dn())
        try:
            ldb_virtual = samba.tests.connect_samdb(host, credentials=creds_virtual,
                                                    lp=lp, ldap_only=True)
        except LdbError as e:
            (num, msg) = e.args
            if num != ERR_INVALID_CREDENTIALS:
                raise
            self.fail(msg)

        res = ldb_virtual.search(base="", expression="", scope=SCOPE_BASE, attrs=["*"])

    def test_computer_account_bind(self):
        # create a computer account for the test
        delete_force(self.ldb, self.computer_dn)
        self.ldb.add_ldif("""
dn: """ + self.computer_dn + """
cn: CENTOS53
displayName: CENTOS53$
name: CENTOS53
sAMAccountName: CENTOS53$
countryCode: 0
objectClass: computer
objectClass: organizationalPerson
objectClass: person
objectClass: top
objectClass: user
codePage: 0
userAccountControl: 4096
dNSHostName: centos53.alabala.test
operatingSystemVersion: 5.2 (3790)
operatingSystem: Windows Server 2003
""")
        self.ldb.modify_ldif("""
dn: """ + self.computer_dn + """
changetype: modify
replace: unicodePwd
unicodePwd:: """ + base64.b64encode(u"\"P@ssw0rd\"".encode('utf-16-le')).decode('utf8') + """
""")

        # do a simple bind and search with the machine account
        creds_machine.set_bind_dn(self.computer_dn)
        creds_machine.set_password(self.password)
        print("BindTest with: " + creds_machine.get_bind_dn())
        ldb_machine = samba.tests.connect_samdb(host, credentials=creds_machine,
                                                lp=lp, ldap_only=True)
        res = ldb_machine.search(base="", expression="", scope=SCOPE_BASE, attrs=["*"])

    def test_user_account_bind(self):
        # create user
        self.ldb.newuser(username=self.username, password=self.password)
        ldb_res = self.ldb.search(base=self.domain_dn,
                                  scope=SCOPE_SUBTREE,
                                  expression="(samAccountName=%s)" % self.username,
                                  attrs=["objectSid"])
        self.assertEqual(len(ldb_res), 1)
        user_dn = ldb_res[0]["dn"]
        self.addCleanup(delete_force, self.ldb, user_dn)

        # do a simple bind and search with the user account in format user@realm
        creds_user1.set_bind_dn(self.username + "@" + creds.get_realm())
        creds_user1.set_password(self.password)
        print("BindTest with: " + creds_user1.get_bind_dn())
        ldb_user1 = samba.tests.connect_samdb(host, credentials=creds_user1,
                                              lp=lp, ldap_only=True)
        res = ldb_user1.search(base="", expression="", scope=SCOPE_BASE, attrs=["*"])

        # do a simple bind and search with the user account in format domain\user
        creds_user2.set_bind_dn(creds.get_domain() + "\\" + self.username)
        creds_user2.set_password(self.password)
        print("BindTest with: " + creds_user2.get_bind_dn())
        ldb_user2 = samba.tests.connect_samdb(host, credentials=creds_user2,
                                              lp=lp, ldap_only=True)
        res = ldb_user2.search(base="", expression="", scope=SCOPE_BASE, attrs=["*"])

        # do a simple bind and search with the user account DN
        creds_user3.set_bind_dn(str(user_dn))
        creds_user3.set_password(self.password)
        print("BindTest with: " + creds_user3.get_bind_dn())
        ldb_user3 = samba.tests.connect_samdb(host, credentials=creds_user3,
                                              lp=lp, ldap_only=True)
        res = ldb_user3.search(base="", expression="", scope=SCOPE_BASE, attrs=["*"])

        # do a simple bind and search with the user account SID
        creds_user5.set_bind_dn(self.ldb.schema_format_value("objectSid", ldb_res[0]["objectSid"][0]).decode('utf8'))
        creds_user5.set_password(self.password)
        print("BindTest with: " + creds_user5.get_bind_dn())
        ldb_user5 = samba.tests.connect_samdb(host, credentials=creds_user5,
                                              lp=lp, ldap_only=True)
        res = ldb_user5.search(base="", expression="", scope=SCOPE_BASE, attrs=["*"])

        # do a simple bind and search with the canonical name
        creds_user6.set_bind_dn(user_dn.canonical_str())
        creds_user6.set_password(self.password)
        print("BindTest with: " + creds_user6.get_bind_dn())
        ldb_user6 = samba.tests.connect_samdb(host, credentials=creds_user6,
                                              lp=lp, ldap_only=True)
        res = ldb_user6.search(base="", expression="", scope=SCOPE_BASE, attrs=["*"])

        # do a simple bind and search with the extended canonical name
        creds_user7.set_bind_dn(user_dn.canonical_ex_str())
        creds_user7.set_password(self.password)
        print("BindTest with: " + creds_user7.get_bind_dn())
        ldb_user7 = samba.tests.connect_samdb(host, credentials=creds_user7,
                                              lp=lp, ldap_only=True)
        res = ldb_user7.search(base="", expression="", scope=SCOPE_BASE, attrs=["*"])

    def test_user_account_bind_no_domain(self):
        # create user
        self.ldb.newuser(username=self.username, password=self.password)
        ldb_res = self.ldb.search(base=self.domain_dn,
                                  scope=SCOPE_SUBTREE,
                                  expression="(samAccountName=%s)" % self.username)
        self.assertEqual(len(ldb_res), 1)
        user_dn = ldb_res[0]["dn"]
        self.addCleanup(delete_force, self.ldb, user_dn)

        creds_user4.set_username(self.username)
        creds_user4.set_password(self.password)
        creds_user4.set_domain('')
        creds_user4.set_workstation('')
        print("BindTest (no domain) with: " + self.username)
        try:
            ldb_user4 = samba.tests.connect_samdb(host, credentials=creds_user4,
                                                  lp=lp, ldap_only=True)
        except:
            self.fail("Failed to connect without the domain set")

        res = ldb_user4.search(base="", expression="", scope=SCOPE_BASE, attrs=["*"])


TestProgram(module=__name__, opts=subunitopts)
