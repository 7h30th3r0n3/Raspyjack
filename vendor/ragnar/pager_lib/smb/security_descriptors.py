"""
This module implements security descriptors, and the partial structures
used in them, as specified in [MS-DTYP].
"""

import struct


# Security descriptor control flags
# [MS-DTYP]: 2.4.6
SECURITY_DESCRIPTOR_OWNER_DEFAULTED = 0x0001
SECURITY_DESCRIPTOR_GROUP_DEFAULTED = 0x0002
SECURITY_DESCRIPTOR_DACL_PRESENT = 0x0004
SECURITY_DESCRIPTOR_DACL_DEFAULTED = 0x0008
SECURITY_DESCRIPTOR_SACL_PRESENT = 0x0010
SECURITY_DESCRIPTOR_SACL_DEFAULTED = 0x0020
SECURITY_DESCRIPTOR_SERVER_SECURITY = 0x0040
SECURITY_DESCRIPTOR_DACL_TRUSTED = 0x0080
SECURITY_DESCRIPTOR_DACL_COMPUTED_INHERITANCE_REQUIRED = 0x0100
SECURITY_DESCRIPTOR_SACL_COMPUTED_INHERITANCE_REQUIRED = 0x0200
SECURITY_DESCRIPTOR_DACL_AUTO_INHERITED = 0x0400
SECURITY_DESCRIPTOR_SACL_AUTO_INHERITED = 0x0800
SECURITY_DESCRIPTOR_DACL_PROTECTED = 0x1000
SECURITY_DESCRIPTOR_SACL_PROTECTED = 0x2000
SECURITY_DESCRIPTOR_RM_CONTROL_VALID = 0x4000
SECURITY_DESCRIPTOR_SELF_RELATIVE = 0x8000

# ACE types
# [MS-DTYP]: 2.4.4.1
ACE_TYPE_ACCESS_ALLOWED = 0x00
ACE_TYPE_ACCESS_DENIED = 0x01
ACE_TYPE_SYSTEM_AUDIT = 0x02
ACE_TYPE_SYSTEM_ALARM = 0x03
ACE_TYPE_ACCESS_ALLOWED_COMPOUND = 0x04
ACE_TYPE_ACCESS_ALLOWED_OBJECT = 0x05
ACE_TYPE_ACCESS_DENIED_OBJECT = 0x06
ACE_TYPE_SYSTEM_AUDIT_OBJECT = 0x07
ACE_TYPE_SYSTEM_ALARM_OBJECT = 0x08
ACE_TYPE_ACCESS_ALLOWED_CALLBACK = 0x09
ACE_TYPE_ACCESS_DENIED_CALLBACK = 0x0A
ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT = 0x0B
ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT = 0x0C
ACE_TYPE_SYSTEM_AUDIT_CALLBACK = 0x0D
ACE_TYPE_SYSTEM_ALARM_CALLBACK = 0x0E
ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT = 0x0F
ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT = 0x10
ACE_TYPE_SYSTEM_MANDATORY_LABEL = 0x11
ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE = 0x12
ACE_TYPE_SYSTEM_SCOPED_POLICY_ID = 0x13

# ACE flags
# [MS-DTYP]: 2.4.4.1
ACE_FLAG_OBJECT_INHERIT = 0x01
ACE_FLAG_CONTAINER_INHERIT = 0x02
ACE_FLAG_NO_PROPAGATE_INHERIT = 0x04
ACE_FLAG_INHERIT_ONLY = 0x08
ACE_FLAG_INHERITED = 0x10
ACE_FLAG_SUCCESSFUL_ACCESS = 0x40
ACE_FLAG_FAILED_ACCESS = 0x80

# Pre-defined well-known SIDs
# [MS-DTYP]: 2.4.2.4
SID_NULL = "S-1-0-0"
SID_EVERYONE = "S-1-1-0"
SID_LOCAL = "S-1-2-0"
SID_CONSOLE_LOGON = "S-1-2-1"
SID_CREATOR_OWNER = "S-1-3-0"
SID_CREATOR_GROUP = "S-1-3-1"
SID_OWNER_SERVER = "S-1-3-2"
SID_GROUP_SERVER = "S-1-3-3"
SID_OWNER_RIGHTS = "S-1-3-4"
SID_NT_AUTHORITY = "S-1-5"
SID_DIALUP = "S-1-5-1"
SID_NETWORK = "S-1-5-2"
SID_BATCH = "S-1-5-3"
SID_INTERACTIVE = "S-1-5-4"
SID_SERVICE = "S-1-5-6"
SID_ANONYMOUS = "S-1-5-7"
SID_PROXY = "S-1-5-8"
SID_ENTERPRISE_DOMAIN_CONTROLLERS = "S-1-5-9"
SID_PRINCIPAL_SELF = "S-1-5-10"
SID_AUTHENTICATED_USERS = "S-1-5-11"
SID_RESTRICTED_CODE = "S-1-5-12"
SID_TERMINAL_SERVER_USER = "S-1-5-13"
SID_REMOTE_INTERACTIVE_LOGON = "S-1-5-14"
SID_THIS_ORGANIZATION = "S-1-5-15"
SID_IUSR = "S-1-5-17"
SID_LOCAL_SYSTEM = "S-1-5-18"
SID_LOCAL_SERVICE = "S-1-5-19"
SID_NETWORK_SERVICE = "S-1-5-20"
SID_COMPOUNDED_AUTHENTICATION = "S-1-5-21-0-0-0-496"
SID_CLAIMS_VALID = "S-1-5-21-0-0-0-497"
SID_BUILTIN_ADMINISTRATORS = "S-1-5-32-544"
SID_BUILTIN_USERS = "S-1-5-32-545"
SID_BUILTIN_GUESTS = "S-1-5-32-546"
SID_POWER_USERS = "S-1-5-32-547"
SID_ACCOUNT_OPERATORS = "S-1-5-32-548"
SID_SERVER_OPERATORS = "S-1-5-32-549"
SID_PRINTER_OPERATORS = "S-1-5-32-550"
SID_BACKUP_OPERATORS = "S-1-5-32-551"
SID_REPLICATOR = "S-1-5-32-552"
SID_ALIAS_PREW2KCOMPACC = "S-1-5-32-554"
SID_REMOTE_DESKTOP = "S-1-5-32-555"
SID_NETWORK_CONFIGURATION_OPS = "S-1-5-32-556"
SID_INCOMING_FOREST_TRUST_BUILDERS = "S-1-5-32-557"
SID_PERFMON_USERS = "S-1-5-32-558"
SID_PERFLOG_USERS = "S-1-5-32-559"
SID_WINDOWS_AUTHORIZATION_ACCESS_GROUP = "S-1-5-32-560"
SID_TERMINAL_SERVER_LICENSE_SERVERS = "S-1-5-32-561"
SID_DISTRIBUTED_COM_USERS = "S-1-5-32-562"
SID_IIS_IUSRS = "S-1-5-32-568"
SID_CRYPTOGRAPHIC_OPERATORS = "S-1-5-32-569"
SID_EVENT_LOG_READERS = "S-1-5-32-573"
SID_CERTIFICATE_SERVICE_DCOM_ACCESS = "S-1-5-32-574"
SID_RDS_REMOTE_ACCESS_SERVERS = "S-1-5-32-575"
SID_RDS_ENDPOINT_SERVERS = "S-1-5-32-576"
SID_RDS_MANAGEMENT_SERVERS = "S-1-5-32-577"
SID_HYPER_V_ADMINS = "S-1-5-32-578"
SID_ACCESS_CONTROL_ASSISTANCE_OPS = "S-1-5-32-579"
SID_REMOTE_MANAGEMENT_USERS = "S-1-5-32-580"
SID_WRITE_RESTRICTED_CODE = "S-1-5-33"
SID_NTLM_AUTHENTICATION = "S-1-5-64-10"
SID_SCHANNEL_AUTHENTICATION = "S-1-5-64-14"
SID_DIGEST_AUTHENTICATION = "S-1-5-64-21"
SID_THIS_ORGANIZATION_CERTIFICATE = "S-1-5-65-1"
SID_NT_SERVICE = "S-1-5-80"
SID_USER_MODE_DRIVERS = "S-1-5-84-0-0-0-0-0"
SID_LOCAL_ACCOUNT = "S-1-5-113"
SID_LOCAL_ACCOUNT_AND_MEMBER_OF_ADMINISTRATORS_GROUP = "S-1-5-114"
SID_OTHER_ORGANIZATION = "S-1-5-1000"
SID_ALL_APP_PACKAGES = "S-1-15-2-1"
SID_ML_UNTRUSTED = "S-1-16-0"
SID_ML_LOW = "S-1-16-4096"
SID_ML_MEDIUM = "S-1-16-8192"
SID_ML_MEDIUM_PLUS = "S-1-16-8448"
SID_ML_HIGH = "S-1-16-12288"
SID_ML_SYSTEM = "S-1-16-16384"
SID_ML_PROTECTED_PROCESS = "S-1-16-20480"
SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY = "S-1-18-1"
SID_SERVICE_ASSERTED_IDENTITY = "S-1-18-2"
SID_FRESH_PUBLIC_KEY_IDENTITY = "S-1-18-3"
SID_KEY_TRUST_IDENTITY = "S-1-18-4"
SID_KEY_PROPERTY_MFA = "S-1-18-5"
SID_KEY_PROPERTY_ATTESTATION = "S-1-18-6"


class SID(object):
    """
    A Windows security identifier. Represents a single principal, such a
    user or a group, as a sequence of numbers consisting of the revision,
    identifier authority, and a variable-length list of subauthorities.

    See [MS-DTYP]: 2.4.2
    """
    def __init__(self, revision, identifier_authority, subauthorities):
        #: Revision, should always be 1.
        self.revision = revision
        #: An integer representing the identifier authority.
        self.identifier_authority = identifier_authority
        #: A list of integers representing all subauthorities.
        self.subauthorities = subauthorities

    def __str__(self):
        """
        String representation, as specified in [MS-DTYP]: 2.4.2.1
        """
        if self.identifier_authority >= 2**32:
            id_auth = '%#x' % (self.identifier_authority,)
        else:
            id_auth = self.identifier_authority
        auths = [self.revision, id_auth] + self.subauthorities
        return 'S-' + '-'.join(str(subauth) for subauth in auths)

    def __repr__(self):
        return 'SID(%r)' % (str(self),)

    @classmethod
    def from_bytes(cls, data, return_tail=False):
        revision, subauth_count = struct.unpack('<BB', data[:2])
        identifier_authority = struct.unpack('>Q', b'\x00\x00' + data[2:8])[0]
        subauth_data = data[8:]
        subauthorities = [struct.unpack('<L', subauth_data[4 * i : 4 * (i+1)])[0]
                          for i in range(subauth_count)]
        sid = cls(revision, identifier_authority, subauthorities)
        if return_tail:
            return sid, subauth_data[4 * subauth_count :]
        return sid


class ACE(object):
    """
    Represents a single access control entry.

    See [MS-DTYP]: 2.4.4
    """
    HEADER_FORMAT = '<BBH'

    def __init__(self, type_, flags, mask, sid, additional_data):
        #: An integer representing the type of the ACE. One of the
        #: ``ACE_TYPE_*`` constants. Corresponds to the ``AceType`` field
        #: from [MS-DTYP] 2.4.4.1.
        self.type = type_
        #: An integer bitmask with ACE flags, corresponds to the
        #: ``AceFlags`` field.
        self.flags = flags
        #: An integer representing the ``ACCESS_MASK`` as specified in
        #: [MS-DTYP] 2.4.3.
        self.mask = mask
        #: The :class:`SID` of a trustee.
        self.sid = sid
        #: A dictionary of additional fields present in the ACE, depending
        #: on the type. The following fields can be present:
        #:
        #: * ``flags``
        #: * ``object_type``
        #: * ``inherited_object_type``
        #: * ``application_data``
        #: * ``attribute_data``
        self.additional_data = additional_data

    def __repr__(self):
        return "ACE(type=%#04x, flags=%#04x, mask=%#010x, sid=%s)" % (
            self.type, self.flags, self.mask, self.sid,
        )

    @property
    def isInheritOnly(self):
        """Convenience property which indicates if this ACE is inherit
        only, meaning that it doesn't apply to the object itself."""
        return bool(self.flags & ACE_FLAG_INHERIT_ONLY)

    @classmethod
    def from_bytes(cls, data):
        header_size = struct.calcsize(cls.HEADER_FORMAT)
        header = data[:header_size]
        type_, flags, size = struct.unpack(cls.HEADER_FORMAT, header)

        assert len(data) >= size

        body = data[header_size:size]
        additional_data = {}

        # In all ACE types, the mask immediately follows the header.
        mask = struct.unpack('<I', body[:4])[0]
        body = body[4:]

        # All OBJECT-type ACEs contain additional flags, and two GUIDs as
        # the following fields.
        if type_ in (ACE_TYPE_ACCESS_ALLOWED_OBJECT,
                     ACE_TYPE_ACCESS_DENIED_OBJECT,
                     ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
                     ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT,
                     ACE_TYPE_SYSTEM_AUDIT_OBJECT,
                     ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT):
            additional_data['flags'] = struct.unpack('<I', body[:4])[0]
            additional_data['object_type'] = body[4:20]
            additional_data['inherited_object_type'] = body[20:36]
            body = body[36:]

        # Then the SID in all types.
        sid, body = SID.from_bytes(body, return_tail=True)

        # CALLBACK-type ACEs (and for some obscure reason,
        # SYSTEM_AUDIT_OBJECT) have a final tail of application data.
        if type_ in (ACE_TYPE_ACCESS_ALLOWED_CALLBACK,
                     ACE_TYPE_ACCESS_DENIED_CALLBACK,
                     ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
                     ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT,
                     ACE_TYPE_SYSTEM_AUDIT_OBJECT,
                     ACE_TYPE_SYSTEM_AUDIT_CALLBACK,
                     ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT):
            additional_data['application_data'] = body

        # SYSTEM_RESOURCE_ATTRIBUTE ACEs have a tail of attribute data.
        if type_ == ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE:
            additional_data['attribute_data'] = body

        return cls(type_, flags, mask, sid, additional_data)


class ACL(object):
    """
    Access control list, encapsulating a sequence of access control
    entries.

    See [MS-DTYP]: 2.4.5
    """
    HEADER_FORMAT = '<BBHHH'

    def __init__(self, revision, aces):
        #: Integer value of the revision.
        self.revision = revision
        #: List of :class:`ACE` instances.
        self.aces = aces

    def __repr__(self):
        return "ACL(%r)" % (self.aces,)

    @classmethod
    def from_bytes(cls, data):
        revision = None
        aces = []

        header_size = struct.calcsize(cls.HEADER_FORMAT)
        header, remaining = data[:header_size], data[header_size:]
        revision, sbz1, size, count, sbz2 = struct.unpack(cls.HEADER_FORMAT, header)

        assert len(data) >= size

        for i in range(count):
            ace_size = struct.unpack('<H', remaining[2:4])[0]
            ace_data, remaining = remaining[:ace_size], remaining[ace_size:]
            aces.append(ACE.from_bytes(ace_data))

        return cls(revision, aces)


class SecurityDescriptor(object):
    """
    Represents a security descriptor.

    See [MS-DTYP]: 2.4.6
    """

    HEADER_FORMAT = '<BBHIIII'

    def __init__(self, flags, owner, group, dacl, sacl):
        #: Integer bitmask of control flags. Corresponds to the
        #: ``Control`` field in [MS-DTYP] 2.4.6.
        self.flags = flags
        #: Instance of :class:`SID` representing the owner user.
        self.owner = owner
        #: Instance of :class:`SID` representing the owner group.
        self.group = group
        #: Instance of :class:`ACL` representing the discretionary access
        #: control list, which specifies access restrictions of an object.
        self.dacl = dacl
        #: Instance of :class:`ACL` representing the system access control
        #: list, which specifies audit logging of an object.
        self.sacl = sacl

    @classmethod
    def from_bytes(cls, data):
        owner = None
        group = None
        dacl = None
        sacl = None

        header = data[:struct.calcsize(cls.HEADER_FORMAT)]
        (revision, sbz1, flags, owner_offset, group_offset, sacl_offset,
         dacl_offset) = struct.unpack(cls.HEADER_FORMAT, header)

        assert revision == 1
        assert flags & SECURITY_DESCRIPTOR_SELF_RELATIVE
        for offset in (owner_offset, group_offset, sacl_offset, dacl_offset):
            assert 0 <= offset < len(data)

        if owner_offset:
            owner = SID.from_bytes(data[owner_offset:])
        if group_offset:
            group = SID.from_bytes(data[group_offset:])
        if dacl_offset:
            dacl = ACL.from_bytes(data[dacl_offset:])
        if sacl_offset:
            sacl = ACL.from_bytes(data[sacl_offset:])

        return cls(flags, owner, group, dacl, sacl)
