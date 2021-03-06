from struct import pack, unpack
from netaddr import IPAddress, IPNetwork
from collections import OrderedDict

AUTH_REQUEST = 1  # Access-Request
AUTH_ACCEPT = 2  # Access-Accept
AUTH_REJECT = 3  # Access-Reject
ACCT_REQUEST = 4  # Accounting-Request
ACCT_RESPONSE = 5  # Accounting-Response
AUTH_CHALLENGE = 11  # Access-Challenge
STATUS_SERVER = 12
STATUS_CLIENT = 13
RESERVED = 255

CODES = {
    1: 'AUTH_REQUEST',
    2: 'AUTH_ACCEPT',
    3: 'AUTH_REJECT',
    4: 'ACCT_REQUEST',
    5: 'ACCT_RESPONSE',
    11: 'AUTH_CHALLENGE',
    12: 'STATUS_SERVER',
    13: 'STATUS_CLIENT',
    255: 'RESERVED'
}


class Attributes:
    # https://tools.ietf.org/html/rfc2865
    # https://www.iana.org/assignments/radius-types/radius-types.txt
    CODED = {
        1: ("User-Name", "text"),  # length: >= 3
        2: ("User-Password", "string"),  # length: 18 - 130
        3: ("CHAP-Password", "string"),  # length: == 19
        4: ("NAS-IP-Address", "ipv4addr"),
        5: ("NAS-Port", "integer"),
        6: ("Service-Type", "enum"),
        7: ("Framed-Protocol", "enum"),
        8: ("Framed-IP-Address", "ipv4addr"),
        9: ("Framed-IP-Netmask", "ipv4addr"),
        10: ("Framed-Routing", "enum"),
        11: ("Filter-Id", "text"),
        12: ("Framed-MTU", "integer"),
        13: ("Framed-Compression", "enum"),
        14: ("Login-IP-Host", "ipv4addr"),
        15: ("Login-Service", "enum"),
        16: ("Login-TCP-Port", "integer"),
        18: ("Reply-Message", "text"),  # length: >= 3
        19: ("Callback-Number", "text"),
        20: ("Callback-Id", "text"),
        22: ("Framed-Route", "text"),
        23: ("Framed-IPX-Network", "ipv4addr"),
        24: ("State", "string"),
        25: ("Class", "string"),
        26: ("Vendor-Specific", "vsa"),
        27: ("Session-Timeout", "integer"),
        28: ("Idle-Timeout", "integer"),
        29: ("Termination-Action", "enum"),
        30: ("Called-Station-Id", "text"),
        31: ("Calling-Station-Id", "text"),
        32: ("NAS-Identifier", "text"),
        33: ("Proxy-State", "string"),
        34: ("Login-LAT-Service", "text"),
        35: ("Login-LAT-Node", "text"),
        36: ("Login-LAT-Group", "string"),
        37: ("Framed-AppleTalk-Link", "integer"),
        38: ("Framed-AppleTalk-Network", "integer"),
        39: ("Framed-AppleTalk-Zone", "text"),
        40: ("Acct-Status-Type", "enum"),
        41: ("Acct-Delay-Time", "integer"),
        42: ("Acct-Input-Octets", "integer"),
        43: ("Acct-Output-Octets", "integer"),
        44: ("Acct-Session-Id", "text"),
        45: ("Acct-Authentic", "enum"),
        46: ("Acct-Session-Time", "integer"),
        47: ("Acct-Input-Packets", "integer"),
        48: ("Acct-Output-Packets", "integer"),
        49: ("Acct-Terminate-Cause", "enum"),
        50: ("Acct-Multi-Session-Id", "text"),
        51: ("Acct-Link-Count", "integer"),
        52: ("Acct-Input-Gigawords", "integer"),
        53: ("Acct-Output-Gigawords", "integer"),
        55: ("Event-Timestamp", "time"),
        56: ("Egress-VLANID", "integer"),
        57: ("Ingress-Filters", "enum"),
        58: ("Egress-VLAN-Name", "text"),
        59: ("User-Priority-Table", "string"),
        60: ("CHAP-Challenge", "string"),
        61: ("NAS-Port-Type", "enum"),
        62: ("Port-Limit", "integer"),
        63: ("Login-LAT-Port", "text"),
        64: ("Tunnel-Type", "enum"),
        65: ("Tunnel-Medium-Type", "enum"),
        66: ("Tunnel-Client-Endpoint", "text"),
        67: ("Tunnel-Server-Endpoint", "text"),
        68: ("Acct-Tunnel-Connection", "text"),
        69: ("Tunnel-Password", "string"),
        70: ("ARAP-Password", "string"),
        71: ("ARAP-Features", "string"),
        72: ("ARAP-Zone-Access", "enum"),
        73: ("ARAP-Security", "integer"),
        74: ("ARAP-Security-Data", "text"),
        75: ("Password-Retry", "integer"),
        76: ("Prompt", "enum"),
        # TODO: enum missing for below
        77: ("Connect-Info", "text"),
        78: ("Configuration-Token", "text"),
        79: ("EAP-Message", "concat"),
        80: ("Message-Authenticator", "string"),
        81: ("Tunnel-Private-Group-ID", "text"),
        82: ("Tunnel-Assignment-ID", "text"),
        83: ("Tunnel-Preference", "integer"),
        84: ("ARAP-Challenge-Response", "string"),
        85: ("Acct-Interim-Interval", "integer"),
        86: ("Acct-Tunnel-Packets-Lost", "integer"),
        87: ("NAS-Port-Id", "text"),
        88: ("Framed-Pool", "text"),
        89: ("CUI", "string"),
        90: ("Tunnel-Client-Auth-ID", "text"),
        91: ("Tunnel-Server-Auth-ID", "text"),
        92: ("NAS-Filter-Rule", "text"),
        94: ("Originating-Line-Info", "string"),
        95: ("NAS-IPv6-Address", "ipv6addr"),
        96: ("Framed-Interface-Id", "ifid"),
        97: ("Framed-IPv6-Prefix", "ipv6prefix"),
        98: ("Login-IPv6-Host", "ipv6addr"),
        99: ("Framed-IPv6-Route", "text"),
        100: ("Framed-IPv6-Pool", "text"),
        101: ("Error-Cause", "Attribute"),
        102: ("EAP-Key-Name", "string"),
        103: ("Digest-Response", "text"),
        104: ("Digest-Realm", "text"),
        105: ("Digest-Nonce", "text"),
        106: ("Digest-Response-Auth", "text"),
        107: ("Digest-Nextnonce", "text"),
        108: ("Digest-Method", "text"),
        109: ("Digest-URI", "text"),
        110: ("Digest-Qop", "text"),
        111: ("Digest-Algorithm", "text"),
        112: ("Digest-Entity-Body-Hash", "text"),
        113: ("Digest-CNonce", "text"),
        114: ("Digest-Nonce-Count", "text"),
        115: ("Digest-Username", "text"),
        116: ("Digest-Opaque", "text"),
        117: ("Digest-Auth-Param", "text"),
        118: ("Digest-AKA-Auts", "text"),
        119: ("Digest-Domain", "text"),
        120: ("Digest-Stale", "text"),
        121: ("Digest-HA1", "text"),
        122: ("SIP-AOR", "text"),
        123: ("Delegated-IPv6-Prefix", "ipv6prefix"),
        124: ("MIP6-Feature-Vector", "integer64"),
        125: ("MIP6-Home-Link-Prefix", "string"),
        126: ("Operator-Name", "text"),
        127: ("Location-Information", "string"),
        128: ("Location-Data", "string"),
        129: ("Basic-Location-Policy-Rules", "string"),
        130: ("Extended-Location-Policy-Rules", "string"),
        131: ("Location-Capable", "enum"),
        132: ("Requested-Location-Info", "enum"),
        133: ("Framed-Management-Protocol", "enum"),
        134: ("Management-Transport-Protection", "enum"),
        135: ("Management-Policy-Id", "text"),
        136: ("Management-Privilege-Level", "integer"),
        137: ("PKM-SS-Cert", "concat"),
        138: ("PKM-CA-Cert", "concat"),
        139: ("PKM-Config-Settings", "string"),
        140: ("PKM-Cryptosuite-List", "string"),
        141: ("PKM-SAID", "text"),
        142: ("PKM-SA-Descriptor", "string"),
        143: ("PKM-Auth-Key", "string"),
        144: ("DS-Lite-Tunnel-Name", "text"),
        145: ("Mobile-Node-Identifier", "string"),
        146: ("Service-Selection", "text"),
        147: ("PMIP6-Home-LMA-IPv6-Address", "ipv6addr"),
        148: ("PMIP6-Visited-LMA-IPv6-Address", "ipv6addr"),
        149: ("PMIP6-Home-LMA-IPv4-Address", "ipv4addr"),
        150: ("PMIP6-Visited-LMA-IPv4-Address", "ipv4addr"),
        151: ("PMIP6-Home-HN-Prefix", "ipv6prefix"),
        152: ("PMIP6-Visited-HN-Prefix", "ipv6prefix"),
        153: ("PMIP6-Home-Interface-ID", "ifid"),
        154: ("PMIP6-Visited-Interface-ID", "ifid"),
        155: ("PMIP6-Home-IPv4-HoA", "ipv4prefix"),
        156: ("PMIP6-Visited-IPv4-HoA", "ipv4prefix"),
        157: ("PMIP6-Home-DHCP4-Server-Address", "ipv4addr"),
        158: ("PMIP6-Visited-DHCP4-Server-Address", "ipv4addr"),
        159: ("PMIP6-Home-DHCP6-Server-Address", "ipv6addr"),
        160: ("PMIP6-Visited-DHCP6-Server-Address", "ipv6addr"),
        161: ("PMIP6-Home-IPv4-Gateway", "ipv4addr"),
        162: ("PMIP6-Visited-IPv4-Gateway", "ipv4addr"),
        163: ("EAP-Lower-Layer", "enum"),
        164: ("GSS-Acceptor-Service-Name", "text"),
        165: ("GSS-Acceptor-Host-Name", "text"),
        166: ("GSS-Acceptor-Service-Specifics", "text"),
        167: ("GSS-Acceptor-Realm-Name", "text"),
        168: ("Framed-IPv6-Address", "ipv6addr"),
        169: ("DNS-Server-IPv6-Address", "ipv6addr"),
        170: ("Route-IPv6-Information", "ipv6prefix"),
        171: ("Delegated-IPv6-Prefix-Pool", "text"),
        172: ("Stateful-IPv6-Address-Pool", "text"),
        173: ("IPv6-6rd-Configuration", "tlv"),
        174: ("Allowed-Called-Station-Id", "text"),
        175: ("EAP-Peer-Id", "string"),
        176: ("EAP-Server-Id", "string"),
        177: ("Mobility-Domain-Id", "integer"),
        178: ("Preauth-Timeout", "integer"),
        179: ("Network-Id-Name", "string"),
        180: ("EAPoL-Announcement", "concat"),
        181: ("WLAN-HESSID", "text"),
        182: ("WLAN-Venue-Info", "integer"),
        183: ("WLAN-Venue-Language", "string"),
        184: ("WLAN-Venue-Name", "text"),
        185: ("WLAN-Reason-Code", "integer"),
        186: ("WLAN-Pairwise-Cipher", "integer"),
        187: ("WLAN-Group-Cipher", "integer"),
        188: ("WLAN-AKM-Suite", "integer"),
        189: ("WLAN-Group-Mgmt-Cipher", "integer"),
        190: ("WLAN-RF-Band", "integer"),
        241: ("Extended-Attribute-1", "extended"),
        241.1: ("Frag-Status", "integer"),
        241.2: ("Proxy-State-Length", "integer"),
        241.3: ("Response-Length", "integer"),
        241.4: ("Original-Packet-Code", "integer"),
        241.5: ("IP-Port-Limit-Info", "tlv"),
        241.6: ("IP-Port-Range", "tlv"),
        241.7: ("IP-Port-Forwarding-Map", "tlv"),
        241.26: ("Extended-Vendor-Specific-1", "evs"),
        242: ("Extended-Attribute-2", "extended"),
        242.26: ("Extended-Vendor-Specific-2", "evs"),
        243: ("Extended-Attribute-3", "extended"),
        243.26: ("Extended-Vendor-Specific-3", "evs"),
        244: ("Extended-Attribute-4", "extended"),
        244.26: ("Extended-Vendor-Specific-4", "evs"),
        245: ("Extended-Attribute-5", "long"),
        245.1: ("SAML-Assertion", "text"),
        245.2: ("SAML-Protocol", "text"),
        245.26: ("Extended-Vendor-Specific-5", "evs"),
        246: ("Extended-Attribute-6", "long"),
        246.26: ("Extended-Vendor-Specific-6", "evs"),
    }
    NAMED = {}

    ENUM = {
        6: {
            1: "Login-User",  # Captive portal auth
            2: "Framed-User",  # 802.1X auth
            3: "Callback-Login-User",
            4: "Callback-Framed-User",
            5: "Outbound-User",
            6: "Administrative-User",
            7: "NAS-Prompt-User",
            8: "Authenticate-Only",
            9: "Callback-NAS-Prompt",
            10: "Call-Check",  # MAC auth
            11: "Callback-Administrative",
        },
        7: {
            1: "PPP",
            2: "SLIP",
            3: "ARAP",
            4: "Gandalf-SLML",
            5: "Xylogics-IPX-SLIP",
            6: "X.75-Synchronous",
            7: "GPRS-PDP",
        },
        10: {
            0: "None",
            1: "Send",
            2: "Listen",
            3: "Send-And-Listen",
        },
        13: {
            0: "None",
            1: "VJ-TCPIP-Header-Compression",
            2: "IPX-Header-Compression",
            3: "Stac-LZS-Compression",
        },
        15: {
            0: "Telnet",
            1: "Rlogin",
            2: "TCP-Clear",
            3: "PortMaster",
            4: "LAT",
            5: "X25-PAD",
            6: "X25-T3POS",
            8: "TCP-Clear-Quiet",
        },
        29: {
            0: "Default",
            1: "RADIUS-Request",
        },
        40: {
            1: "Start",
            2: "Stop",
            3: "Interim-Update",
            7: "Accounting-On",
            8: "Accounting-Off",
            9: "Tunnel-Start",
            10: "Tunnel-Stop",
            11: "Tunnel-Reject",
            12: "Tunnel-Link-Start",
            13: "Tunnel-Link-Stop",
            14: "Tunnel-Link-Reject",
            15: "Failed",
        },
        45: {
            1: "RADIUS",
            2: "Local",
            3: "Remote",
            4: "Diameter",
        },
        49: {
            1: "User-Request",
            2: "Lost-Carrier",
            3: "Lost-Service",
            4: "Idle-Timeout",
            5: "Session-Timeout",
            6: "Admin-Reset",
            7: "Admin-Reboot",
            8: "Port-Error",
            9: "NAS-Error",
            10: "NAS-Request",
            11: "NAS-Reboot",
            12: "Port-Unneeded",
            13: "Port-Preempted",
            14: "Port-Suspended",
            15: "Service-Unavailable",
            16: "Callback",
            17: "User-Error",
            18: "Host-Request",
            19: "Supplicant-Restart",
            20: "Reauthentication-Failure",
            21: "Port-Reinitialized",
            22: "Port-Administratively-Disabled",
            23: "Lost-Power",
        },
        57: {
            1: "Enabled",
            2: "Disabled"
        },
        61: {
            0: "Async",
            1: "Sync",
            2: "ISDN",
            3: "ISDN-V120",
            4: "ISDN-V110",
            5: "Virtual",
            6: "PIAFS",
            7: "HDLC-Clear-Channel",
            8: "X.25",
            9: "X.75",
            10: "G.3-Fax",
            11: "SDSL",
            12: "ADSL-CAP",
            13: "ADSL-DMT",
            14: "IDSL",
            15: "Ethernet",
            16: "xDSL",
            17: "Cable",
            18: "Wireless-Other",
            19: "Wireless-802.11",
            20: "Token-Ring",
            21: "FDDI",
            22: "Wireless-CDMA2000",
            23: "Wireless-UMTS",
            24: "Wireless-1X-EV",
            25: "IAPP",
            26: "FTTP",
            27: "Wireless-802.16",
            28: "Wireless-802.20",
            29: "Wireless-802.22",
            30: "PPPoA",
            31: "PPPoEoA",
            32: "PPPoEoE",
            33: "PPPoEoVLAN",
            34: "PPPoEoQinQ",
            35: "xPON",
            36: "Wireless-XGP",
            37: "WiMAX",
            38: "WIMAX-WIFI-IWK",
            39: "WIMAX-SFF",
            40: "WIMAX-HA-LMA",
            41: "WIMAX-DHCP",
            42: "WIMAX-LBS",
            43: "WIMAX-WVS",
        },
        64: {
            1: "PPTP",
            2: "L2F",
            3: "LT2P",
            4: "ATMP",
            5: "VTP",
            6: "AH",
            7: "IP-IP",
            8: "MIN-IP-IP",
            9: "ESP",
            10: "GRE",
            11: "DVS",
            12: "IP-IP-TUN",
            13: "VLAN",
        },
        65: {
            1: "IPv4",
            2: "IPv6",
            3: "NSAP",
            4: "HDLC",
            5: "BBN",
            6: "802",
            7: "E.163",
            8: "E.164",
            9: "F.69",
            10: "X.121",
            11: "IPX",
            12: "Appletalk",
            13: "DecnetIV",
            14: "Banyan-Vines",
            15: "E.164-NSAP",
        },
        72: {
            1: "Only-Default-Zone",
            2: "Zone-Filter-Inclusive",
            4: "Zone-Filter-Exclusive",
        },
        76: {
            0: "No-Echo",
            1: "Echo",
        }
    }

    def __init__(self):
        for code, val in self.CODED.items():
            self.NAMED[val[0]] = code

    def get_name(self, code):
        return self.CODED[code][0]

    def get_type(self, code):
        return self.CODED[code][1]

    def get_code(self, named):
        if isinstance('named', int):
            return named
        return self.NAMED.get(named)

    def get_enum_text(self, code, value):
        opts = self.ENUM[code]
        return opts[value]

    def get_enum_code(self, code, text):
        opts = self.ENUM[code]
        for k, v in opts.items():
            if v == text:
                return k

    def pack_attributes(self, attrs):
        if not attrs:
            return b''
        data = []
        for name, values in attrs.items():
            if not isinstance(values, list):
                values = [values]
            for value in values:
                code = self.get_code(name)
                if code is None:
                    raise AttributeError("Unknown attribute name '{}'".format(name))
                val = self.encode_attribute(code, value)
                length = len(val)
                data.append(pack('!BB{}s'.format(length), code, length + 2, val))
        return b''.join(data)

    def unpack_attributes(self, data):
        # code(1), length(2), value(length-3)
        pos, attrs = 0, OrderedDict({})
        while pos < len(data):
            code, length = unpack('!BB', data[pos:pos + 2])
            value = self.decode_attribute(code, data[pos + 2:pos + length])
            name = self.get_name(code)
            attrs.setdefault(name, []).append(value)
            pos += length
        return attrs

    def encode_attribute(self, code, value):
        typ = self.get_type(code)
        if typ in ('text', 'string', 'concat'):
            try:
                if typ == 'concat':
                    value = b''.join(value)
                return value.encode('utf-8')
            except UnicodeDecodeError:
                return value
        elif typ == 'integer':
            return pack('!I', int(value))
        elif typ == "ipv4addr":
            return IPAddress(value).packed
        elif typ == "enum":
            return pack('!I', self.get_enum_code(code, value))
        return value

    def decode_attribute(self, code, value):
        typ = self.get_type(code)
        if typ in ('text', 'string'):
            try:
                value = value.decode('utf-8')
            except UnicodeDecodeError:
                pass
        elif typ == 'integer':
            value = unpack('!I', value)[0]
        elif typ == 'ipv4addr':
            value = '.'.join(map(str, unpack('!BBBB', value)))
        elif typ == 'ipv6addr':
            addr = value + b'\x00' * (16 - len(value))
            prefix = ':'.join(map('{0:x}'.format, unpack('!' + 'H' * 8, addr)))
            value = str(IPAddress(prefix))
        elif typ == 'ipv6prefix':
            addr = value + b'\x00' * (18 - len(value))
            _, length, prefix = ':'.join(map('{0:x}'.format, unpack('!BB' + 'H' * 8, addr))).split(":", 2)
            value = str(IPNetwork("%s/%s" % (prefix, int(length, 16))))
        elif typ == 'ifid':
            pass  # ??
        elif typ == 'enum':
            key = unpack('!I', value)[0]
            value = self.get_enum_text(code, key)
        return value
