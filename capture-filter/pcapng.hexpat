#pragma endian little
#pragma base_address 0x00
// #pragma debug
#pragma pattern_limit 900000
#pragma array_limit 900000

// Docs: https://docs.werwolv.net/pattern-language

import std.io;
import std.mem;
import std.core;

// std::print("{}", $);

// using block_ctrl;

enum BlockType : u32 {
    Reserved_Unknown = 0x00000000, // This value is reserved in the spec, and used here to represent an unknown block type.
    InterfaceDescriptionBlock = 0x00000001,
    PacketBlock = 0x00000002,
    SimplePacketBlock = 0x00000003,
    NameResolutionBlock = 0x00000004,
    InterfaceStatisticsBlock = 0x00000005,
    EnhancedPacketBlock = 0x00000006,
    IRIGTimestampBlock = 0x00000007,
    Arinc429InformationBlock = 0x00000008,
    SystemdJournalExportBlock = 0x00000009,
    DecryptionSecretsBlock = 0x0000000A,
    HoneProjectMachineInfoBlock = 0x00000101,
    HoneProjectConnectionEventBlock = 0x00000102,
    SysdigMachineInfoBlock = 0x00000201,
    SysdigProcessInfoBlockV1 = 0x00000202,
    SysdigFDListBlock = 0x00000203,
    SysdigEventBlock = 0x00000204,
    SysdigInterfaceListBlock = 0x00000205,
    SysdigUserListBlock = 0x00000206,
    SysdigProcessInfoBlockV2 = 0x00000207,
    SysdigEventBlockWithFlags = 0x00000208,
    SysdigProcessInfoBlockV3 = 0x00000209,
    SysdigProcessInfoBlockV4 = 0x00000210,
    SysdigProcessInfoBlockV5 = 0x00000211,
    SysdigProcessInfoBlockV6 = 0x00000212,
    SysdigProcessInfoBlockV7 = 0x00000213,
    CustomBlockCopyable = 0x00000BAD,
    CustomBlockNotCopyable = 0x40000BAD,
    SectionHeaderBlock = 0x0A0D0D0A,
    // 0x0A0D0A00-0x0A0D0AFF => Reserved. Used to detect trace files corrupted because of file transfers using the HTTP protocol in text mode.
    // 0x000A0D0A-0xFF0A0D0A => Reserved. Used to detect trace files corrupted because of file transfers using the HTTP protocol in text mode.
    // 0x000A0D0D-0xFF0A0D0D => Reserved. Used to detect trace files corrupted because of file transfers using the HTTP protocol in text mode.
    // 0x0D0D0A00-0x0D0D0AFF => Reserved. Used to detect trace files corrupted because of file transfers using the FTP protocol in text mode.
    // 0x80000000-0xFFFFFFFF => Reserved for local use
};

enum LinkType : u16 {
    LINKTYPE_NULL = 0,
    LINKTYPE_ETHERNET = 1,
    LINKTYPE_EXP_ETHERNET = 2,
    LINKTYPE_AX25 = 3,
    LINKTYPE_PRONET = 4,
    LINKTYPE_CHAOS = 5,
    LINKTYPE_IEEE802_5 = 6,
    LINKTYPE_ARCNET_BSD = 7,
    LINKTYPE_SLIP = 8,
    LINKTYPE_PPP = 9,
    LINKTYPE_FDDI = 10,
    LINKTYPE_PPP_HDLC = 50,
    LINKTYPE_PPP_ETHER = 51,
    LINKTYPE_SYMANTEC_FIREWALL = 99,
    LINKTYPE_ATM_RFC1483 = 100,
    LINKTYPE_RAW = 101,
    LINKTYPE_SLIP_BSDOS = 102,
    LINKTYPE_PPP_BSDOS = 103,
    LINKTYPE_C_HDLC = 104,
    LINKTYPE_IEEE802_11 = 105,
    LINKTYPE_ATM_CLIP = 106,
    LINKTYPE_FRELAY = 107,
    LINKTYPE_LOOP = 108,
    LINKTYPE_ENC = 109,
    LINKTYPE_LANE8023 = 110,
    LINKTYPE_HIPPI = 111,
    LINKTYPE_HDLC = 112,
    LINKTYPE_LINUX_SLL = 113,
    LINKTYPE_LTALK = 114,
    LINKTYPE_ECONET = 115,
    LINKTYPE_IPFILTER = 116,
    LINKTYPE_PFLOG = 117,
    LINKTYPE_CISCO_IOS = 118,
    LINKTYPE_IEEE802_11_PRISM = 119,
    LINKTYPE_IEEE802_11_AIRONET = 120,
    LINKTYPE_HHDLC = 121,
    LINKTYPE_IP_OVER_FC = 122,
    LINKTYPE_SUNATM = 123,
    LINKTYPE_RIO = 124,
    LINKTYPE_PCI_EXP = 125,
    LINKTYPE_AURORA = 126,
    LINKTYPE_IEEE802_11_RADIOTAP = 127,
    LINKTYPE_TZSP = 128,
    LINKTYPE_ARCNET_LINUX = 129,
    LINKTYPE_JUNIPER_MLPPP = 130,
    LINKTYPE_JUNIPER_MLFR = 131,
    LINKTYPE_JUNIPER_ES = 132,
    LINKTYPE_JUNIPER_GGSN = 133,
    LINKTYPE_JUNIPER_MFR = 134,
    LINKTYPE_JUNIPER_ATM2 = 135,
    LINKTYPE_JUNIPER_SERVICES = 136,
    LINKTYPE_JUNIPER_ATM1 = 137,
    LINKTYPE_APPLE_IP_OVER_IEEE1394 = 138,
    LINKTYPE_MTP2_WITH_PHDR = 139,
    LINKTYPE_MTP2 = 140,
    LINKTYPE_MTP3 = 141,
    LINKTYPE_SCCP = 142,
    LINKTYPE_DOCSIS = 143,
    LINKTYPE_LINUX_IRDA = 144,
    LINKTYPE_IBM_SP = 145,
    LINKTYPE_IBM_SN = 146,
    LINKTYPE_RESERVED_01 = 147,
    LINKTYPE_RESERVED_02 = 148,
    LINKTYPE_RESERVED_03 = 149,
    LINKTYPE_RESERVED_04 = 150,
    LINKTYPE_RESERVED_05 = 151,
    LINKTYPE_RESERVED_06 = 152,
    LINKTYPE_RESERVED_07 = 153,
    LINKTYPE_RESERVED_08 = 154,
    LINKTYPE_RESERVED_09 = 155,
    LINKTYPE_RESERVED_10 = 156,
    LINKTYPE_RESERVED_11 = 157,
    LINKTYPE_RESERVED_12 = 158,
    LINKTYPE_RESERVED_13 = 159,
    LINKTYPE_RESERVED_14 = 160,
    LINKTYPE_RESERVED_15 = 161,
    LINKTYPE_RESERVED_16 = 162,
    LINKTYPE_IEEE802_11_AVS = 163,
    LINKTYPE_JUNIPER_MONITOR = 164,
    LINKTYPE_BACNET_MS_TP = 165,
    LINKTYPE_PPP_PPPD = 166,
    LINKTYPE_JUNIPER_PPPOE = 167,
    LINKTYPE_JUNIPER_PPPOE_ATM = 168,
    LINKTYPE_GPRS_LLC = 169,
    LINKTYPE_GPF_T = 170,
    LINKTYPE_GPF_F = 171,
    LINKTYPE_GCOM_T1E1 = 172,
    LINKTYPE_GCOM_SERIAL = 173,
    LINKTYPE_JUNIPER_PIC_PEER = 174,
    LINKTYPE_ERF_ETH = 175,
    LINKTYPE_ERF_POS = 176,
    LINKTYPE_LINUX_LAPD = 177,
    LINKTYPE_JUNIPER_ETHER = 178,
    LINKTYPE_JUNIPER_PPP = 179,
    LINKTYPE_JUNIPER_FRELAY = 180,
    LINKTYPE_JUNIPER_CHDLC = 181,
    LINKTYPE_MFR = 182,
    LINKTYPE_JUNIPER_VP = 182,
    LINKTYPE_A653_ICM = 185,
    LINKTYPE_USB_FREEBSD = 186,
    LINKTYPE_BLUETOOTH_HCI_H4 = 187,
    LINKTYPE_IEEE802_16_MAC_CPS = 188,
    LINKTYPE_USB_LINUX = 189,
    LINKTYPE_CAN20B = 190,
    LINKTYPE_IEEE802_15_4_LINUX = 191,
    LINKTYPE_PPI = 192,
    LINKTYPE_IEEE802_16_MAC_CPS_RADIO = 193,
    LINKTYPE_JUNIPER_ISM = 194,
    LINKTYPE_IEEE802_15_4_WITHFCS = 195,
    LINKTYPE_SITA = 196,
    LINKTYPE_ERF = 197,
    LINKTYPE_RAIF1 = 198,
    LINKTYPE_IPMB_KONTRON = 199,
    LINKTYPE_JUNIPER_ST = 200,
    LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201,
    LINKTYPE_AX25_KISS = 202,
    LINKTYPE_LAPD = 203,
    LINKTYPE_PPP_WITH_DIR = 204,
    LINKTYPE_C_HDLC_WITH_DIR = 205,
    LINKTYPE_FRELAY_WITH_DIR = 206,
    LINKTYPE_LAPB_WITH_DIR = 207,
    Reserved = 208,
    LINKTYPE_IPMB_LINUX = 209,
    LINKTYPE_FLEXRAY = 210,
    LINKTYPE_MOST = 211,
    LINKTYPE_LIN = 212,
    LINKTYPE_X2E_SERIAL = 213,
    LINKTYPE_X2E_XORAYA = 214,
    LINKTYPE_IEEE802_15_4_NONASK_PHY = 215,
    LINKTYPE_LINUX_EVDEV = 216,
    LINKTYPE_GSMTAP_UM = 217,
    LINKTYPE_GSMTAP_ABIS = 218,
    LINKTYPE_MPLS = 219,
    LINKTYPE_USB_LINUX_MMAPPED = 220,
    LINKTYPE_DECT = 221,
    LINKTYPE_AOS = 222,
    LINKTYPE_WIHART = 223,
    LINKTYPE_FC_2 = 224,
    LINKTYPE_FC_2_WITH_FRAME_DELIMS = 225,
    LINKTYPE_IPNET = 226,
    LINKTYPE_CAN_SOCKETCAN = 227,
    LINKTYPE_IPV4 = 228,
    LINKTYPE_IPV6 = 229,
    LINKTYPE_IEEE802_15_4_NOFCS = 230,
    LINKTYPE_DBUS = 231,
    LINKTYPE_JUNIPER_VS = 232,
    LINKTYPE_JUNIPER_SRX_E2E = 233,
    LINKTYPE_JUNIPER_FIBRECHANNEL = 234,
    LINKTYPE_DVB_CI = 235,
    LINKTYPE_MUX27010 = 236,
    LINKTYPE_STANAG_5066_D_PDU = 237,
    LINKTYPE_JUNIPER_ATM_CEMIC = 238,
    LINKTYPE_NFLOG = 239,
    LINKTYPE_NETANALYZER = 240,
    LINKTYPE_NETANALYZER_TRANSPARENT = 241,
    LINKTYPE_IPOIB = 242,
    LINKTYPE_MPEG_2_TS = 243,
    LINKTYPE_NG40 = 244,
    LINKTYPE_NFC_LLCP = 245,
    LINKTYPE_PFSYNC = 246,
    LINKTYPE_INFINIBAND = 247,
    LINKTYPE_SCTP = 248,
    LINKTYPE_USBPCAP = 249,
    LINKTYPE_RTAC_SERIAL = 250,
    LINKTYPE_BLUETOOTH_LE_LL = 251,
    LINKTYPE_WIRESHARK_UPPER_PDU = 252,
    LINKTYPE_NETLINK = 253,
    LINKTYPE_BLUETOOTH_LINUX_MONITOR = 254,
    LINKTYPE_BLUETOOTH_BREDR_BB = 255,
    LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256,
    LINKTYPE_PROFIBUS_DL = 257,
    LINKTYPE_PKTAP = 258,
    LINKTYPE_EPON = 259,
    LINKTYPE_IPMI_HPM_2 = 260,
    LINKTYPE_ZWAVE_R1_R2 = 261,
    LINKTYPE_ZWAVE_R3 = 262,
    LINKTYPE_WATTSTOPPER_DLM = 263,
    LINKTYPE_ISO_14443 = 264,
    LINKTYPE_RDS = 265,
    LINKTYPE_USB_DARWIN = 266,
    LINKTYPE_OPENFLOW = 267,
    LINKTYPE_SDLC = 268,
    LINKTYPE_TI_LLN_SNIFFER = 269,
    LINKTYPE_LORATAP = 270,
    LINKTYPE_VSOCK = 271,
    LINKTYPE_NORDIC_BLE = 272,
    LINKTYPE_DOCSIS31_XRA31 = 273,
    LINKTYPE_ETHERNET_MPACKET = 274,
    LINKTYPE_DISPLAYPORT_AUX = 275,
    LINKTYPE_LINUX_SLL2 = 276,
    LINKTYPE_SERCOS_MONITOR = 277,
    LINKTYPE_OPENVIZSLA = 278,
    LINKTYPE_EBHSCR = 279,
    LINKTYPE_VPP_DISPATCH = 280,
    LINKTYPE_DSA_TAG_BRCM = 281,
    LINKTYPE_DSA_TAG_BRCM_PREPEND = 282,
    LINKTYPE_IEEE802_15_4_TAP = 283,
    LINKTYPE_DSA_TAG_DSA = 284,
    LINKTYPE_DSA_TAG_EDSA = 285,
    LINKTYPE_ELEE = 286,
    LINKTYPE_Z_WAVE_SERIAL = 287,
    LINKTYPE_USB_2_0 = 288,
    LINKTYPE_ATSC_ALP = 289
};


u32 interface_count = 0;
str interface_names[1000];

using Option;

fn find_add_interface_name(auto options) {
    for (u8 i = 0, i < std::core::member_count(options), i = i + 1) {
        if (options[i].type == 0x02) {
            interface_names[interface_count] = options[i].value;
            interface_count = interface_count + 1;
            return;
        }
    }
    interface_names[interface_count] = "UNKNOWN";
    interface_count = interface_count + 1;
    
};


struct Option {
    u16 type;
    u16 length;
    char value[length];
    if (length % 4 != 0) {
        padding[4 - length % 4];
    }
};


struct Block {
    u64 start_address = $;
    
    BlockType type;
    u32 length;
    
    if (type == BlockType::SectionHeaderBlock) {
        u32 byte_order_magic;
        u16 major_version;
        u16 minor_version;
        u64 section_length;
        
        u64 option_start_pos = $;
    
        if ($ < start_address + length - 4) {
            Option options[while(std::mem::read_unsigned($, 4) != 0x0000)];
            Option end_of_options [[hidden]];   
        }
        
    } else if (type == BlockType::InterfaceDescriptionBlock) {
        LinkType link_type;
        padding[2];
        u32 snaplen;
    
        Option options[while(std::mem::read_unsigned($, 4) != 0x0000)];
        Option end_of_options [[hidden]];
        
        find_add_interface_name(options);
    } else if (type == BlockType::EnhancedPacketBlock) {
        u32 interface_id;
        if (interface_id < interface_count) {
            str interface_name = interface_names[interface_id] [[export]];
        }
        u32 timestamp_high;
        u32 timestamp_low;
        u32 captured_packet_length;
        u32 original_packet_length;
        u8 packet_data[captured_packet_length];
        if (captured_packet_length % 4 != 0) {
            padding[4 - captured_packet_length % 4];
        }
        
        if ($ < start_address + length - 4) {
            Option options[while(std::mem::read_unsigned($, 4) != 0x0000)];
            Option end_of_options [[hidden]];   
        }
    } else {
        u8 data[length - 12];
    }
    
    
    u32 length_2;
};

// Size should be: while($ < std::mem::size())
Block section_header_blocks[10] @ 0x00;