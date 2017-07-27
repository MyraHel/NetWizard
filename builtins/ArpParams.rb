module ArpParams

  ## ARP PROTOCOLS CONSTANTS 
  ARP_OPCODES = Array.new([
    "reserved", 
    "Request", 
    "Reply", 
    "Request-Reverse", 
    "Reply-Reverse",
    "DRARP Request",
    "DRARP Reply",
    "DRARP Error",
    "InARP Request",
    "InARP Reply",
    "ARP NAK",
    "MARS Request",	 
    "MARS Multi",	 
    "MARS MServ",
    "MARS Join",
    "MARS Leave",
    "MARS NAK",
    "MARS Unserv",
    "MARS SJoin",
    "MARS SLeave",	 
    "MARS Grouplist Request",
    "MARS Grouplist Reply",
    "MARS Redirect Map",
    "MAPOS UNARP",
    "OP_EXP1",
    "OP_EXP2"
  ])
  
  ARP_HWTYPES = Array.new([
    "reserved",
    "Ethernet",
    "Experimental Ethernet",
    "Amateur Radio AX.25",
    "Proteon ProNET Token Ring",
    "Chaos",
    "IEEE 802",
    "ARCNET",
    "Hyperchannel",
    "Lanstar",
    "Autonet Short Address",
    "LocalTalk",
    "LocalNet (IBM PCNet or SYTEK LocalNET)",
    "Ultra link",
    "SMDS",
    "Frame Relay",
    "ATM, Asynchronous Transmission Mode",
    "HDLC",
    "Fibre Channel",
    "ATM, Asynchronous Transmission Mode",
    "Serial Line",
    "ATM, Asynchronous Transmission Mode",
    "MIL-STD-188-220",
    "Metricom",
    "IEEE 1394.1995",
    "MAPOS",
    "Twinaxial",
    "EUI-64",
    "HIPARP",
    "IP and ARP over ISO 7816-3",
    "ARPSec",
    "IPsec tunnel",
    "Infiniband",
    "CAI, TIA-102 Project 25 Common Air Interface",
    "Wiegand Interface",
    "Pure IP",
    "HW_EXP1	RFC 5494"
  ])
  
  ARP_HWTYPES[255] = "HW_EXP2	RFC 5494"
  ARP_HWTYPES[256] =	"HW_EXP2	RFC 5494"
  ARP_HWTYPES[257] = "HW_EXP2	RFC 5494"
  ARP_HWTYPES[65534] = "reserved"
  ARP_HWTYPES[65535] =	"reserved"

end