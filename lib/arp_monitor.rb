#!/usr/bin/env ruby

# Passive Arp Monitor
# Analyze ARP traffic and extract some useful info
# Usage: arp_monitor("eth0"[, 0])



require_relative './arp_params.rb'
require 'json'

def arp_monitor(eth,verb) 
  
  # Init of some useful variables
  pairs = Hash.new  
  
  # Trap INT signal.. is better to exit cleanly ;)
  trap "SIGINT" do
    return pairs.to_json
    # puts "Exiting..."
    # break
  end
  
  # Init capture with static filter "ARP" and parse packets
	cap = PacketFu::Capture.new(:iface => eth, :filter => 'arp', :start => true)
	cap.stream.each do |p|
		pkt = PacketFu::Packet.parse p

    packet_info = [
      pkt.arp_saddr_ip, 
      pkt.arp_saddr_mac, 
      pkt.arp_daddr_ip, 
      pkt.arp_daddr_mac, 
      pkt.arp_hw_len, 
      pkt.arp_proto,
      pkt.arp_proto_len, 
      ArpParams::ARP_HWTYPES[pkt.arp_hw], 
      ArpParams::ARP_OPCODES[pkt.arp_opcode], 
      pkt.arp_header.body]
    
    # creating an hash with ip-mac pairs and check if something was wrong ;)
    if (pairs.has_key?(pkt.arp_saddr_ip))
      if not (pairs[pkt.arp_saddr_ip] == pkt.arp_saddr_mac)
        puts "ARP SPOOFING DETECTED: $#{pkt.arp_saddr_ip}"
      end
    else
      pairs[pkt.arp_saddr_ip] = pkt.arp_saddr_mac
    end
      
    #Are you verbose? 
    if verb == 0 # if not only some packet informations
		  puts "%-15s %-17s -> %-15s %-17s %s %s %s %s %s" % packet_info
    else
      if verb != "silent" # else if not silent all the packet
        puts "---------------------------------------"
        pp packet_info
      end
    end

	end

end
