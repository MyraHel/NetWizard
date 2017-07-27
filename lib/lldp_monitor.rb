#!/usr/bin/env ruby
require_relative './arp_params.rb'

def lldp_monitor(eth,verb) 

  trap "SIGINT" do
    puts "Exiting..."
    break
  end
  

	cap = PacketFu::Capture.new(:iface => eth, :filter => '(ether[12:2]=0x88cc)', :start => true)
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
    
    if verb == 0
		  puts "%-15s %-17s -> %-15s %-17s %s %s %s %s %s" % packet_info
    else 
      puts "verbose: %-15s %-17s -> %-15s %-17s %s %s %s %s %s %s" % packet_info
    end

	end

end
