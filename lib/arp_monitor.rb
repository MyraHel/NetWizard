#!/usr/bin/env ruby
require_relative './ArpParams.rb'

def arp_monitor(eth) 

  trap "SIGINT" do
    puts "Exiting..."
    break
  end
  

	cap = PacketFu::Capture.new(:iface => eth, :filter => 'arp', :start => true)
	cap.stream.each do |p|
		pkt = PacketFu::Packet.parse p

    packet_info = [pkt.arp_saddr_ip, pkt.arp_saddr_mac, pkt.arp_daddr_ip, pkt.arp_daddr_mac, ArpParams::ARP_HWTYPES[pkt.arp_hw], ArpParams::ARP_OPCODES[pkt.arp_opcode]]
		puts "%-15s %-17s -> %-15s %-17s %s %s" % packet_info

	end

end