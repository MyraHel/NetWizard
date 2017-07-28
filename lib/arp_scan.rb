#!/usr/bin/env ruby
require 'packetfu'
require 'packetfu/protos/ipv6'
require 'packetfu/protos/eth'
require 'packetfu/utils'

def usage
  puts
  puts "You need to be root/administrator to run this."
end

# Execute an ARP scan
#
# target - CIDR block
# iface  - Ethernet interface to use
#
# Examples
#
#   arp_scan('192.168.0.0/24', 'eth0')
#
# Returns scan result
def arp_scan(target, iface) 
  if !Process.euid.zero?
    usage
    return nil
  else
    IPAddr.new(target)

    puts "Discovering: #{target}, on interface: #{iface}"

    response_scan = PacketFu::Utils.arp(target, :iface => iface)

    return response_scan
  end
end

