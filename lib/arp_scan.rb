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
# ip     - Source ip for request
#
# Examples
#
#   arp_scan('192.168.0.0/24', 'eth0', '192.168.1.1')
#
# Returns scan result
def arp_scan(target, iface, ip) 
  if !Process.euid.zero?
    usage
    return nil
  else
    IPAddr.new(target)

    puts "Discovering: #{target}, on interface: #{iface}"

    response_scan = PacketFu::Utils.arp(target, :iface => iface, :ip_saddr => ip)

    return response_scan
  end
end

