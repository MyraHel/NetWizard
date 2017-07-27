#!/usr/bin/env ruby
require 'packetfu'
require 'packetfu/protos/ipv6'
require 'packetfu/protos/eth'
require 'packetfu/utils'

def usage
  if !Process.euid.zero?
    raise SecurityError, "You need to be root to run this."
  end
end


def arp_scan(target, iface) 
  usage unless Process.euid.zero?
  IPAddr.new(target)
  print "Discovery: " + target + " On interface: " + iface + "\n"
  response_scan = PacketFu::Utils.arp(target, :iface => iface)
  puts response_scan
end

