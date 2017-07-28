#!/usr/bin/env ruby
require_relative './arp_params.rb'

def raw_sniff(eth,verb) 

  trap "SIGINT" do
    puts "Exiting..."
    break
  end

  cap = PacketFu::Capture.new(:iface => eth, :promisc => true)
  cap.show_live(:save => true)
end