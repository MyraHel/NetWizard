#!/usr/bin/env ruby

# Active host scan
# Tries differently flagged packets on host's ports
# Usage: host_scan(ip_addr, ports, flags, protocols)
#      where ip_addr is an address string
#            iface is a string representing an interface
#            ports is a comma separated ports list string, including dash separated ranges or an array;
#            flags is a comma separated flags list string or an array;
#            protocol a comma separated protocols list string or an array;

# def host_scan(ip_addr = nil, ports = nil, flags = nil, protocols = nil)



def host_scan(options = nil, verbose = true)



  defaults = {
    ip_addr: '127.0.0.1',
    iface: PacketFu::Utils.default_int,
    ports: '139',                   # example values: '22', '137,139', '0-1024', '22,137-145,80,8080'
    flags: ['SYN'],       # possible values: 'SYN','ACK','FIN','PSH','RST','URG'
    protocols: ['TCP']                # possible values: 'TCP','UDP'
  }

  ports = Array.new
  flags = Array.new
  protocols = Array.new

  options = defaults.merge(options)

  ip_addr = options[:ip_addr].split '.'
  ip_addr.each_with_index do |o,i|
    ip_addr[i] = o.to_i
  end
  ports = parse_list(options[:ports])
  flags = parse_list(options[:flags])
  protocols = parse_list(options[:protocols])

  # config will determine the ifconfig data for iface
  config = PacketFu::Utils.ifconfig(options[:iface])

  # print out some of the relevant information
  puts
  puts "      iface: " + config[:iface]
  puts "mac address: " + config[:eth_saddr]
  puts "   local ip: " + config[:ip_saddr]
  puts

  puts 'Scanning..'
  puts options
  puts
  # STDIN.gets

  listener = PacketFu::Capture.new(:iface => options[:iface], :start => true, :promisc => true)
  STDIN.gets

  # listener.save
  # listener.async.run

  ports.each do |port|
    puts "Port #{port}"
    puts
    protocols.each do |protocol|
      puts "Protocol #{protocol} (flags: #{flags.join(', ')})"
      puts
      case protocol
      when 'TCP'
        packet = PacketFu::TCPPacket.new(:flavor => "Linux")
        puts packet.eth_daddr = PacketFu::Utils.arp(options[:ip_addr])
        packet.ip_daddr = options[:ip_addr]
        packet.ip_saddr = config[:ip_saddr]
        packet.tcp_win = 29200
        packet.tcp_dst = port
        # packet.ip_frag = 0
        flags.each do |flag|
          packet.tcp_flags[flag.downcase.to_sym] = 1
        end
      when 'UDP'
        packet = PacketFu::UDPPacket.new
      else
        raise ArgumentError, "Unknown protocol #{protocol}."
      end
      packet.recalc
      puts packet.inspect
      # puts packet.tcp_flags.inspect
      # puts packet.ip_header.inspect
      # puts packet.tcp_header.inspect
      # puts packet.tcp_opts.inspect
      # puts packet.inspect if verbose
      packet.to_w(options[:iface])

      # STDIN.gets
    end
  end
  listener.save
  puts listener.inspect
  listener.stream.each do | packet |
    pkt = PacketFu::Packet.parse(packet)
    # puts listener.stream.inspect
    puts pkt.inspect if pkt.class == PacketFu::TCPPacket && (pkt.ip_saddr == options[:ip_addr] || pkt.ip_daddr == options[:ip_addr])
  end
end

def parse_list(list,numeric = true)       # arguments: comme separated list string, boolean indicating presence of numeric ranges
  result = Array.new
  if(list.is_a? String)                   # if it's a string split it
    splitted_list = list.split(',')
    splitted_list.each do |i|             # if the element is a range split it
      range = i.split('-')
      port = range[0]
      if(range.size == 2)                 # expand splitted range
        port = port.to_i
        begin
          result << port
          port += 1
        end while port <= range[range.size-1].to_i
      else
        port = port.to_i if numeric
        result << port
      end
    end
  elsif(list.is_a? Array)
    result = list
  else
    raise ArgumentError, 'List must be either a comma separated list or an array.'
  end
  result
end
