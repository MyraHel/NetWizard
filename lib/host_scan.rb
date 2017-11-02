#!/usr/bin/env ruby

# Active host scan
# Tries differently flagged packets on host's ports
# Usage: host_scan(ip_daddr, ports, flags, protocols)
#      where ip_daddr is an address string
#            iface is a string representing an interface
#            ports is a comma separated ports list string, including dash separated ranges or an array;
#            flags is a comma separated flags list string or an array;
#            protocol a comma separated protocols list string or an array;



def host_scan(options = nil, verbose = true)

  # config will determine the ifconfig data for iface
  config = PacketFu::Utils.ifconfig(PacketFu::Utils.default_int)
  timeout = 60

  defaults = {
    ip_daddr: config[:ip_saddr] || '127.0.0.1',
    ip_saddr: config[:ip_saddr] || '127.0.0.1',
    iface: config[:iface],
    ports: '22,80,135-139,445',                   # example values: '22', '137,139', '0-1024', '22,137-145,80,8080'
    flags: ['SYN'],       # possible values: 'SYN','ACK','FIN','PSH','RST','URG'
    protocols: ['TCP']                # possible values: 'TCP','UDP'
  }

  ports = Array.new
  flags = Array.new
  protocols = Array.new

  options = defaults.merge(options)

  # ip_addr = options[:ip_daddr].split '.'
  # ip_addr.each_with_index do |o,i|
  #   ip_addr[i] = o.to_i
  # end
  ports = parse_list(options[:ports]).sort
  flags = parse_list(options[:flags])
  protocols = parse_list(options[:protocols])


  # print out some of the relevant information
  puts
  puts "      iface: " + config[:iface]
  puts "mac address: " + config[:eth_saddr]
  puts "   local ip: " + config[:ip_saddr]
  puts "    Timeout: #{timeout}s"
  puts


  puts 'Scanning..'
  puts options
  eth_daddr = PacketFu::Utils.arp(options[:ip_daddr], :iface => options[:iface], :timeout => 7, :flavor => 'Linux')
  puts 'Destination MAC: '+eth_daddr
  puts

  listener = PacketFu::Capture.new(:iface => options[:iface], :start => true, :promisc => true)
  sent_packets = Hash.new

  # listener.save
  # listener.async.run
  protocols.each do |protocol|
    sent_packets[protocol] = Hash.new
    ports.each do |port|
      # sent_packets[protocol][port.to_s] = Hash.new :send => nil, :return => nil
      case protocol
      when 'TCP'
        packet = PacketFu::TCPPacket.new(:flavor => "Linux")
        packet.eth_daddr = eth_daddr
        packet.eth_saddr = config[:eth_saddr]
        packet.ip_daddr = options[:ip_daddr]
        packet.ip_saddr = options[:ip_saddr]
        packet.tcp_win = 29200
        packet.tcp_dst = port
        packet.ip_frag = 0
        flags.each do |flag|
          packet.tcp_flags[flag.downcase.to_sym] = 1
        end
      when 'UDP'
        # todo: udp packet construction
        # packet = PacketFu::UDPPacket.new
      else
        raise ArgumentError, "Unknown protocol #{protocol}."
      end
      packet.recalc
      # packet.to_w(options[:iface])
      # packets[protocol.to_sym][port.to_s]

      sent_packets[protocol][port.to_s] = packet
      packet.to_w(options[:iface])
    end
  end

  # ports.each do |port|
  #   # puts
  #   # puts "Port #{port}"
  #   packets[port.to_s] = Hash.new
  #   protocols.each do |protocol|
  #     # puts "Protocol #{protocol} (flags: #{flags.join(', ')})"
  #     packets[port.to_s][protocol.to_sym] = Hash.new :send => nil, :return => nil
  #     case protocol
  #     when 'TCP'
  #       packet = PacketFu::TCPPacket.new(:flavor => "Linux")
  #       packet.eth_daddr = eth_daddr
  #       packet.eth_saddr = config[:eth_saddr]
  #       packet.ip_daddr = options[:ip_daddr]
  #       packet.ip_saddr = config[:ip_saddr]
  #       packet.tcp_win = 29200
  #       packet.tcp_dst = port
  #       packet.ip_frag = 0
  #       flags.each do |flag|
  #         packet.tcp_flags[flag.downcase.to_sym] = 1
  #       end
  #     when 'UDP'
  #       packet = PacketFu::UDPPacket.new
  #     else
  #       raise ArgumentError, "Unknown protocol #{protocol}."
  #     end
  #     packet.recalc
  #     # puts packet.inspect
  #     # packet.to_w(options[:iface])
  #     # packets[protocol.to_sym][port.to_s]
  #     sent_packets[protocol.to_sym][port.to_s][:send] = packet
  #     # STDIN.gets
  #   end
  # end
  # listener.save

    # puts packets.inspect
  # packets.each do |port,cont|
  #   cont.each do |protocol,pkts|
  #
  #     # pkts.each do |packt|
  #       # puts packt.inspect
  #       puts packt.inspect
  #       pkts[:send].to_w(options[:iface])
  #     # end
  #   end
  # end
  # puts 'Packets sent..'
  # puts
  # sleep 3
  listener.save
  time = Time.now.getutc
  packets = Array.new
  listener.stream.each do | packet |
    pkt = PacketFu::Packet.parse(packet)
    if pkt.nil?
      puts 'Nil packet?!'
      puts packet.inspect
    else
      begin
        # puts pkt.inspect
        case pkt.eth_proto
        when 0x800 #IPv4
          src = pkt.ip_saddr || pkt.ip_src
          dst = pkt.ip_daddr || pkt.ip_dst
          if (src == options[:ip_daddr] && dst == options[:ip_saddr]) || (src == options[:ip_saddr] && dst == options[:ip_daddr])
            unless pkt.tcp_header.nil?
              puts src+' --> '+dst
              puts 'Port: '+pkt.tcp_src.to_s
              puts pkt.tcp_flags
              # puts pkt.tcp_header.inspect
            else
              puts 'No tcp'
              # puts pkt.inspect
            end
          end
        when 0x86dd # IPv6

        when 0x806 # ARP

        else
          puts
          puts 'Unrecognized'
          puts pkt.inspect
        end
      rescue
        puts
        puts 'Trouble..'
        puts pkt.to_s
      end
    end

    break if (Time.now.getutc - time) > timeout
  end
  puts packets.inspect
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
