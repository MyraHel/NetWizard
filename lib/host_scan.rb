#!/usr/bin/env ruby

# Active host scan
# Tries differently flagged packets on host's ports
# Usage: host_scan(ip_daddr, ports, flags, protocols)
#      where ip_daddr is an address string
#            iface is a string representing an interface
#            ports is a comma separated ports list string, including dash separated ranges or an array;
#            flags is a comma separated flags list string or an array;
#            protocol a comma separated protocols list string or an array;

require_relative './common_functions.rb'

def host_scan(options = nil, verbose = true)

  # help
  if options.include?('--help') || options.include?('-h')
    puts <<-HELP
      Host scan:
      Scans for open ports on specified host.

      Options:
        -d: destination address(es). Default: configured own ip address or 127.0.0.1.
        -s: source address. Default: configured own ip address or 127.0.0.1.
        -i: net interface.
        -p: target port(s). Format: comma sparated number or ranges list string. Default: '0-1024'
        -f: active flags. Format: strings array. Possible values: 'SYN','ACK','FIN','PSH','RST','URG', Default: ['SYN']
        -P: test protocols. Format: strings array. Default: ['TCP','UDP']

        Examples:
        host_scan ip_daddr: '192.168.1.5' ip_saddr: '192.168.1.100', iface: 'wlan0', ports: '25,143,135-139', flags: ['SYN','ACK'], protocols: ['TCP']

    HELP
    return
  end
  # config will determine the ifconfig data for iface
  config = PacketFu::Utils.ifconfig(PacketFu::Utils.default_int)
  timeout = 60

  defaults = {
    ip_daddr: config[:ip_saddr] || '127.0.0.1',
    ip_saddr: config[:ip_saddr] || '127.0.0.1',
    eth_saddr: config[:eth_saddr],
    iface: config[:iface],
    ports: '0-1024',                   # example values: '22', '137,139', '0-1024', '22,137-145,80,8080'
    flags: ['SYN'],                               # possible values: 'SYN','ACK','FIN','PSH','RST','URG'
    protocols: ['TCP','UDP']                      # possible values: 'TCP','UDP','ICMP'
  }

  ports = Array.new
  flags = Array.new
  protocols = Array.new
  opts = Hash.new
  argument = false

  #apply options
  options.each_with_index do |v,i|

    #skip if it's the argument to the previous option
    if argument
      argument = false
      next
    end

    case v
    when '-d' then
      opts[:ip_daddr] = options[i+1]
      argument = true
    when '-s' then
      opts[:ip_saddr] = options[i+1]
      argument = true
    when '-i' then
      opts[:iface] = options[i+1]
      argument = true
    when '-p' then
      opts[:ports] = options[i+1]
      argument = true
    when '-P' then
      opts[:protocols] = options[i+1].split(',').map{|p| p.upcase }
      argument = true
    when '-f' then
      opts[:flags] = options[i+1].split(',').map{|f| f.upcase }
      argument = true
    else
      raise "Unrecognized option \"#{v}\""
    end
  end

  options = defaults.merge(opts)


  # ip_addr = options[:ip_daddr].split '.'
  # ip_addr.each_with_index do |o,i|
  #   ip_addr[i] = o.to_i
  # end
  # ip_addr = options[:ip_daddr].split('.').map{ |a| a.to_i }
  ports = parse_list(options[:ports]).sort
  flags = parse_list(options[:flags])
  protocols = options[:protocols]

  if protocols.include? 'UDP'
    timeout = ports.size * 2
  else
    timeout = ports.size
  end
  sent_packets = Hash.new
  udp_packets = Hash.new
  packets = Array.new

  # print out some of the relevant information
  puts
  puts "      iface: " + options[:iface]
  puts "mac address: " + options[:eth_saddr]
  puts "   local ip: " + options[:ip_saddr]
  puts "    Timeout: #{timeout}s"
  puts


  puts "Scanning #{options[:ip_daddr]}.."

  eth_daddr = PacketFu::Utils.arp(options[:ip_daddr], :iface => options[:iface], :timeout => 7, :flavor => 'Linux')
  puts 'Destination MAC: '+eth_daddr
  puts

  time = Time.now.getutc
  thread = Thread.new {

    listener = PacketFu::Capture.new(:iface => options[:iface], :start => true, :promisc => true, :save => true, :timeout => timeout)
    listener.stream.each do | packet |
      pkt = PacketFu::Packet.parse(packet)

      if pkt.nil?
        puts 'Nil packet?!'
        puts packet.inspect
      else
        begin

          case pkt.eth_proto
          when 0x800 #IPv4
            src = pkt.ip_saddr || pkt.ip_src
            dst = pkt.ip_daddr || pkt.ip_dst
            if (src == options[:ip_daddr] && dst == options[:ip_saddr]) #|| (src == options[:ip_saddr] && dst == options[:ip_daddr])
              if pkt.nil?
                puts 'Nil packet?!'
                puts packet.inspect
              end
              case pkt.ip_proto
              # if !pkt.tcp_header.nil?
              when 0x01 # 1 - ICMP
                puts 'ICMP'
                puts pkt.inspect
                payload = pkt.payload.to_s
                udp_packets.keys.each do |port|
                  sent_packets['UDP'][port.to_s] = 'Closed' if udp_packets[port.to_s] === payload
                  puts '.................................'
                  puts payload.to_s(16)
                  puts '.................................'
                  puts '.................................'
                  puts udp_packets[port.to_s].to_s(16)
                  puts '.................................'
                end
              when 0x06 # 6 - TCP
                  if pkt.tcp_flags.rst == 1
                    state = 'Filtered'
                  elsif pkt.tcp_flags.ack == 1 && pkt.tcp_flags.syn == 1
                    state = 'Open'
                  else
                    state = 'Closed'
                  end

                  sent_packets['TCP'][pkt.tcp_src.to_s] = state
                  puts
                  puts src+' --> '+dst
                  puts 'Port: '+pkt.tcp_src.to_s+'         '+state
                  puts pkt.tcp_flags.inspect
                  # puts pkt.tcp_header.inspect
                # elsif !pkt.udp_header.nil?
              when 0x11 # 17 - UDP
                  puts 'UDP'
                  puts pkt.inspect
                  # if pkt.tcp_flags.rst == 1
                  #   state = 'Filtered'
                  # elsif pkt.tcp_flags.ack == 1 && pkt.tcp_flags.syn == 1
                  #   state = 'Open'
                  # else
                  #   state = 'Closed'
                  # end
                  #
                  # sent_packets['TCP'][pkt.tcp_src.to_s] = state
                  # puts
                  # puts src+' --> '+dst
                  # puts pkt.inspect
                  # puts 'Port: '+pkt.tcp_src.to_s+'         '+state
                  # puts pkt.tcp_flags.inspect
                  # puts pkt.tcp_header.inspect
                # end
              else

                # puts pkt.inspect
              end
            end
          when 0x86dd # IPv6

          when 0x806 # ARP

          else
            puts
            puts 'Unrecognized' + pkt.eth_proto
            puts pkt.inspect
          end
        rescue Exception => e
          begin
            puts
            puts 'Trouble..'
            puts e.message
            puts
            puts pkt.to_s
            puts
            puts pkt.inspect
            puts
            puts pkt.headers.inspect

            puts
            puts e.backtrace.join("\n")
          rescue Exception => e2
            puts 'Double troble..!'
            puts
            puts e2.message
            puts
            puts e2.backtrace.join("\n")
          end
        end
      end
      finished = true
      sent_packets.keys.each do |protocol|
        sent_packets[protocol].keys.each do |port|
          finished = false if sent_packets[protocol][port.to_s].nil?
        end
      end
      if ((Time.now.getutc - time) > timeout or finished)
        puts
        puts 'Completed'
        puts
        puts
        thread.kill
      end
    end
  }

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
        packet = PacketFu::UDPPacket.new()
        packet.eth_daddr = eth_daddr
        packet.eth_saddr = config[:eth_saddr]
        packet.ip_daddr = options[:ip_daddr]
        packet.ip_saddr = options[:ip_saddr]
        # packet.udp_win = 29200
        packet.udp_dst = port
        packet.udp_src = rand(0xffff-1024) + 1024
        # copy first 8 bytes of raw packet for icmp comparation
        udp_packets[port.to_s] = packet.to_s[0,8]
        # packet.ip_frag = 0
        # flags.each do |flag|
        #   packet.udp_flags[flag.downcase.to_sym] = 1
        # end
      else
        raise ArgumentError, "Unknown protocol #{protocol}."
      end
      packet.recalc
      # packet.to_w(options[:iface])
      # packets[protocol.to_sym][port.to_s]
      # puts protocol
      sent_packets[protocol][port.to_s] = nil
      packet.to_w(options[:iface])
    end
  end
  thread.join
  puts sent_packets
end
