#!/usr/bin/env ruby

# Active host scan
# Tries differently flagged packets on host's ports
# Usage: host_scan({ip_addr, ports, flags, protocols})
#      where ip_addr is an address string
#            ports is a comma separated ports list string, including dash separated ranges or an array;
#            flags is a comma separated flags list string or an array;
#            protocol a comma separated protocols list string or an array;

def host_scan(options = nil)

  defaults = {
    ip_addr: '127.0.0.1',
    ports: '22,7-100',                # example values: '22', '137,139', '0-1024', '22,137-145,80,8080'
    flags: ['SYN','ACK'],             # possible values: 'SYN','ACK','FIN','PSH','RST','URG'
    protocols: ['TCP']                # possible values: 'TCP','UDP'
  }


  ports = Array.new
  flags = Array.new
  protocols = Array.new

  if(options.nil?)
    ip_addr = defaults[:ip_addr]
    ports = parse_list(defaults[:ports])
    flags = parse_list(defaults[:flags],false)
    protocols = parse_list(defaults[:protocols],false)
  else
    puts options.inspect
    puts options.class
    if(options[:ip_addr].nil?)
      ip_addr = defaults[:ip_addr]
    else
      ip_addr = options[:ip_addr]
    end
    if(options[:ports].nil?)
      ports = parse_list(defaults[:ports])
    else
      ports = parse_list(options[:ports])
    end
    if(options[:flags].nil?)
      flags = parse_list(defaults[:flags])
    else
      flags = parse_list(options[:flags])
    end
    if(options[:protocols].nil?)
      protocols = parse_list(defaults[:protocols])
    else
      protocols = parse_list(options[:protocols])
    end
  end


  puts 'Scanning..'
  puts ip_addr
  puts ports.inspect
  puts flags.inspect
  puts protocols.inspect

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
    raise ArgumentError, 'List must be either a comma separated list or an array'
  end
  result
end
