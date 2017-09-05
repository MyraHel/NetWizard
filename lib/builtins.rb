#!/usr/bin/env ruby
require 'shellwords'

BUILTINS = {
  'cd'          => lambda { |dir| Dir.chdir(dir) },
  'exit'        => lambda { |code = 0| exit(code.to_i) },
  'quit'        => lambda { |code = 0| exit(code.to_i) },
  'exec'        => lambda { |*command| %x(*command) },
  'arp_scan'    => lambda { |target, iface, ip=PacketFu::Utils.whoami?(:iface => iface)[:ip_saddr]| arp_scan(target, iface, ip) },
  'arp_monitor' => lambda { |eth,verb=0| arp_monitor(eth,verb) },
  'host_scan'   => lambda { |ip_daddr = nil, iface = nil, ports = nil,flags = nil,protocols = nil|
                              options = Hash.new
                              options[:ip_daddr] = ip_daddr unless ip_daddr.nil?
                              options[:iface] = iface unless iface.nil?
                              options[:ports] = ports unless ports.nil?
                              options[:flags] = flags unless flags.nil?
                              options[:protocols] = protocols unless protocols.nil?
                              host_scan(options) },
  'raw_sniff'   => lambda { |eth,verb=0| raw_sniff(eth,verb) },
  'server'      => lambda { |command| server(command)},
  'hist'        => lambda { puts Readline::HISTORY.to_a },
  'set'         => lambda { |args|
                      key, value = args.split('=')
                      ENV[key] = value
                          },
  'logout' => lambda { exit },
  'banner' => lambda { banner() }
}

ENV['PROMPT'] = 'nwsh# '

def builtin?(program)
  BUILTINS.has_key?(program)
end

def call_builtin(program, *arguments)
  BUILTINS[program].call(*arguments)
end
