#!/usr/bin/env ruby
require 'shellwords'

BUILTINS = {
  'cd'          => lambda { |dir| Dir.chdir(dir) }, 
  'exit'        => lambda { |code = 0| exit(code.to_i) },
  'quit'        => lambda { |code = 0| exit(code.to_i) },
  'exec'        => lambda { |*command| exec *command },
  'arp_scan'    => lambda { |target, iface| arp_scan(target, iface) },
  'arp_monitor' => lambda { |eth| arp_monitor(eth) },
  'hist'        => lambda { puts Readline::HISTORY.to_a },
  'set'         => lambda { |args|
                      key, value = args.split('=')
                      ENV[key] = value
                          },
  'logout' => lambda { exit }
}

ENV['PROMPT'] = 'nwsh# '

def builtin?(program)
  BUILTINS.has_key?(program)
end

def call_builtin(program, *arguments)
  BUILTINS[program].call(*arguments)
end

