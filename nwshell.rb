#!/usr/bin/env ruby

require 'shellwords'
require 'readline'
require 'require_all'
require_all 'lib'
require_all './lib/readline/history'
require 'pry'

#
# Smarter Readline to prevent empty and dups
#   1. Read a line and append to history
#   2. Quick Break on nil
#   3. Remove from history if empty or dup
#
def readline_with_hist_management

  @HISTORY_FILE = ".nwshell_history"

  # Autocompletion based on BUILTINS command list
  list = BUILTINS.keys.sort
  comp = proc { |s| list.grep( /^#{Regexp.escape(s)}/ ) }
  Readline.completion_append_character = " "
  Readline.completion_proc = comp

  Readline::History::Restore.new(Dir.home + "/#{@HISTORY_FILE}")

  # Trapping ^C to prevent users from exiting unadvertently
  stty_save = `stty -g`.chomp
  trap('INT') { system('stty', stty_save); exit }

  line = Readline.readline(ENV['PROMPT'], true)

  # Remove from history if empty or dup
  if line =~ /^\s*$/ or Readline::HISTORY.to_a[-2] == line or line.nil? or line.strip.length.zero?
    Readline::HISTORY.pop
  end

  line
end

def main
  loop do

    # Puts homedir path into a variable
    @HOME = File.expand_path('~')

    # Loads settings from file
    @settings = Settings.instance
    @settings.load("#{@HOME}/.nwshell.yaml")

    line = input = readline_with_hist_management

    comp = proc do |s|
      directory_list = Dir.glob("#{s}*")
    
      if directory_list.size > 0
  	directory_list
      else
	Readline::HISTORY.grep(/^#{Regexp.escape(s)}/)
      end
    end

    commands = split_on_pipes(line)

    placeholder_in = $stdin
    placeholder_out = $stdout
    pipe = []

    # If input == nil, then readline has caught a ^D
    exit if commands.nil?
    
    # Main loop
    commands.each_with_index do |command, index|
      program, *arguments = Shellwords.shellsplit(command)
     
      begin
        if builtin?(program)

          # Builtins return a value
          ret = call_builtin(program, *arguments)
          puts ret
        else
          if index+1 < commands.size
            pipe = IO.pipe
            placeholder_out = pipe.last
          else
            placeholder_out = $stdout
          end

          if (program != nil)
	    spawn_program(program, *arguments, placeholder_out, placeholder_in)
	  else
	    puts
	  end
        end

        placeholder_out.close unless placeholder_out == $stdout
        placeholder_in.close unless placeholder_in == $stdin
        placeholder_in = pipe.first
      rescue => errmsg
        puts "Error: #{errmsg}"
      end
    end

    Process.waitall
  end
end



main
