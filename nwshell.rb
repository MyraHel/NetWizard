#!/usr/bin/env ruby

require 'shellwords'
require 'readline'
require 'require_all'
require_all 'lib'
require 'pry'


def main
  loop do
#    $stdout.print ENV['PROMPT']
#    line = $stdin.gets.strip
    line = input = Readline.readline(ENV['PROMPT'], true)
    Readline::HISTORY.pop if input == ""

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

    # If input == nil, then readline caught a ^D
    exit unless ! commands.nil?
      
    commands.each_with_index do |command, index|
      program, *arguments = Shellwords.shellsplit(command)
      
      if builtin?(program)
        call_builtin(program, *arguments)

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
	  print "\n"
	end

        placeholder_out.close unless placeholder_out == $stdout
        placeholder_in.close unless placeholder_in == $stdin
        placeholder_in = pipe.first
      end
    end

    Process.waitall
  end
end



main
