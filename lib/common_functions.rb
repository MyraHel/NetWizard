def spawn_program(program, *arguments, placeholder_out, placeholder_in)
  fork {
    unless placeholder_out == $stdout
      $stdout.reopen(placeholder_out)
      placeholder_out.close
    end

    unless placeholder_in == $stdin
      $stdin.reopen(placeholder_in)
      placeholder_in.close
    end

    begin
      exec program, *arguments
    rescue SystemCallError => e
      puts "Error: #{e}"
    end
  }
end

def split_on_pipes(line)
  if line.nil?
    nil
  else
    line.scan( /([^"'|]+)|["']([^"']+)["']/ ).flatten.compact
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
