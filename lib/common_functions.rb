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
