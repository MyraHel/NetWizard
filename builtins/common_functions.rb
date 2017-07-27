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
    
    exec program, *arguments
  }
end

def split_on_pipes(line)
  line.scan( /([^"'|]+)|["']([^"']+)["']/ ).flatten.compact
end
