require_relative './nw_server.rb'
require_relative './builtins.rb'

def server(command)
  
  trap "SIGINT" do
    puts "Exiting..."
    break
  end
  
  if (command == "start") 
    puts "Starting server"
    nwserver = NWServer.new('2000', '1', '60')
    nwserver.initssl
    
    ssl_context = OpenSSL::SSL::SSLContext.new()
    ssl_context.cert = OpenSSL::X509::Certificate.new(File.open(Dir.pwd+"/certs/certificate.pem"))
    ssl_context.key = OpenSSL::PKey::RSA.new(File.open(Dir.pwd+"/certs/server_private.pem"))
    # ssl_context.ssl_version = :SSLv23
    ssl_socket = OpenSSL::SSL::SSLServer.new(nwserver.get_server_socket, ssl_context)
  puts "OK"  
  
    th_server = Thread.new {
      loop do
        connection = ssl_socket.accept
        th = Thread.new {
                  begin
                    connection.puts $stdout
                    while (lineIn = connection.gets)
                      lineIn = lineIn.chomp
                      $stdout.puts "=> " + lineIn
                      program, *arguments = Shellwords.shellsplit(lineIn)
                      if builtin?(program) 
                        # lineOut = "You said: " + lineIn
                        # $stdout.puts "<= " + lineOut
                        # connection.puts lineOut
 
                        # Builtins return a value
                        ret = call_builtin(program, *arguments)
                        connection.puts ret
                      end
                    end
                    connection.close
                  rescue
                    $stderr.puts $!
                  end
                }
      end
      puts "closing"
    }
    th_server.join
    ssl_socket.close
    th.join
  end
  puts("COMMAND:" + command)
  if (command == "initssl")
    NWServer.initssl
  end
  
end

