require_relative './nw_server.rb'

def server(command)
  
  trap "SIGINT" do
    puts "Exiting..."
    break
  end
  
  
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
                  while (lineIn = connection.gets)
                    lineIn = lineIn.chomp
                    $stdout.puts "=> " + lineIn
                    lineOut = "You said: " + lineIn
                    $stdout.puts "<= " + lineOut
                    connection.puts lineOut
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

  
  if (command == "initssl")
    nwserver.initssl
  end
  
end

