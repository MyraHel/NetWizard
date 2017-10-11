#!/usr/bin/env ruby

require 'shellwords'
require 'readline'
require 'require_all'
require_all 'lib'
require 'pry'
require 'openssl'


class NWServer
  def initialize( port, timeout, verbose )
    @port = port        # the server listens on this port
    @timeout = timeout  # in seconds
    @verbose = verbose  # a boolean
    @server =
      begin
        TCPServer.new( @port )
      rescue SystemCallError => ex
        raise "cannot initialize tcp server for port #{@port}: #{ex}"
      end
  end

  def get_server_socket
    return @server
  end

  def get_socket
    # Process incoming connections and messages.

    # When a message has arrived, we return the connection's TcpSocket.
    # Applications can read from this socket with gets(),
    # and they can respond with write().

    # one select call for three different purposes -> saves timeouts
    ios = select( [@server]+@connections, nil, @connections, @timeout ) or
      return nil
    # disconnect any clients with errors
    ios[2].each do |sock|
      sock.close
      @connections.delete( sock )
      raise "socket #{sock.peeraddr.join(':')} had error"
    end
    # accept new clients
    ios[0].each do |s|
      # loop runs over server and connections; here we look for the former
      s==@server or next
      client = @server.accept or
        raise "server: incoming connection, but no client"
      @connections << client
      @verbose and
        puts "server: incoming connection no. #{@connections.size} from #{client.peeraddr.join(':')}"
      # give the new connection a chance to be immediately served
      ios = select( @connections, nil, nil, @timeout )
    end

    # process input from existing client
    ios[0].each do |s|
      # loop runs over server and connections; here we look for the latter
      s==@server and next

      # since s is an element of @connections, it is a client created
      # by @server.accept, hence a TcpSocket < IPSocket < BaseSocket
      if s.eof?
        # client has closed connection
        @verbose and
          puts "server: client closed #{s.peeraddr.join(':')}"
        @connections.delete(s)
        next
      end
      @verbose and
        puts "server: incoming message from #{s.peeraddr.join(':')}"
      return s # message can be read from this
    end

    return nil # no message arrived
  end


  def initssl

    if not (File.file?(Dir.pwd+'/certs/server_private.pem'))
      key = OpenSSL::PKey::RSA.new 2048
      open Dir.pwd+'/certs/server_private.pem', 'w' do |io| io.write key.to_pem end
      open Dir.pwd+'/certs/server_public.pem', 'w' do |io| io.write key.public_key.to_pem end

      name = OpenSSL::X509::Name.parse 'CN=nwserver/DC=nwserver'

      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 0
      cert.not_before = Time.now
      cert.not_after = Time.now + 3600

      cert.public_key = key.public_key
      cert.subject = name

      cert.issuer = name
      cert.sign key, OpenSSL::Digest::SHA1.new

      open Dir.pwd+'/certs/certificate.pem', 'w' do |io| io.write cert.to_pem end
    end
  end
  
end