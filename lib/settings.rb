require 'singleton'
require 'yaml'

class Settings
  include Singleton

  attr_accessor :data

  def initialize
    
    @data = {}

  end

  def load (filename)
    # File must be valid YAML
    if File.exist?(filename)
      begin
        @data = YAML.load_file(filename)
      rescue ParseError
        nil
      end
    end
  end

  def add key, value
    @data[key] = value
  end

  def version
    '0.0.1'
  end
end
