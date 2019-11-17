require 'readline'
require 'fileutils'
require 'pathname'

module Readline
  module History
    class Restore

      def initialize(filename, options = {})
        raise 'Filename for history is mandatory' unless filename && !filename.empty?

        @filepath = Pathname.new filename
        load_history @filepath
        @history_limit = options[:history_limit] || 10000
        @finalizer = at_exit { save_history @filepath }
        self
      end

      attr_accessor :history_limit, :finalizer

      # Loads history from a file
      #
      # filepath - the file to load history from
      #
      # Examples
      #
      #   load_history(Dir.home + ".some_history")
      #
      # Return true if successful, false otherwise
      def load_history(filepath)
        begin
          filepath.readlines.each { |line| Readline::HISTORY << line.chomp  } if filepath.file?
        rescue
          return false
        end
        return true
      end

      # Saves history to a file
      #
      # filepath - the file to save history to
      #
      # Examples
      #
      #   save_history(Dir.home + ".some_history")
      #
      # Return true if successful, false otherwise
      def save_history(filepath)
        begin
          filepath.parent.mkpath unless filepath.parent.directory?
          filepath.open('w') do |f|
            Readline::HISTORY.to_a.last(@history_limit).each {|l| f.puts l unless l.empty? }
          end
        rescue
          return false
        end
        return true
      end
    end
  end
end
