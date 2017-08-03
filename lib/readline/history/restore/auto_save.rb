require 'readline'
require 'readline/history/restore'
require 'fileutils'
require 'pathname'

module Readline
  module History
    class Restore
      module AutoSave
        AUTOSAVE_HOME = ENV['RUBY_READLINE_AUTOSAVE'] || ENV['HOME'] + '/.ruby_readline_history/'

        def scriptname(options = {}) # :don't use win32
          unless fn = ENV['_']
            raise "don't found scriptfile name"
          end
          home = Pathname.new(options[:history_home] || AUTOSAVE_HOME)
          home.mkpath unless home.directory?
          history = home.join(Pathname.new(fn).realpath.to_s.gsub('/', '%23'))
          Readline::History::Restore.new(history.to_s)
        end
        module_function :scriptname
      end
    end
  end
end
