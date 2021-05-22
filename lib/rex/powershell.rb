# requires
require 'rex/powershell/version'
require 'rex/powershell/output'
require 'rex/powershell/parser'
require 'rex/powershell/obfu'
require 'rex/powershell/function'
require 'rex/powershell/param'
require 'rex/powershell/script'
require 'rex/powershell/templates'
require 'rex/powershell/payload'
require 'rex/powershell/psh_methods'
require 'rex/powershell/command'


module Rex
    module Powershell

        def self.read_script(script_path)
            Rex::Powershell::Script.new(script_path)
        end

        def self.make_subs(script, subs)
            if ::File.file?(script)
                script = ::File.read(script)
            end

            subs.each do |set|
                script.gsub!(set[0], set[1])
            end

            script 
        end

        def self.process_subs(subs)
            return [] if subs.nil? or subs.empty?
            new_subs = []
            subs.split(';').each do |set|
                new_subs << set.split(',', 2)
            end

            new_subs
        end

        def self.to_powershell(str, name = "buf")
            return Rex::Powershell::Script.to_byte_array(str, name)
        end
    end
end
