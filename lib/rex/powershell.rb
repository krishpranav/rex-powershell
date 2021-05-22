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
        