module Rex
module Powershell
    class Function
        FUNCTION_REGEX = Regexp.new(/\[(\w+\[\])\]\$(\w+)\s?=|\[(\w+)\]\$(\w+)\s?=|\[(\w+\[\])\]\s+?\$(\w+)\s+=|\[(\w+)\]\s+\$(\w+)\s?=/i)
        PARAMETER_REGEX = Regexp.new(/param\s+\(|param\(/im)
        attr_accessor :code, :name, :params

        include Output
        include Parser
        include Obfu

        def initialize(name, code)
            @name = name
            @code = code
            populate_params
        end

        