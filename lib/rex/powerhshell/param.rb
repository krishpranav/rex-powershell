module Rex
module Powershell
    class Param
        attr_accessor :klass, :name
        def initialize(klass, name)
            @klass = klass.strip
            @name = name.strip.gsub(\/s|,/, '')
        end

        def to_s
            "[#{klass}]$#{name}"
        end
    end
end
end
