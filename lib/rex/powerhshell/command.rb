module Rex
module Powershell
module Command

    def self.encode_script(script_in, eof=nil, opts={})
        psh = Rex::Powershell::Script.new(script_in)
        psh.strip_comments if opts[:strip_comments]
        psh.strip_whitespaces if opts[:strip_whitespaces]
        psh.sub_vars if opts[:sub_vars]
        psh.sub_funcs if opts[:sub_funcs]
        psh.encode_code(eof)
    end

    def self.decode_script(script_in)
        Rex::Powershell::Script.new(script_in).decode_code
    end

    def self.compress_script(script_in, eof=nil, opts={})
        psh = Rex::Powershell::Script.new(script_in)
        psh.strip_comments if opts[:strip_comments]
        psh.strip_whitespaces if opts[:strip_whitespaces]
        psh.sub_vars if opts[:sub_vars]
        psh.sub_funcs if opts[:sub_funcs]
        psh.compress_code(eof)
    end

    def self.decompress_script(script_in)
        Rex::Powershell::Script.new(script_in).decompress_code
    end
    