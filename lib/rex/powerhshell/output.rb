# -*- coding: binary -*-

require 'zlib'
require 'rex/text'

module Rex
module Powershell
  module Output

    def to_s
      code
    end


    def size
      code.size
    end

    def to_s_lineno
      numbered = ''
      code.split(/\r\n|\n/).each_with_index do |line, idx|
        numbered << "#{idx}: #{line}"
      end

      numbered
    end



    def deflate_code(eof = nil)
      # Compress using the Deflate algorithm
      compressed_stream = ::Zlib::Deflate.deflate(code,
                                                  ::Zlib::BEST_COMPRESSION)

      # Base64 encode the compressed file contents
      encoded_stream = Rex::Text.encode_base64(compressed_stream)

      # Build the powershell expression
      # Decode base64 encoded command and create a stream object
      psh_expression =  "$s=New-Object System.IO.MemoryStream(,"
      psh_expression << "[System.Convert]::FromBase64String('#{encoded_stream}'));"
      # Read & delete the first two bytes due to incompatibility with MS
      psh_expression << '$s.ReadByte();'
      psh_expression << '$s.ReadByte();'
      # Uncompress and invoke the expression (execute)
      psh_expression << 'IEX (New-Object System.IO.StreamReader('
      psh_expression << 'New-Object System.IO.Compression.DeflateStream('
      psh_expression << '$s,'
      psh_expression << '[System.IO.Compression.CompressionMode]::Decompress)'
      psh_expression << ')).ReadToEnd();'

      psh_expression << "echo '#{eof}';" if eof

      @code = psh_expression
    end


    def encode_code(eof = nil)
      @code = Rex::Text.encode_base64(Rex::Text.to_unicode(code))
    end


    def decode_code
      @code = Rex::Text.to_ascii(Rex::Text.decode_base64(code))
    end

    def gzip_code(eof = nil)
      # Compress using the Gzip algorithm
      compressed_stream = Rex::Text.gzip(code)

      # Base64 encode the compressed file contents
      encoded_stream = Rex::Text.encode_base64(compressed_stream)

      # Build the powershell expression
      # Create and execute script lock fed by the IO.StreamReader
      psh_expression = '&([scriptblock]::create((New-Object System.IO.StreamReader('
      # Feed StreamREader from a GzipStream
      psh_expression << 'New-Object System.IO.Compression.GzipStream('
      # GzipStream operates on the Memory Stream
      psh_expression << '(New-Object System.IO.MemoryStream(,'
      # MemoryStream consists of base64 encoded compressed data
      psh_expression << "[System.Convert]::FromBase64String('#{encoded_stream}')))"
      # Set the GzipStream to decompress its MemoryStream contents
      psh_expression << ',[System.IO.Compression.CompressionMode]::Decompress)'
      # Read the decoded, decompressed result into scriptblock contents
      psh_expression << ')).ReadToEnd()))'

      psh_expression << "echo '#{eof}';" if eof

      @code = psh_expression
    end

    def compress_code(eof = nil, gzip = true)
      @code = gzip ? gzip_code(eof) : deflate_code(eof)
    end

    def decompress_code
      # Extract substring with payload
      encoded_stream = @code.scan(/FromBase64String\('(.*)'/).flatten.first
      # Decode and decompress the string
      unencoded = Rex::Text.decode_base64(encoded_stream)
      begin
        @code = Rex::Text.ungzip(unencoded) || Rex::Text.zlib_inflate(unencoded)
      rescue Zlib::GzipFile::Error
        begin
          @code = Rex::Text.zlib_inflate(unencoded)
        rescue Zlib::DataError => e
          raise RuntimeError, 'Invalid compression'
        end
      end

      @code
    end
  end
end
end
