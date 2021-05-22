require 'rex/text'

module Rex
module Powershell
    module Obfu
        MULTI_LINE_COMMENTS_REGEX = Regexp.new(/<#(.*?)#>/m)
        SINGLE_LINE_COMMENTS_REGEX = Regexp.new(/^\s*#(?!.*region)(.*$)/i)
        WINDOWS_EOL_REGEX = Regexp.new(/[\r\n]+/)
        UNIX_EOL_REGEX = Regexp.new(/[\n]+/)
        WHITESPACE_REGEX = Regexp.new(/\s+/)
        EMPTY_LINE_REGEX = Regexp.new(/^$|^\s+$/)