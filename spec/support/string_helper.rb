# frozen_string_literal: true

module StringHelper
  def utf16le(str)
    str.encode('UTF-16LE')
  end
end