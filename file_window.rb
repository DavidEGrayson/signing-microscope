require 'forwardable'

class FileWindow
  attr_reader :real_file, :window_offset, :window_size

  extend Forwardable
  def_delegator :@real_file, :preserve_position

  def initialize(file, offset, size)
    if file.respond_to?(:real_file)
      offset += file.window_offset
      file = file.real_file
    end
    @real_file = file
    @window_offset = offset
    @window_size = size
    seek(0)
  end

  def seek(position)
    @real_file.seek(@window_offset + position)
  end

  def tell
    @real_file.tell - @window_offset
  end

  def read(size = max_read_size)
    @real_file.read(size)
  end

  def max_read_size
    @window_size - tell
  end
end
