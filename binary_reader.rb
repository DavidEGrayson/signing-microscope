module BinaryReader
  def read_byte
    read(1).ord
  end

  def read_u16
    read(2).unpack('S<')[0]
  end

  def read_s16
    read(2).unpack('s<')[0]
  end

  def read_u32
    read(4).unpack('L<')[0]
  end

  def read_s32
    read(4).unpack('l<')[0]
  end

  def read_u64
    read(8).unpack('Q<')[0]
  end
end

class IO
  include BinaryReader
end
