#!/usr/bin/env ruby

class File
  def preserve_position
    position = tell
    r = yield
    seek(position)
    r
  end
end

require_relative 'hex_inspect'

if ARGV.size != 1
  $stderr.puts "Usage: crypt32_dll_dump.rb DLLFILE"
end

filename = ARGV.fetch(0)
file_size = File.size(filename)

def search_pe_file(f)
  f.seek(0x3C)
  pe_signature_offset = f.read(4).unpack('L<')[0]
  f.seek(pe_signature_offset)
  pe_magic = f.read(4)
  raise "Bad PE signature" if pe_magic != "PE\x00\x00"

  coff_header = f.read(20).unpack('S<S<L<L<L<S<S<')
  machine_type, section_count, creation_time, symbol_table_offset, symbol_count,
    optional_header_size, _ = coff_header

  machine_type_name = {
    0x8664 => "x64",
    0x014c => "i386",
  }.fetch(machine_type, "unknown")
  time_string = Time.at(creation_time).utc.strftime "%Y-%m-%d %H:%M:%S"
  puts "Machine type: #{machine_type_name}"
  puts "Creation time: #{time_string}"

  optional_header = f.read(optional_header_size)

  resource_section_offset = nil
  resource_section_size = nil
  resource_section_virtual_address = nil
  section_count.times do
    section_header = f.read(40).unpack('Z8L<L<L<L<L<L<S<S<L<')
    name, virtual_size, virtual_address, raw_data_size, raw_data_offset,
      relocations_offset, _, relocations_size, _, _ = section_header
    if name == ".rsrc"
      resource_section_size = raw_data_size
      resource_section_offset = raw_data_offset
      resource_section_virtual_address = virtual_address
    end
  end

  if !resource_section_offset
    raise "Could not find .rsrc section."
  end
  puts "Resource section size: " + resource_section_size.to_s
  search_resource_section(f, resource_section_offset, resource_section_virtual_address)
end

def search_resource_section(f, section_offset, virtual_address)
  search_resource_directory(f, section_offset, virtual_address, section_offset, [])
end

def search_resource_directory(f, section_offset, virtual_address, offset, path)
  f.seek(offset)

  dir_header = f.read(16).unpack('L<L<S<S<S<S<')
  _, time, major, minor, name_entries_count, id_entries_count = dir_header

  entries = []
  name_entries_count.times do
    name_offset, offset = f.read(8).unpack('L<L<')
    type = offset[31] == 1 ? :directory : :leaf
    offset = section_offset + (offset & 0x7FFF_FFFF)
    name_offset = section_offset + (name_offset & 0x7FFF_FFFF)
    name = f.preserve_position do
      f.seek(name_offset)
      name_size = f.read(2).unpack('S<')[0] * 2
      f.read(name_size).force_encoding('UTF-16LE').encode('UTF-8')
    end
    entries << [type, name, offset]
  end
  id_entries_count.times do
    id, offset = f.read(8).unpack('L<L<')
    type = offset[31] == 1 ? :directory : :leaf
    offset = section_offset + (offset & 0x7FFF_FFFF)
    entries << [type, id, offset]
  end

  entries.each do |type, id, offset|
    if type == :directory
      search_resource_directory(f, section_offset, virtual_address, offset, path + [id])
    else
      search_resource_leaf(f, section_offset, virtual_address, offset, path + [id])
    end
  end
end

def search_resource_leaf(f, section_offset, virtual_address, offset, path)
  f.seek(offset)
  leaf = f.read(16).unpack('L<L<L<L<')
  data_offset, size, _, _ = leaf
  data_offset += section_offset - virtual_address
  puts "Leaf %s, offset 0x%X, size %d" % [path.inspect, data_offset, size]
  f.seek(data_offset)

  puts 'interesting!' if data_offset <= 0x13548B && 0x13548B < data_offset + size

  case path.first
  when 'AUTHROOTS', 'UPDROOTS'
    parse_cert_sst(f, data_offset, size)
  when 'AUTHROOTSTL'
    parse_cert_stl(f, data_offset, size)
  end
end

# Parse a Microsoft Serialized Certificate Store (SST)
def parse_cert_sst(f, offset, size)
  f.seek(offset)
  start = f.read(8)
  if start != "\x00\x00\x00\x00CERT"
    raise "Cert list at 0x%x does not start with magic sequence." % offset
  end

  # TODO:
end

def parse_cert_stl(f, offset, size)
  f.seek(offset)
  stl = f.read(size)

  p stl[0,400]

  # TODO

  #puts start.hex_inspect
  #puts start.inspect
  #require 'openssl'
  #pk = OpenSSL::PKCS7.read_smime(stl)
  #puts pk.certificates.size
end

$stdout.sync = true
f = File.open(filename, 'rb')
search_pe_file(f)
