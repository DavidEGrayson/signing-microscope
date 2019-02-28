#!/usr/bin/env ruby

require_relative 'binary_reader'
require_relative 'hex_inspect'

if ARGV.size != 1
  $stderr.puts "Usage: crypt32_dll_dump.rb DLLFILE"
end

filename = ARGV.fetch(0)
file_size = File.size(filename)

check_offset = Proc.new do |offset, size = 0|
  raise "Bad file offset" if offset >= file_size
  raise "Bad file are length" if offset + size >= file_size
end

f = File.open(filename, 'rb')
f.seek(0x3C)
pe_signature_offset = f.read_u32
check_offset.(pe_signature_offset)
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
puts "Machine type: #{machine_type_name}"

optional_header = f.read(optional_header_size)

resource_section_offset = nil
resource_section_size = nil
section_count.times do
  section_header = f.read(40).unpack('Z8L<L<L<L<L<L<S<S<L<')
  name, virtual_size, virtual_address, raw_data_size, raw_data_offset,
    relocations_offset, _, relocations_size, _, _ = section_header
  if name == ".rsrc"
    resource_section_size = raw_data_size
    resource_section_offset = raw_data_offset
  end
end

if !resource_section_offset
  raise "Could not find .rsrc section."
end
check_offset.(resource_section_offset, resource_section_size)

f.seek(resource_section_offset)
p f.read(resource_section_size)
