#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Converted from Python to Ruby (best-effort)
# - Requires 'cfpropertylist' gem to parse binary plists
# - Uses OpenSSL for AES-128-CBC decryption (IV = 16 zero bytes)
#
# Author: converted for you
# Original: Willi Ballenthin / modified by h00die

require 'logger'
require 'openssl'
require 'cfpropertylist' # gem install cfpropertylist
require 'base64'
require 'fileutils'
require 'pathname'

logger = Logger.new($stdout)
logger.level = Logger::INFO

INPUT_GLOB = '/Users/*/Library/Saved Application State/com.apple.Terminal.savedState/'
OUTPUT_PATH = '/tmp'

def aes_decrypt(key_bytes, ciphertext, iv = "\x00" * 16)
  cipher = OpenSSL::Cipher.new('AES-128-CBC')
  cipher.decrypt
  cipher.key = key_bytes
  cipher.iv = iv
  plaintext = cipher.update(ciphertext) + cipher.final
  plaintext
rescue OpenSSL::Cipher::CipherError => e
  raise "AES decrypt failed: #{e.message}"
end

# parse the inner "archived" plist from the decrypted window state
def parse_plaintext(buf)
  # struct layout (big endian)
  # uint32 unk1
  # uint32 class_name_size
  # char[class_name_size] class_name
  # char[4] magic (expect "rchv")
  # uint32 size
  # uint8 buf[size] -> this is a bplist (NSData of an NSKeyedArchiver object)
  raise 'buffer too small' if buf.bytesize < 16

  unk1, class_name_size = buf[0,8].unpack('N2')
  offset = 8
  class_name = buf[offset, class_name_size]
  offset += class_name_size
  magic = buf[offset, 4]
  offset += 4
  size = buf[offset, 4].unpack1('N')
  offset += 4

  raise "unexpected magic: #{magic.inspect}" unless magic == 'rchv'

  plistbuf = buf[offset, size]
  raise 'inner plist missing or truncated' if plistbuf.nil? || plistbuf.bytesize < 1

  # parse plistbuf as binary plist via CFPropertyList
  plist = CFPropertyList::List.new(data: plistbuf)
  CFPropertyList.native_types(plist.value)
end

WindowState = Struct.new(:size, :meta, :plaintext, :state)

def parse_window_state(plist_array, buf)
  # Read header: >4s4sII
  raise 'invalid magic size' if buf.bytesize < 16
  magic, version, window_id, size = buf[0,16].unpack('A4A4NN')

  raise 'invalid magic' unless magic == 'NSCR'
  raise 'invalid version' unless version == '1000'

  # ciphertext is bytes from offset 16 up to 'size'
  raise 'buffer smaller than declared size' if size > buf.bytesize
  ciphertext = buf[16, size - 16]

  # find corresponding window metadata in plist_array
  # plist_array is expected to be an Array of Hashes
  window_meta = nil
  if plist_array.respond_to?(:each)
    plist_array.each do |entry|
      # native_types conversion: keys can be strings
      if entry.is_a?(Hash)
        # some plists may use symbols or strings; coerce to string keys
        entry_keyed = {}
        entry.each { |k, v| entry_keyed[k.to_s] = v }
        if entry_keyed['NSWindowID'] == window_id
          window_meta = entry_keyed
          break
        end
      end
    end
  end

  unless window_meta
    window_ids = []
    if plist_array.respond_to?(:map)
      plist_array.each do |p|
        if p.is_a?(Hash)
          p_keyed = {}
          p.each { |k, v| p_keyed[k.to_s] = v }
          window_ids << (p_keyed['NSWindowID'] || 'unknown')
        end
      end
    end
    raise ArgumentError.new("missing window metadata, wanted: #{window_id}, found: #{window_ids.join(', ')}"), size
  end

  # window_meta is a Hash containing 'NSDataKey' which should be raw bytes
  # CFPropertyList will usually represent data as a Ruby String (binary)
  key = window_meta['NSDataKey']
  unless key.is_a?(String)
    # sometimes CFPropertyList returns CFData wrapper; attempt to coerce
    key = key.to_s rescue nil
  end
  raise 'missing NSDataKey for window' if key.nil? || key.bytesize == 0

  # ensure key length is 16 for AES-128
  key_bytes = key
  if key_bytes.bytesize != 16
    logger.warn("NSDataKey length is #{key_bytes.bytesize}, expecting 16. Truncating/padding to 16 bytes.")
    key_bytes = key_bytes.ljust(16, "\x00")[0,16]
  end

  plaintext = aes_decrypt(key_bytes, ciphertext)
  state = parse_plaintext(plaintext)

  WindowState.new(size, window_meta, plaintext, state)
end

def parse_window_states(plist, data)
  buf = data.dup
  results = []
  while buf.bytesize > 16
    unless buf.start_with?('NSCR')
      raise 'invalid magic at window states stream'
    end

    begin
      ws = parse_window_state(plist, buf)
    rescue ArgumentError => e
      # Python code used exception args to carry a size param sometimes; ignore similarly
      logger.warn("failed to parse window state: #{e.message}")
      if e.respond_to?(:to_a) && e.to_a.size > 1
        # not likely in Ruby; try to skip by size if second arg present
        size_to_skip = e.to_a[1] rescue nil
        if size_to_skip && size_to_skip > 0 && size_to_skip < buf.bytesize
          buf = buf.byteslice(size_to_skip, buf.bytesize - size_to_skip) || ''
          next
        end
      end
      break
    rescue => e
      logger.warn("failed to parse window state: #{e.class}: #{e.message}")
      break
    end

    results << ws
    # advance buffer by ws.size
    if ws.size <= 0 || ws.size > buf.bytesize
      break
    end
    buf = buf.byteslice(ws.size, buf.bytesize - ws.size) || ''
  end
  results
end

def main
  input_paths = Dir.glob(INPUT_GLOB)
  if input_paths.empty?
    logger.info("no saved-state input paths found for pattern: #{INPUT_GLOB}")
  end

  input_paths.each do |inputpath|
    logger.info("input: #{inputpath}")

    windows_plist_path = File.join(inputpath, 'windows.plist')
    data_data_path = File.join(inputpath, 'data.data')

    unless File.exist?(windows_plist_path)
      logger.warn("windows.plist not found: #{windows_plist_path}")
      next
    end

    unless File.exist?(data_data_path)
      logger.warn("data.data not found: #{data_data_path}")
      next
    end

    begin
      list = CFPropertyList::List.new(file: windows_plist_path)
      windows = CFPropertyList.native_types(list.value)
    rescue => e
      logger.error("failed to parse windows.plist: #{e.class}: #{e.message}")
      next
    end

    data = File.binread(data_data_path)

    parse_window_states(windows, data).each_with_index do |window, i|
      if window.meta.nil? || window.meta.empty?
        logger.info("no data for window#{i}")
        next
      end

      unless window.meta.key?('NSTitle')
        logger.info("skipping window, no title")
        next
      end

      filename = "window#{i}.json"
      filepath = File.join(OUTPUT_PATH, filename)
      logger.info("writing: #{filepath}")
      puts "Window #{i} Title: #{window.meta['NSTitle']}"

      # The 33rd object is the start of the window data in the archived plist.
      objects = window.state['$objects']
      if !objects || objects.size <= 32
        next
      end

      shell_content = objects[33..-1] || []
      output_lines = []
      shell_content.each do |line|
        if line.is_a?(String)
          output_lines << line.force_encoding('UTF-8')
        elsif line.respond_to?(:to_s)
          output_lines << line.to_s
        end
      end

      # Write the concatenated output to /tmp/<i> like the Python script
      begin
        outpath = File.join('/tmp', i.to_s)
        File.open(outpath, 'wb') do |f|
          f.write(output_lines.join)
        end
      rescue => e
        logger.error("failed to write /tmp/#{i}: #{e.class}: #{e.message}")
      end
    end
  end
end

if __FILE__ == $0
  main
end
