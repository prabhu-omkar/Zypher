require 'openssl'

# A top-level constant is not resolved through a wrapper in Ruby, so the
# resolved case below passes a literal. See
# test_taint_scanner.py::test_module_level_constants_are_a_known_boundary.
LEGACY_BITS = 1024

def build_key(bits)
  OpenSSL::PKey::RSA.new(bits)
end

def legacy_key
  build_key(1024)
end

def const_key
  build_key(LEGACY_BITS)
end

def build_cipher(name)
  OpenSSL::Cipher.new(name)
end

def legacy_cipher
  build_cipher('DES-EDE3-CBC')
end
