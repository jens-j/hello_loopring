try:
    # pysha3
    from sha3 import keccak_256
except ImportError:
    # pycryptodome
    from Crypto.Hash import keccak
    #keccak_256 = lambda *args: keccak.new(*args, digest_bits=256)
    
    # Changed this line for compatibility with python3.11
    keccak_256 = lambda arg: keccak.new(data=arg, digest_bits=256)
