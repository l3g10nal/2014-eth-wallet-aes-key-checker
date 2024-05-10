from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Hash import keccak
import eth_keys

encseed_hex = '408dc3157574d5c0ace8d8d5bc2959b9646f64a867be7625a51dc36335155ec6ac2721aa28039e3d20679c65fe3b2eabb9254bc7519827cbef3631e1633de4077bc3392da5b58634503a37ad5545b552f806b13db9dd903c350947810b331b2e3630cb7ee391d8b4d635036af3e085a3b86b24ecff4ca6906cf6a5b116db629054634586def851c87ef2b824e658af675022dbaf0f2cbec0ebefd9f49da865ae8066e89a25f619506e7e03918889488ec32c85b750f775bedb702bdf8529606edf713219c6b1efea8ecae29b8aff63ca69060d932fffd2b8ea20b830fc308b28b31e62fb85a6fd495cb85681be318bdfdbabcdaa05228a93e76e02da050c94a62384b579ace24976489730798cebc82fbb590eb217b4d711792d422ccd7952b481ee71be17186a41774066e8ed6a29ae13d02ec8b3dc33b7b6e141f9d199e58b9f18a28ee2c99b95e954e86583d3638613f734769be9c2812c5d47b2efa1d332e8a8cd356d1d128ead0534456ee161d6c1726f999d18d33b4d8ae733a439fa61e1c1fb9f6b8baaa7a2a786349f5464300a9646774974fc326359ac58c04574b83cbbebbb2f961a0b411fd9b8e1f3a3c3c42662fba299b3a64b30f0862f3a162526a34f4d2f4d4ffe3b0378604b29a1f43ac73d7061c353fa465b6f6078da777bee5a98d08e3619acb46dbac5bed1c1d8446c6b7489a13c3c10c0b2063d0413d8ecd38d00f3d64adafff8005dd10496bb4874ff1df7ca8d4d81e863580e19fb74d7f50972fb3d92360a90864253fd0ff152eed710b150955000cdb87994e78adb42a3948197d82b38fff4eb3c49e881e5d84d5af9091129cc8bf85efbb1f3b8a244ba0edbb59d0ca5db33e04b7680cc52'
address= '0x6Eb2DB307c563AABa2cC967fff47E46970EfBCF3' # Target address
aes_key_hex = 'f9deabc99461685b85f9fd3f611a3163' # Example AES Key in Hex String

aes_key = bytes.fromhex(aes_key_hex)
iv = bytes.fromhex(encseed_hex[:32])
encseed = bytes.fromhex(encseed_hex[32:])  # Adjusted comment placement

# Check if the IV is 16 bytes long
if len(iv) != 16:
    raise ValueError("IV must be 16 bytes long.")

# Initialize the cipher for decryption
cipher = AES.new(aes_key, AES.MODE_CBC, iv)

# Decrypt and unpad the data
try:
    decrypted_data = unpad(cipher.decrypt(encseed), AES.block_size)
    print("Decrypted data:", decrypted_data.hex())
    print("Decrypted data length:", len(decrypted_data), "bytes")

    # Generate keccak hash of the decrypted data
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(decrypted_data)  # Directly use the byte data
    private_key_bytes = keccak_hash.digest()
    
    # Convert bytes to Eth_PrivateKey
    private_key = eth_keys.keys.PrivateKey(private_key_bytes)

    # Generate public key and Ethereum address
    public_key = private_key.public_key
    eth_address = public_key.to_checksum_address()
    
    #Comparison of addresses
    if eth_address.lower() == address.lower():
        print("Calculated Ethereum Address matches the expected address:", eth_address)
    else:
        print("Calculated Ethereum Address:", eth_address)
        print("Expected Ethereum Address should be:", address)
   
except ValueError as e:
    print("Error during decryption or encryption:", e)
