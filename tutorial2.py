# Run with python -i tutorial.py
# and call individual functions from the interpreter

from __future__ import print_function
import ptrace.debugger
import subprocess
import binascii
import signal
import struct

def step():
    process.singleStep()
    process.waitSignals(signal.SIGTRAP)

def run_asm(instr):
    old_rip = process.getreg('rip')
    old_values = process.readBytes(old_rip, len(instr))
    process.writeBytes(old_rip, instr)
    step()
    # Rewind rip unless the instruction altered it.
    if process.getreg('rip') == old_rip + len(instr):
        process.setreg('rip', old_rip)
    process.writeBytes(old_rip, old_values)

def func_call(func_addr):
    old_rip = process.getreg('rip')
    old_regs = process.getregs()
    old_values = process.readBytes(old_rip, 6)
    diff = func_addr - (old_rip + 5)
    new_values = chr(0xE8) + struct.pack('i', diff) + chr(0xCC)
    process.writeBytes(old_rip, new_values)
    step()
    new_rip = process.getreg('rip')
    assert(new_rip == func_addr)
    process.cont()
    process.waitSignals(signal.SIGTRAP)
    process.writeBytes(old_rip, old_values)
    process.setregs(old_regs)

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

def variables(filename="a.out"):
    f = ELFFile(open(filename))
    symb_sections = [section for section in f.iter_sections()
                     if isinstance(section, SymbolTableSection)]
    variables = {symb.name:symb['st_value'] for section in symb_sections
                 for symb in section.iter_symbols()}
    return variables

def reserve_memory(size):
    old_regs = process.getregs()
    regs = {'rax': syscalls['mmap'], 'rdi': 0, 'rsi': size,
            'rdx': MMAP_PROT_BITMASK['PROT_ALL'],
            'r10': MAP_PRIVATE | MAP_ANONYMOUS,
            'r8': -1, 'r9': 0}
    for reg, value in regs.items():
        process.setreg(reg, value)
    run_asm(chr(0x0f) + chr(0x05))
    result = process.getreg('rax')
    process.setregs(old_regs)
    return result

def safe_func_call(func_addr):
    # import pdb; pdb.set_trace()
    old_rip = process.getreg('rip')
    old_regs = process.getregs()
    tmp_addr = reserve_memory(6)
    process.setreg('rip', tmp_addr)
    # call rax
    process.setreg('rax', func_addr)
    new_values = chr(0xff) + chr(0xd0) + chr(0xcc)
    process.writeBytes(tmp_addr, new_values)
    step()

    new_rip = process.getreg('rip')
    assert(new_rip == func_addr)
    process.cont()
    process.waitSignals(signal.SIGTRAP)
    process.setregs(old_regs)

def look(addr=None):
    print("ip:", hex(process.getreg('rip')))
    for i, instr in enumerate(process.disassemble(start=addr)):
        hexa = instr.hexa
        hexa = ' '.join(hexa[i:i+2] for i in range(0, len(hexa), 2))
        print(str(i).ljust(4), hexa.ljust(24), instr.text.lower())

def read_int(var_name):
    addr = start + c_variables[var_name]
    type_, size = 'h', 2
    return struct.unpack(type_, process.readBytes(addr, size))[0]

def write_int(var_name, value):
    addr = start + c_variables[var_name]
    type_, size = 'h', 2
    process.writeBytes(addr, struct.pack(type_, value))

def c_func_call(func_name, _start=None):
    _start = start if _start is None else _start
    safe_func_call(_start + c_variables[func_name])

from collections import defaultdict

def memory_maps():
    mmap = defaultdict(dict)
    mmaped_counter = 0
    for line in open("/proc/%s/maps" % pid).readlines():
        if len(line.split()) == 5:
            line += "[mmaped-%s]" % mmaped_counter
            mmaped_counter += 1
        region, permissions, offset, dev, inode, filename = line.split()
        start, end = [int(x, 16) for x in region.split("-")]
        mmap[filename][permissions] = {"start": start, "end": end,
                                       "offset": int(offset, 16),
                                       "dev": dev, "inode": int(inode)}
    return mmap

def find_section(mmap, address):
    for filename in mmap:
        for perm, region in mmap[filename].items():
            if region['start'] <= address <= region['end']:
                return (filename, perm), address - region['start']

def load_lib_vars(filename):
    line1 = [l for l in open("/proc/%s/maps" % pid).readlines()
             if l.endswith(filename + '\n')][0]

    starts[filename] = int(line1.split("-")[0], 16)
    lib_vars = variables(filename)
    c_variables.update(lib_vars)

import shlex

def run_c(c_lines):
    program = """
    #include <stdio.h>
    %s;
    void run_once(){
    %s
    }""" % (";\n".join(c_globals), c_lines.encode('string_escape'))
    command = "gcc -shared -x c -o run_once.so -fPIC -"
    gcc_proc = subprocess.Popen(shlex.split(command), stdin=subprocess.PIPE)
    out = gcc_proc.communicate(input=program)
    gcc_proc.stdin.close()
    if not gcc_proc.returncode: # No error
        c_func_call("reload_run_once")
        load_lib_vars('run_once.so')
        c_func_call("run_once", starts['run_once.so'])

import elfreader

def get_stack():
    bottom = process.getreg('rsp')
    top = process.getreg('rbp')
    stack_bytes = process.readBytes(bottom, top - bottom)
    return [struct.unpack('l', stack_bytes[i*8: (i+1)*8])[0]
            for i in xrange(len(stack_bytes) / 8)]

def line_numbers():
    elfreader.load_dwarf_info(mmap)
    lines = [elfreader.address_info(find_section(mmap, frame)[1])
             for frame in get_stack() + [process.getreg('rip')]
             if find_section(mmap, frame)]
    return [line for line in lines if line is not None]

def save_state(skip_save=False):
    global child_pid, parent_process, child_process, process
    c_func_call('make_fork')    
    child_pid = read_int('pid')
    parent_process = process
    child_process = process = debugger.addProcess(child_pid, False)
    process.cont()
    if not skip_save:
        states.append(parent_process)

def load_state(state=None):
    global process
    state = states[-1] if state is None else state
    process.kill(9)
    process = state
    save_state(True)

import atexit

def cleanup():
    print("Cleaning up child processes.")
    for proc in [process] + states:
        try:
            proc.kill(9)
        except OSError:
            pass

def wait_for_count(min_count=1):
    while read_int('count') < min_count:
        step()

if __name__ == '__main__':
    shell_command = ["./a.out"]
    child_proc = subprocess.Popen(shell_command)
    pid = child_proc.pid
    debugger = ptrace.debugger.PtraceDebugger()
    process = debugger.addProcess(pid, False)

    c_variables = variables("a.out")

    line1 = open("/proc/%s/maps" % pid).readline()
    _start = int(line1.split("-")[0], 16)
    start = _start if _start != 0x400000 else 0

    import ptrace.syscall
    MMAP_PROT_BITMASK = {k:v for v,k in ptrace.syscall.posix_arg.MMAP_PROT_BITMASK}
    MMAP_PROT_BITMASK['PROT_ALL'] = MMAP_PROT_BITMASK['PROT_READ']\
                                  | MMAP_PROT_BITMASK['PROT_WRITE']\
				  | MMAP_PROT_BITMASK['PROT_EXEC']
    MAP_PRIVATE = 0x02
    MAP_ANONYMOUS = 0x20
    syscalls = {k: v for v, k in ptrace.syscall.linux_syscall64.SYSCALL_NAMES.items()}

    mmap = memory_maps()

    starts = {}
    c_globals = []

    states = []
    
    atexit.register(cleanup)
