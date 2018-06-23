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
