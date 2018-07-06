from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from elftools.dwarf.descriptions import describe_form_class
from bisect import bisect

def variables(filename="a.out"):
    f = ELFFile(open(filename))
    symb_sections = [section for section in f.iter_sections()
                     if isinstance(section, SymbolTableSection)]
    variables = {symb.name:symb['st_value'] for section in symb_sections
                 for symb in section.iter_symbols()}
    return variables

def die_bounds(die):
    lowpc = die.attributes['DW_AT_low_pc'].value

    highpc_attr = die.attributes['DW_AT_high_pc']
    highpc_attr_class = describe_form_class(highpc_attr.form)
    highpc = highpc_attr.value if highpc_attr_class == 'address' else\
             highpc_attr.value + lowpc if highpc_attr_class == 'constant' else\
             Exception('Error: invalid DW_AT_high_pc class: %s' % highpc_attr_class)
    return lowpc, highpc

def address_info(address):
    for filename, dwarfinfo in all_dwarf_info.items():
        for cu in dwarfinfo["units"]:
            index = bisect(cu["addresses"], address) - 1
            if -1 < index < len(cu["addresses"]) - 1:
                state = cu["states"][index]
                # Could probably bisect
                func_name = None
                for entry in cu["entries"]:
                    if entry["bounds"][0] <= address < entry["bounds"][1]:
                        func_name = entry["name"]
                        break
                if func_name is None:
                    import pdb; pdb.set_trace()
                return {"function": func_name,
                        "file": cu["lineprog"]['file_entry'][state.file - 1].name,
                        "line": state.line}

all_dwarf_info = {}
# elfreader.all_dwarf_info.values()[0]['units'][0]["addresses"]


def load_dwarf_info(mmap):
    """ Load or reload all dwarf info from mmap. """
    for filename in mmap:
        if filename.startswith("["):
            continue
        elffile = ELFFile(open(filename, "rb"))
        if not elffile.has_dwarf_info():
            continue

        dwarfinfo = elffile.get_dwarf_info()
        # Information from Compilation Units (CUs)
        cus = []
        for cu in dwarfinfo.iter_CUs():
            lineprog = dwarfinfo.line_program_for_CU(cu)
            states = [entry.state for entry in lineprog.get_entries()
                      if entry.state and not entry.state.end_sequence]
            addresses = [state.address for state in states]
            dies = [{"entry": die,
                     "bounds": die_bounds(die),
                     "name": die.attributes['DW_AT_name'].value}
                    for die in cu.iter_DIEs()
                    if die.tag == 'DW_TAG_subprogram']
            cus.append({"lineprog": lineprog, "states": states,
                        "addresses": addresses, "entries": dies})
        all_dwarf_info[filename] = {"dwarfinfo": dwarfinfo, "units": cus}

def line_num_dict():
    line_nums = {}
    for filename, dwarfinfo in all_dwarf_info.items():
        line_nums[filename] = {}
        for cu in dwarfinfo["units"]:
            line_nums[filename].update({s.line: s.address for s in cu["states"]})
    return line_nums
