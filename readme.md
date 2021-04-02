# ptracedbg - Instructions for making a custom debugger and live C/assembly program editor.

These are the source files for [this post](https://blog.asrpo.com/making_a_low_level_debugger) and [this post](https://blog.asrpo.com/making_a_low_level_debugger_part_2).

To run part 1

    pip install -r requirements.txt
    gcc -fPIC sample1.c
    python -i tutorial1.py

Then run individual commands from the python interpreter such as

    >>> safe_func_call(start + c_variables['test_function'])

To run part 2

    gcc -rdynamic -fPIC -gdwarf-2 sample2.c -ldl
    python -i tutorial2.py

Then try some commands

    >>> find_section(mmap, process.getreg('rip'))
    >>> run_c('printf("Hello world\n");')
    >>> line_numbers()
    >>> wait_for_count(2)
    >>> save_state()
    >>> wait_for_count(4)
    >>> load_state()
    >>> wait_for_count(4)

To run part 3

    cd sample3
    gcc -rdynamic -fPIC -gdwarf-2 sample3.c -ldl
    gcc -shared -x c -o library.so -fPIC library.c
    python -i tutorial3.py

Then try some commands

    >>> reload_library()
    >>> c_func_call("print_memory", starts["library.so"])
    >>> c_lib_globals.extend(["int* memory", "int* program_counter",
    ...                       "void* toggle", "void* primitives"])
    >>> run_c('((void (**)(void))primitives)[1]();')
    >>> iter_()
    >>> for _ in range(60):
    ...     run_loop()
