# ptracedbg - Instructions for making a custom debugger and live C/assembly program editor.

These are the source files for [this post](https://blog.asrpo.com/making_a_low_level_debugger).

To run

    pip install -r requirements.txt
    gcc -fPIC sample1.c
    python -i tutorial.py

Then run individual commands from the python interpreter such as

    >>> safe_func_call(start + c_variables['test_function'])
