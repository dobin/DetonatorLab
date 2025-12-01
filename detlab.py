import subprocess
import os
import sys
import importlib

loaders = {}

OUTPUT_DIR = 'output'


def ImportLoaders():
    # import all loader modules dynamically
    # e.g.: loader/loader_1/loader_1.py
    loader_dir = 'loader'
    
    for root, dirs, files in os.walk(loader_dir):
        for file in files:
            if file.endswith('.py') and not file.startswith('__'):
                module_name = os.path.join(root, file).replace(os.sep, '.').rstrip('.py')
                #loaders.append(importlib.import_module(module_name))
                module_name_short = module_name.split('.')[-1]
                try:
                    module = importlib.import_module(module_name)
                    loaders[module_name_short] = module
                except ImportError as e:
                    print(f"Error importing {module_name}: {e}")
                #print(f"Loaded: {module_name_short}")


def prepare(loader, shellcode):
    with open(f'loader/{loader}/{loader}.c', 'r') as f:
        loader_template: str = f.read()
    with open(f'shellcodes/{shellcode}/{shellcode}.bin', 'rb') as f:
        shellcode_raw: bytes = f.read()

    if not loader in loaders:
        print(f"Loader {loader} not found.")
        return None
    loader_converter = loaders[loader]

    # C source file
    template_shellcode = loader_converter.convert(shellcode_raw)
    loader_template = loader_template.replace('{{SHELLCODE}}', template_shellcode)
    basename = f'{loader}_{shellcode}'
    filename = f'{basename}.c'
    with open(os.path.join(OUTPUT_DIR, filename), 'w') as f:
        f.write(loader_template)

    # Optional: resource file
    if hasattr(loader_converter, 'get_rc_file'):
        rc_content, encrypted_shellcode = loader_converter.get_rc_file(shellcode_raw)
        rc_filename = f'payload.rc'
        with open(os.path.join(OUTPUT_DIR, rc_filename), 'w') as f:
            f.write(rc_content)
        bin_filename = 'payload.bin'
        with open(os.path.join(OUTPUT_DIR, bin_filename), 'wb') as f:
            f.write(encrypted_shellcode)

    return basename


def compile(basename):
    module_c = os.path.join(OUTPUT_DIR, basename + '.c')
    module_out = os.path.join(OUTPUT_DIR, basename + '.exe')
    
    # Standard compile flags
    compile_flags = "/nologo /MT /W0 /GS- /DNDEBUG"

    # Standard link libraries
    link_libs = " user32.lib"  # for MessageBoxA

    # check if DLL
    if '_dll' in basename:
        compile_flags += " /LD"
        module_out = module_out.replace('.exe', '.dll')
        
    # Check if resource file exists and compile accordingly
    # payload.rc is created by merge() before
    module_rc = os.path.join(OUTPUT_DIR, 'payload.rc')
    if os.path.exists(module_rc):
        module_res = os.path.join(OUTPUT_DIR, 'payload.res')

        # compile the resource file
        print(f"Compiling resource file: {module_rc}")
        rc_cmd = f"rc.exe /nologo {module_rc}"
        result = subprocess.run(rc_cmd, shell=True)
        if result.returncode != 0:
            print("Error compiling resource file: " + rc_cmd)
            sys.exit(1)
        
        # Compile C file with resource file
        cmd = "cl.exe {} /Tc{} {} /link /OUT:{} /SUBSYSTEM:CONSOLE /MACHINE:x64{}".format(
            compile_flags, module_c, module_res, module_out, link_libs
        )
    else:
        # Compile C file without resource file (original behavior)
        cmd = "cl.exe {} /Tc{} /link /OUT:{} /SUBSYSTEM:CONSOLE /MACHINE:x64{}".format(
            compile_flags, module_c, module_out, link_libs
        )

    print("Compiling: {} into {}".format(module_c, module_out))
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print("Error executing command: " + cmd)
        sys.exit(1)


def cleanup(basename):
    files = [
        basename + ".exp",
        basename + ".lib",
        basename + ".obj",
        os.path.join(OUTPUT_DIR, 'payload.rc'),
        os.path.join(OUTPUT_DIR, 'payload.res'),
        os.path.join(OUTPUT_DIR, 'payload.bin'),
    ]
    for file in files:
        if os.path.exists(file):
            os.remove(file)


def main():
    ImportLoaders()

    if len(sys.argv) < 3:
        print("Usage: python merge.py <loader> <shellcode> ")
        sys.exit(1)
    loader = sys.argv[1]
    shellcode = sys.argv[2]

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    if not os.path.exists(f'shellcodes/{shellcode}/{shellcode}.bin'):
        print(f"Shellcode {shellcode} not found.")
        sys.exit(1)
    if not os.path.exists(f'loader/{loader}/{loader}.c'):
        print(f"Loader {loader} not found.")
        sys.exit(1)

    basename = prepare(loader, shellcode)
    if not basename:
        print("Merging failed.")
        sys.exit(1)
    cleanup(basename)

    compile(basename)

    cleanup(basename)
    #execute(name)


if __name__ == "__main__":
    main()
