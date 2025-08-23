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


def merge(loader, shellcode):
    with open(f'loader/{loader}/{loader}.c', 'r') as f:
        loader_template: str = f.read()
    with open(f'shellcodes/{shellcode}/{shellcode}.bin', 'rb') as f:
        shellcode_raw: bytes = f.read()

    if not loader in loaders:
        print(f"Loader {loader} not found.")
        return None
    loader_converter = loaders[loader]

    template_shellcode = loader_converter.convert(shellcode_raw)
    loader_template = loader_template.replace('{{SHELLCODE}}', template_shellcode)

    filename = f'{loader}_{shellcode}.c'

    with open(os.path.join(OUTPUT_DIR, filename), 'w') as f:
        f.write(loader_template)

    return filename


def compile(filepath):
    module_c = os.path.join(OUTPUT_DIR, filepath)
    module_exe = os.path.join(OUTPUT_DIR, os.path.splitext(os.path.basename(filepath))[0] + '.exe')

    cmd = "cl.exe /nologo /MT /W0 /GS- /DNDEBUG /Tc{} /link /OUT:{} /SUBSYSTEM:CONSOLE /MACHINE:x64".format(
        module_c, module_exe
    )

    print("Compiling: {} into {}".format(module_c, module_exe))
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print("Error executing command: " + cmd)
        sys.exit(1)

    filename_compile = module_exe + ".bat"
    with open(filename_compile, 'w') as f:
        f.write(cmd)


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

    filename = merge(loader, shellcode)
    compile(filename)
    #execute(name)


if __name__ == "__main__":
    main()
