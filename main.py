import sys
import time
from PET import PET
from termcolor import colored
"""

CREATED BY ZAKARIA HARIRA @2022

"""

if __name__ == "__main__":
    print(colored(f"[+] listening on {sys.argv[1]}", "white"))
    time.sleep(1)
    purp = PET(sys.argv[1], 0)
    try:
        purp.start()
    except KeyboardInterrupt:
        print("[!] EXIT...")