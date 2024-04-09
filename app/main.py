#!/usr/bin/env python3

"""Checks if a password has been leaked or generates a password."""

from typing import Union
import getpass
import hashlib
import requests
import click
import string
import secrets

COLORS = {
    'red': '\033[31m',
    'green': '\033[32m',
    'yellow': '\033[33m',
    'blue': '\033[34m',
    'magenta': '\033[35m',
    'cyan': '\033[36m',
    'white': '\033[37m',
    'reset': '\033[0m',
}

def hash_password(pw_in) -> tuple:
    """Take password as input, hash it in SHA-1, and split it for use later on"""
    pw_hash = hashlib.sha1()
    pw_hash.update(str.encode(pw_in))
    digest = pw_hash.hexdigest()
    return (digest[:5], digest[5:])

def get_pwned_hashes(api_param) -> list:
    """Query the API for all hashes matching the input string"""
    returned_hashes = []
    res = requests.get(f"https://api.pwnedpasswords.com/range/{api_param}", stream=True)
    for line in res.iter_lines():
        if line:
            returned_hashes.append(line.decode().split(":"))
    return returned_hashes

def check(password: str) -> Union[tuple, bool]:
    """Run password check"""
    # Get the split hash of the password
    pw_hash_array = hash_password(password)
    # Send first 5 chars to API to retrieve matching hashes
    possible_hashes = get_pwned_hashes(pw_hash_array[0])
    # For each hash, test for a match
    for possible_hash in possible_hashes:
        if pw_hash_array[1].upper() == possible_hash[0]:
            identified_hash = pw_hash_array[0] + pw_hash_array[1]
            occurrences = possible_hash[1]
            return (True, identified_hash, occurrences)
    return False

@click.command()
def main() -> None:
    """Main function"""
    banner()
    while True:
        click.echo("1. Check if your password has been leaked")
        click.echo("2. Generate a strong password")
        option = input("Enter your option: ")
        if option == '1':
            password = getpass.getpass("Enter the password to check: ")
            result = check(password)
            if isinstance(result, tuple) and result[0]:
                click.echo(f"Password found as hash {result[1]}")
                click.echo(f"Occurrences: {result[2]}")
            else:
                click.echo("Password not found.")
            break
        elif option == '2':
            while True:
                try:
                    generate_and_print_password()
                    back_to_menu = input("Press Enter to return to the main menu: ")
                    if not back_to_menu:
                        break
                except KeyboardInterrupt:
                    print("\n" + COLORS['red'] + "Generator Stopped" + COLORS['reset'])
                    break
        else:
            click.echo("Invalid option. Please select again.")

def generate_and_print_password(length=25):
    """Generate and print a random password."""
    all_characters = string.ascii_letters + string.digits + string.punctuation
    password = [secrets.choice(all_characters) for _ in range(length)]
    secrets.SystemRandom().shuffle(password)
    password = ''.join(password)
    print(COLORS['green'] + password + COLORS['reset'])

def banner():
    font = f"""
 {COLORS['green']}                                                                                                                          
@@@@@@@   @@@  @@@  @@@  @@@  @@@  @@@@@@@@  @@@@@@@       @@@@@@@  @@@  @@@  @@@@@@@@   @@@@@@@  @@@  @@@  @@@@@@@@  @@@@@@@   
@@@@@@@@  @@@  @@@  @@@  @@@@ @@@  @@@@@@@@  @@@@@@@@     @@@@@@@@  @@@  @@@  @@@@@@@@  @@@@@@@@  @@@  @@@  @@@@@@@@  @@@@@@@@  
@@!  @@@  @@!  @@!  @@!  @@!@!@@@  @@!       @@!  @@@     !@@       @@!  @@@  @@!       !@@       @@!  !@@  @@!       @@!  @@@  
!@!  @!@  !@!  !@!  !@!  !@!!@!@!  !@!       !@!  @!@     !@!       !@!  @!@  !@!       !@!       !@!  @!!  !@!       !@!  @!@  
@!@@!@!   @!!  !!@  @!@  @!@ !!@!  @!!!:!    @!@  !@!     !@!       @!@!@!@!  @!!!:!    !@!       @!@@!@!   @!!!:!    @!@!!@!   
!!@!!!    !@!  !!!  !@!  !@!  !!!  !!!!!:    !@!  !!!     !!!       !!!@!!!!  !!!!!:    !!!       !!@!!!    !!!!!:    !!@!@!    
!!:       !!:  !!@  !!:  !!:  !!!  !!:       !!:  !!!     :!!       !!:  !!!  !!:       :!!       !!: :!!   !!:       !!: :!!   
:!:       :!:  :!:  :!:  :!:  !:!  :!:       :!:  !:!     :!:       :!:  !:!  :!:       :!:       :!:  !:!  :!:       :!:  !:!  
 ::        :::: :: :::    ::   ::   :: ::::   :::: ::      ::: :::  ::   :::   :: ::::   ::: :::   ::  :::   :: ::::  ::   :::  
 :          :: :  : :    ::    :   : :: ::   :: :  :       :: :: :   :   : :  : :: ::    :: :: :   :   :::  : :: ::    :   : :  
                                                                                                                                
 """
    click.echo(font)

if __name__ == "__main__":
    main()
