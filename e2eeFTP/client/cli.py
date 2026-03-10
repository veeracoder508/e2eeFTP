from .client import e2eeftpClient
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich import print as rprint
import subprocess
import platform
import os
import socket

def check_host_status(host, port=None):
    """
    Checks if a host is up. If a port is provided, it attempts a 
    TCP connection. Otherwise, it defaults to a standard ping.
    """
    if port:
        try:
            # Create a TCP socket and attempt to connect
            with socket.create_connection((host, int(port)), timeout=2):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
    else:
        # Fallback to the original ping logic if no port is provided
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', host]
        try:
            subprocess.run(command, capture_output=True, text=True, check=True, timeout=2)
            return True
        except Exception:
            return False

class e2eeftpClientCli:
    def __init__(self):
        # Initialize client - ensure host is accessible via self.client.host
        self.client = e2eeftpClient(logging=False)
        self.console = Console()
        self.status_map = {
            "200": "[bold green]200: Success[/bold green]",
            "226": "[bold cyan]226: Transfer Complete[/bold cyan]",
            "400": "[bold yellow]400: Bad Request[/bold yellow]",
            "404": "[bold red]404: File Not Found[/bold red]",
            "500": "[bold red]500: Internal Server Error[/bold red]"
        }
        self._create_help_table()

    def _create_help_table(self):
        """Creates the persistent help table."""
        self.help_table = Table(title="Available Commands", header_style="bold magenta")
        self.help_table.add_column("Command", style="cyan", width=15)
        self.help_table.add_column("Description")
        self.help_table.add_column("Syntax", style="italic")
        
        self.help_table.add_row("SEND", "Upload a file to server", "SEND <local_path>")
        self.help_table.add_row("GET", "Download from server", "GET <remote_path>")
        self.help_table.add_row("LIST", "List server files", "LIST")
        self.help_table.add_row("DELETE", "Delete server file", "DELETE <remote_path>")
        self.help_table.add_row("PING", "Check server status", "PING")
        self.help_table.add_row("HELP", "Show this message", "HELP")
        self.help_table.add_row("EXIT", "Close the client", "EXIT")

    def _get_status_style(self, code):
        return self.status_map.get(str(code), f"[white]{code}: Unknown Status[/white]")

    def run(self):
        self.console.clear()
        self.console.print(Panel.fit(
            "[bold cyan]E2EE FTP Client[/bold cyan]\n[dim]Type 'HELP' for commands[/dim]",
            border_style="magenta"
        ))
        
        try:
            while True:
                # Use Prompt.ask for a clean input experience
                command_input = Prompt.ask("[bold green]>>>[/bold green]").strip()
                
                if not command_input:
                    continue
                
                if command_input.upper() == "EXIT":
                    rprint("[yellow]Exiting...[/yellow]")
                    break
                    
                self._evaluate_command(command_input)
        except (KeyboardInterrupt, EOFError):
            rprint("\n[red]Session terminated.[/red]")

    def _evaluate_command(self, command: str):
        parts = command.split(maxsplit=1)
        method = parts[0].upper()
        args = parts[1] if len(parts) > 1 else None

        match method:
            case "SEND":
                if args:
                    if os.path.exists(args):
                        rprint(f"[blue]Action:[/blue] Uploading {args}...")
                        status = self.client.send(args) 
                        rprint(f"Status: {self._get_status_style(status)}")
                    else:
                        rprint(f"[bold red]Error:[/bold red] Local file '{args}' not found.")
                else:
                    rprint("[red]Error: Provide a file path.[/red]")
            
            case "GET":
                if args:
                    rprint(f"[blue]Action:[/blue] Downloading {args}...")
                    status = self.client.get(args)
                    rprint(f"Status: {self._get_status_style(status)}")
                else:
                    rprint("[red]Error: Provide a file path.[/red]")
            
            case "LIST":
                self.client.list()
                if os.path.exists("list.txt"):
                    with open("list.txt", 'r') as file:
                        lines = [line.strip() for line in file if line.strip()]
                    
                    if not lines:
                        rprint("[yellow]Server directory is empty.[/yellow]")
                        return

                    table = Table(title="Server Directory", header_style="bold magenta")
                    table.add_column("Filename", style="white")
                    table.add_column("Status", justify="center")

                    for line in lines:
                        table.add_row(line, self._get_status_style(200))
                    
                    self.console.print(table)
                else:
                    rprint("[bold red]Error:[/bold red] Could not retrieve directory list.")
            
            case "DELETE":
                if args:
                    status = self.client.delete(args)
                    rprint(f"Status: {self._get_status_style(status or 200)}")
                else:
                    rprint("[red]Error: Provide a file path.[/red]")

            case "HELP":
                self.console.print(self.help_table)

            case "PING":
                # Use the host and port from your client instance
                host = getattr(self.client, 'host', 'localhost')
                port = getattr(self.client, 'port', 21) # Default FTP port is 21
                
                rprint(f"[blue]Checking connection to {host}:{port}...[/blue]")
                
                if check_host_status(host, port):
                    rprint(f"Status: [bold green]UP (Port {port} is open)[/bold green]")
                else:
                    rprint(f"Status: [bold red]DOWN (Could not connect to port {port})[/bold red]")
            
            case _:
                rprint(f"Status: {self._get_status_style(400)} (Unknown Command '{method}')")
