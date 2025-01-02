import socket
import threading
from tqdm import tqdm
from tabulate import tabulate
import pandas as pd


print_lock = threading.Lock()


def scan_port(target_ip, port):
    """
    Scans a single port on a target IP address.

    Args:
        target_ip: The IP address of the target system.
        port: The port number to scan.

    Returns:
        A tuple containing the port number and its status ("Open", "Closed", or "Error").
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        if result == 0:
            return (port, "Open")
        else:
            return (port, "Closed")
    except KeyboardInterrupt:
        print("\nYou pressed Ctrl+C")
        return (port, "Error")
    except socket.gaierror:
        print("Hostname could not be resolved. Exiting")
        return (port, "Error")
    except socket.error:
        print("Couldn't connect to server")
        return (port, "Error")


def scan_port_range(target_ip, start_port, end_port, progress_bar):
    """
    Scans a range of ports and collects the results, updating the progress bar.
    """
    results = []
    for port in range(start_port, end_port + 1):
        results.append(scan_port(target_ip, port))
        progress_bar.update(1)  # Update the progress bar after each port scan
    return results


def scan_ports_threaded(target_ip, start_port, end_port, num_threads):
    threads = []
    # Add 1 to end_port to include the last port in the range
    ports_per_thread = (end_port - start_port + 1) // num_threads
    all_results = []

    # Create a tqdm progress bar
    with tqdm(total=end_port - start_port + 1, desc="Scanning ports") as progress_bar:
        for i in range(num_threads):
            start = start_port + i * ports_per_thread
            end = min(start + ports_per_thread, end_port + 1)  # Include end_port
            thread = threading.Thread(
                target=lambda: all_results.extend(
                    scan_port_range(target_ip, start, end, progress_bar)
                )
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    return all_results


def main():
    """
    Prompts the user for target IP and port range, then scans the ports using threads,
    prints the results in a table, and optionally saves the output to an Excel file.
    """
    target_ip = input("Enter the target IP address: ")
    start_port = int(input("Enter the starting port number: "))
    end_port = int(input("Enter the ending port number: "))

    print(f"Scanning {target_ip} from port {start_port} to {end_port}...")

    num_threads = 10  # You can adjust this
    # Add 1 to end_port to include the last port in the range
    results = scan_ports_threaded(target_ip, start_port, end_port + 1, num_threads)

    # Sort the results by port number
    results.sort(key=lambda x: x[0])

    # Create the table using tabulate
    table_data = [["Port Number", "Status"]] + results
    print(tabulate(table_data, headers="firstrow", tablefmt="fancy_grid"))

    # Ask the user if they want to save the output to Excel
    save_to_excel = input("Save output to Excel file? (y/n): ").lower() == "y"
    if save_to_excel:
        df = pd.DataFrame(results, columns=["Port Number", "Status"])
        excel_file = "port_scan_results.xlsx"
        df.to_excel(excel_file, index=False)
        print(f"Results saved to {excel_file}")


if __name__ == "__main__":
    main()
