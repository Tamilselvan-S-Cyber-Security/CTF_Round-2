
import socket
import requests
import os
from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading

def http_client():
    response = requests.get("https://jsonplaceholder.typicode.com/posts/1")
    print("Status Code:", response.status_code)
    print("Response Body:", response.text)

def http_server():
    PORT = 8000
    server = HTTPServer(('localhost', PORT), SimpleHTTPRequestHandler)
    print(f"HTTP Server started at http://localhost:{PORT}")
    server.serve_forever()

def tcp_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 9999))
    client.send(b'Hello TCP Server!')
    data = client.recv(1024)
    print("Received:", data.decode())
    client.close()

def tcp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 9999))
    server.listen(1)
    print("TCP Server waiting for connection...")
    conn, addr = server.accept()
    print("Connected by", addr)
    data = conn.recv(1024)
    conn.sendall(b'Hello TCP Client!')
    conn.close()

def udp_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.sendto(b'Hello UDP Server!', ('localhost', 8888))
    data, addr = client.recvfrom(1024)
    print("Received from server:", data.decode())
    client.close()

def udp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('localhost', 8888))
    print("UDP Server running...")
    data, addr = server.recvfrom(1024)
    print("Received:", data.decode())
    server.sendto(b'Hello UDP Client!', addr)

def ping_site():
    hostname = "google.com"
    response = os.system(f"ping -c 1 {hostname}" if os.name != 'nt' else f"ping -n 1 {hostname}")
    print("Ping success" if response == 0 else "Ping failed")

def download_file():
    url = "https://www.w3.org/TR/PNG/iso_8859-1.txt"
    r = requests.get(url)
    with open("downloaded.txt", "wb") as f:
        f.write(r.content)
    print("File downloaded as downloaded.txt")

def get_host_info():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    print("Hostname:", hostname)
    print("IP Address:", ip_address)

def port_scanner():
    host = 'localhost'
    for port in range(75, 85):
        s = socket.socket()
        result = s.connect_ex((host, port))
        status = "open" if result == 0 else "closed"
        print(f"Port {port} is {status}")
        s.close()

def main():
    options = {
        "1": ("HTTP Client", http_client),
        "2": ("Start HTTP Server", lambda: threading.Thread(target=http_server).start()),
        "3": ("TCP Client", tcp_client),
        "4": ("Start TCP Server", lambda: threading.Thread(target=tcp_server).start()),
        "5": ("UDP Client", udp_client),
        "6": ("Start UDP Server", lambda: threading.Thread(target=udp_server).start()),
        "7": ("Ping Website", ping_site),
        "8": ("Download File via HTTP", download_file),
        "9": ("Get Hostname and IP", get_host_info),
        "10": ("Port Scanner", port_scanner)
    }

    while True:
        print("\n==== Networking Toolkit ====")
        for key, (desc, _) in options.items():
            print(f"{key}. {desc}")
        print("0. Exit")

        choice = input("Enter your choice: ")
        if choice == "0":
            break
        action = options.get(choice)
        if action:
            print(f"\nRunning: {action[0]}\n{'-'*40}")
            try:
                action[1]()
            except Exception as e:
                print("Error:", e)
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
