import io
from PIL import Image, ImageTk
# import pyscreenshot as ImageGrab
import pyautogui
import time
import mss
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import hashlib
import http
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import os
import socket
import subprocess
from typing import Dict, List
from urllib.parse import urlparse
import tkinter as tk
import dearpygui.dearpygui as dpg
from PyQt5.QtWidgets import QApplication, QLabel
from PyQt5.QtGui import QPixmap, QImage
from PyQt5.QtCore import Qt, QTimer
import sys
import concurrent



PASSWORD = ''

URL = None
PORT = 8000

FPS = 30
FRAME_DURATION = 1.0 / FPS
IMAGE_QUALITY = 92
MONITOR = 1

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
FRAME_BOUNDRY = b"--frame"

RED = '\x1b[38;2;255;0;0m'
ORANGE = '\x1b[38;2;230;76;0m'
YELLOW = '\x1b[38;2;230;226;0m'
GREEN = '\x1b[38;2;0;186;40m'
BLUE = '\x1b[38;2;0;72;255m'
INDIGO = '\x1b[38;2;84;0;230m'
VIOLET = '\x1b[38;2;176;0;230m'
ANSII_RESET = '\x1b[0m'
STRIKE = '\033[9m'
START_OF_LINE_AND_CLEAR = '\r\033[K'

SHRUG = '¯\_(ツ)_/¯'
NICE = '(☞ﾟヮﾟ)☞'
NICE_OTHER = '☜(ﾟヮﾟ☜)'
TABLE_FLIP = '(╯°□°）╯︵ ┻━┻'
PUT_TABLE_BACK = '┬─┬ ノ( ゜-゜ノ)'
WAVING = '(°▽°)/'


# UTIL FUNCTION
def parse_url(url: str):
    # parsed_url = urlparse(url)
    scheme = 'https' if url.startswith("https") else 'http'
    i = 0
    if url.startswith('http'):
        i = 4
        while url[i] != '/' and url[i-1] != '/':
            i += 1
    
    start = i
    while i < len(url) and url[i] != ':' and url[i] != '/':
        i += 1
    host = url[start:i]

    port = ''
    if i < len(url) and url[i] == ':':
        start = i + 1
        while i < len(url) and url[i] != '/':
            i += 1
        port = url[start:i]
    
    path = url[i:]

    conn_class = http.client.HTTPSConnection if scheme == 'https' else http.client.HTTPConnection
    if port is None:
        port = 443 if scheme == 'https' else 80

    return host, port, path, conn_class

def call(url: str, method: str, body: any, headers={'Content-type': 'application/json'}, timeout=10) -> list[int, any]:

    if headers is None:
        headers = {}
    headers['Content-Type'] = 'application/json'
    

    redirect_count = 0
    current_url = url

    while redirect_count < 10:
        
        # parse host and make request
        host, port, path, conn_class = parse_url(current_url)
        conn = conn_class(host, port, timeout=timeout)

        if body != None:
            payload = json.dumps(body)
            conn.request(method, path, body=payload, headers=headers)
        else:
            conn.request(method, path, headers=headers)

        response = conn.getresponse()

        # handle redirects
        if response.status in (301, 302, 303, 307, 308):
            location = response.getheader('Location')
            if not location:
                break
            current_url = location
            conn.close()
            redirect_count += 1
            continue
        else:
            # process response
            res_body = response.read().decode()
            conn.close()
            return response.status, json.loads(res_body) if res_body else {}
    # Too many redirects
    raise Exception("Too many redirects")

def get(url: str, headers={}, timeout=10) -> list[int, any]:
    return call(url, 'GET', None, headers, timeout=timeout)

def post(url: str, body: any, headers={'Content-type': 'application/json'}, timeout=10) -> list[int, any]:
    return call(url, 'POST', body, headers, timeout=timeout)

def delete(url: str, body: any, headers={'Content-type': 'application/json'}, timeout=10) -> list[int, any]:
    return call(url, 'DELETE', body, headers, timeout=timeout)

def chunked_file_upload(url: str, file_path: str, method: str, headers={'Content-type': 'application/octet-stream', 'Transfer-Encoding': 'chunked'}, timeout=10):
    
    host, port, path, conn_class = parse_url(url)
    conn = conn_class(host, port, timeout=timeout)
    conn.putrequest(method, path)
    headers['Content-type'] = 'application/octet-stream'
    headers['Transfer-Encoding'] = 'chunked'
    for key, value in headers.items():
        conn.putheader(key, value)
    conn.endheaders()

    file_size = os.path.getsize(file_path)
    i_sent = 0
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(1024*1024)  # 1MB chunks
            if not chunk:
                break
            # Send chunk size in hex
            conn.send(f"{len(chunk):X}\r\n".encode('utf-8'))
            # Send chunk data
            conn.send(chunk)
            conn.send(b"\r\n")

            i_sent += 1024*1024
            print(START_OF_LINE_AND_CLEAR + file_path + ' --> ' + str(int(100 * i_sent / file_size)) + '%', end='')
    print(START_OF_LINE_AND_CLEAR, end='')

    # Send zero-length chunk to indicate end
    conn.send(b"0\r\n\r\n")

    response = conn.getresponse()

    res_body = response.read().decode()
    conn.close()
    return response.status, json.loads(res_body) if res_body else {}

def chunked_file_download(url: str, headers={}, dest_file: str = None, timeout=10):

    redirect_count = 0
    current_url = url

    while redirect_count < 10:
        
        # parse host and make request
        host, port, path, conn_class = parse_url(current_url)
        conn = conn_class(host, port, timeout=timeout)

        conn.request('GET', path, headers=headers)

        response = conn.getresponse()

        # handle redirects
        if response.status in (301, 302, 303, 307, 308):
            location = response.getheader('Location')
            if not location:
                break
            current_url = location
            conn.close()
            redirect_count += 1
            continue
        else:
            # process response
            file_path = response.getheader('file_path', '')
            if dest_file == None: dest_file = file_path
            file_size = int(response.getheader('file_size', ''))
            i_recieved = 0
            os.makedirs(os.path.dirname(CLIENT_DIR + '/' + dest_file), exist_ok=True)
            with open(CLIENT_DIR + '/' + dest_file, 'wb') as f:
                while True:
                    # Read the chunk size line
                    chunk_size_line = response.fp.readline().strip()
                    if not chunk_size_line:
                        break
                    try:
                        size = int(chunk_size_line, 16)
                    except ValueError:
                        # Invalid chunk size
                        break
                    if size == 0:
                        # Last chunk
                        break
                    # Read the chunk data
                    chunk_data = response.fp.read(size)
                    # Read the trailing CRLF
                    response.fp.read(2)
                    # Write chunk to file
                    f.write(chunk_data)

                    i_recieved += size
                    print(START_OF_LINE_AND_CLEAR + file_path + ' --> ' + str(int(100 * i_recieved / file_size)) + '%', end='')
            print(START_OF_LINE_AND_CLEAR, end='')

            return response.status, file_path
        
    # Too many redirects
    raise Exception("Too many redirects")

def stream(url: str, headers={}, dest_file: str = None, timeout=10):
    redirect_count = 0
    current_url = url

    while redirect_count < 10:
        
        # parse host and make request
        host, port, path, conn_class = parse_url(current_url)
        conn = conn_class(host, port, timeout=timeout)

        conn.request('GET', path, headers=headers)

        response = conn.getresponse()

        # handle redirects
        if response.status in (301, 302, 303, 307, 308):
            location = response.getheader('Location')
            if not location:
                break
            current_url = location
            conn.close()
            redirect_count += 1
            continue
        else:
            return response
        
    # Too many redirects
    raise Exception("Too many redirects")

def get_next_stream_frame(stream_obj):
    # # process response
    # buffer = b""

    # while True:
    #     chunk = stream_obj.read(1024)  # read in small chunks
    #     if not chunk:
    #         break
    #     buffer += chunk

    #     # Look for frame boundary
    #     while True:
    #         start = buffer.find(FRAME_BOUNDRY)
    #         if start == -1:
    #             break
    #         end = buffer.find(FRAME_BOUNDRY, start + len(FRAME_BOUNDRY))
    #         if end == -1:
    #             break

    #         # Extract the full frame section
    #         frame_section = buffer[start + len(FRAME_BOUNDRY):end]
    #         buffer = buffer[end:]  # keep remaining

    #         # Split headers from JPEG binary
    #         header_end = frame_section.find(b"\r\n\r\n")
    #         if header_end == -1:
    #             continue
    #         headers = frame_section[:header_end]
    #         jpeg_data = frame_section[header_end + 4:]

    #         return jpeg_data

    buffer = b""

    while True:
        chunk = stream_obj.read(1024)
        if not chunk:
            break
        buffer += chunk

        # Look for frame boundary
        while True:
            start = buffer.find(FRAME_BOUNDRY)
            if start == -1:
                break

            # Find the next boundary to determine frame end
            end = buffer.find(FRAME_BOUNDRY, start + len(FRAME_BOUNDRY))
            if end == -1:
                break  # Wait for more data

            # Extract the frame segment
            frame_segment = buffer[start + len(FRAME_BOUNDRY):end]
            buffer = buffer[end:]  # Keep the remaining buffer

            # Find end of headers (look for double CRLF)
            header_end = frame_segment.find(b"\r\n\r\n")
            if header_end == -1:
                continue  # Wait for full headers

            # Separate headers and raw data
            headers_bytes = frame_segment[:header_end]
            raw_data = frame_segment[header_end + 4:]

            # Optionally, parse headers (e.g., width, height, format)
            headers_lines = headers_bytes.split(b"\r\n")
            headers = {}
            for line in headers_lines:
                if b":" in line:
                    key, value = line.split(b":", 1)
                    headers[key.strip().lower()] = value.strip()

            # Example: headers might include width, height, format
            width = int(headers.get(b"x-width", 0))
            height = int(headers.get(b"x-height", 0))
            pixel_format = headers.get(b"x-format", b"BGRA").decode()

            # Now, raw_data contains the pixel bytes
            # You can process it accordingly, e.g.,
            # convert to an image, process pixels, etc.

            # For example, returning or processing the raw image data:
            return {
                "width": width,
                "height": height,
                "format": pixel_format,
                "data": raw_data
            }



def print_rainbow(str: str, end='\n'):
    colors = [RED, ORANGE, YELLOW, GREEN, BLUE, INDIGO, VIOLET]
    for i, c in enumerate(str):
        color = colors[i % len(colors)]
        print(color, c, sep='', end='')
    print(ANSII_RESET, end=end)

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # This doesn't need to be reachable
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

def get_network_ip():
    local_ip = get_local_ip()
    i = len(local_ip) - 1
    while i >= 0 and local_ip[i] != '.':
        i -= 1
    
    return local_ip[:i] + ".0/24"

def record_video():

    frames = 100
    start_time = time.time()
    img = None
    with mss.mss() as sct:
        # Capture the whole primary monitor
        monitor = sct.monitors[3]
        for i in range(frames):
            capture_start = time.time()

            sct_img = sct.grab(monitor)
            img = Image.frombytes('RGB', sct_img.size, sct_img.bgra, 'raw', 'BGRX')
            buf = io.BytesIO()
            img.save(buf, format='JPEG', quality=30)  # adjust quality for speed/bandwidth
            jpeg_data = buf.getvalue()

            duration = time.time() - capture_start
            if (FRAME_DURATION > duration):
                time.sleep(FRAME_DURATION - duration)


        total_time = time.time() - start_time
        print(frames / total_time, " fps")

        img.save("test_pics/test_capture.png")

def get_monitors():
    with mss.mss() as sct:

        for i, monitor in enumerate(sct.monitors):

            sct_img = sct.grab(monitor)
            img = Image.frombytes('RGB', sct_img.size, sct_img.bgra, 'raw', 'BGRX')
            img.save(f"test_pics/monitor_{i}.jpg", format='JPEG', quality=30)  # adjust quality for speed/bandwidth

            print(f"Monitor {i}: {monitor}")

def move_mouse():

    # Wait for a moment
    time.sleep(1)

    # Move the mouse to position (x=100, y=100)
    pyautogui.moveTo(100, 100, duration=1)

    # Click at that position
    pyautogui.click()

    # Type some text
    pyautogui.write('Hello from Raspberry Pi!', interval=0.1)

    # Optional: move mouse around
    pyautogui.move(50, 50, duration=1)







# CLIENT METHODS
def CLIENT_PING(host):

    try:
        status, response = get(host + '/ping', timeout=1, headers={'password' : PASSWORD})
        return status == 200 and response == 'up'
    except Exception as e:
        return False

def CLIENT_STREAM(host):
    try:


        stream_obj = stream(host + '/stream', timeout=1000, headers={'password' : PASSWORD})
        frame_count = 0

        app = QApplication(sys.argv)
        label = QLabel()
        label.setWindowFlags(Qt.Window)   # Make it a standalone window
        # label.showFullScreen() 
        label.resize(800, 600)  # width x height
        label.setMinimumWidth(500)  # prevent the window from being smaller than this
        label.show()

        def update_frame():
            frame = get_next_stream_frame(stream_obj)  # bytes
            if frame is None: 
                # XXX: put a filler image
                return

            # # Save the JPEG (for debugging)
            # frame_count += 1
            # with open(f"frame.jpg", "wb") as f:
            #     f.write(frame)

            # pixmap = QPixmap()
            # pixmap.loadFromData(frame, "JPEG")

            # # Scale pixmap to the window height while keeping aspect ratio
            # window_height = label.height()
            # scaled_pixmap = pixmap.scaledToHeight(window_height, Qt.SmoothTransformation)

            # label.setPixmap(scaled_pixmap)

            img = QImage(
                frame["data"],                # raw bytes
                frame["width"],
                frame["height"],
                frame["width"] * 3,          # bytes per line (for RGB it's width * 3)
                QImage.Format_RGB888
            )

            # QImage expects RGB, but MSS gives BGRA → strip alpha and convert
            img = img.rgbSwapped()

            # Convert QImage → QPixmap
            pixmap = QPixmap.fromImage(img)



            # Convert QImage to QPixmap
            pixmap = QPixmap.fromImage(img)

            # Scale pixmap to fit window
            window_height = label.height()
            scaled_pixmap = pixmap.scaledToHeight(window_height, Qt.SmoothTransformation)

            # Set pixmap to label
            label.setPixmap(scaled_pixmap)


        timer = QTimer()
        timer.timeout.connect(update_frame)
        timer.start(FPS) 

        sys.exit(app.exec_())




    


    except Exception as e:
        print("Error in CLIENT_STREAM:", e)
        return False
    

def CLIENT_MONITORS(host):

    try:
        status, response = get(host + '/monitors', timeout=1, headers={'password' : PASSWORD})
        print("Monitors:")
        print(response)
    except Exception as e:
        return False
 
def Client():
    CLIENT_MONITORS(URL)
    CLIENT_STREAM(URL)




# ENDPOINTS
def PING():
    return 200, 'up'

def STREAM(handler):

    handler.send_response(200)
    handler.send_header("Content-type", "multipart/x-mixed-replace; boundary=frame")
    handler.end_headers()

    with mss.mss() as sct:
        monitor = sct.monitors[MONITOR]  # choose your monitor index
        while True:
            capture_start = time.time()

            # Capture screen
            sct_img = sct.grab(monitor)
            # img = Image.frombytes('RGB', sct_img.size, sct_img.bgra, 'raw', 'BGRX')

            # # Encode to JPEG in memory
            # buf = io.BytesIO()
            # img.save(buf, format='JPEG', quality=IMAGE_QUALITY)
            # frame = buf.getvalue()

            # Write multipart frame
            try:
                # handler.wfile.write(FRAME_BOUNDRY + b"\r\n")
                # handler.wfile.write(b"Content-Type: image/jpeg\r\n")
                # handler.wfile.write(b"Content-Length: " + str(len(frame)).encode() + b"\r\n")
                # handler.wfile.write(b"\r\n")
                # handler.wfile.write(frame)
                # handler.wfile.write(b"\r\n")

                header = (
                    f"Content-Type: application/octet-stream\r\n"
                    f"X-Width: {sct_img.width}\r\n"
                    f"X-Height: {sct_img.height}\r\n"
                    f"X-Format: BGRA\r\n"
                    f"Content-Length: {len(sct_img.bgra)}\r\n"
                ).encode()
                handler.wfile.write(FRAME_BOUNDRY + b"\r\n")
                handler.wfile.write(header + b"\r\n")
                handler.wfile.write(b"\r\n")
                handler.wfile.write(sct_img.bgra)
                handler.wfile.write(b"\r\n")
            except (BrokenPipeError, ConnectionResetError):
                # Client disconnected
                break

            # FPS control
            duration = time.time() - capture_start
            if duration < FRAME_DURATION:
                time.sleep(FRAME_DURATION - duration)

def MONITORS():
    monitors = []
    with mss.mss() as sct:
        for i, monitor in enumerate(sct.monitors):
            monitors.append(i)

    return 200, json.dumps(monitors)



class Server(BaseHTTPRequestHandler):

    def password_check(self):
        headers = self.headers
        password = headers['password']

        if password != PASSWORD:
            raise Exception('bad password')


    def do_GET(self):
        json_str = None
        status = 200
        try:
            self.password_check()

            response_body = None

            if self.path == '/ping':
                status, response_body = PING()
            elif self.path == '/stream':
                STREAM(self)
                return
            elif self.path == '/monitors':
                status, response_body = MONITORS();

                
            json_str = json.dumps(response_body)

        except Exception as e:
            response_obj = {
                "error": str(e)
            }
            json_str = json.dumps(response_obj)

        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json_str.encode('utf-8'))

    def do_POST(self):
        json_str = None
        status = 200
        try:
            self.password_check()


            transfer_encoding = self.headers.get('Transfer-Encoding', '').lower()
            body = None
            if 'chunked' in transfer_encoding:
                if self.path == '/upload':
                    self.handle_chunked()
                return
            else:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                req_json = post_data.decode('utf-8')
                body = json.loads(req_json)

            response_body = None

            if self.path == '/sync':
                # status, response_body = SYNC(body)
                pass

            json_str = json.dumps(response_body)

        except Exception as e:
            response_obj = {
                "error": str(e)
            }
            json_str = json.dumps(response_obj)

        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json_str.encode('utf-8'))
        
    def do_DELETE(self):
        json_str = None
        status = 204
        try:
            self.password_check()

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            req_json = post_data.decode('utf-8')
            body = json.loads(req_json)

            response_body = None

            if self.path == '/delete':
                # status, response_body = DELETE(body)
                pass

            json_str = json.dumps(response_body)

        except Exception as e:
            response_obj = {
                "error": str(e)
            }
            json_str = json.dumps(response_obj)

        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json_str.encode('utf-8'))

    
    def handle_chunked(self):
        file_path = DIRECTORY + '/' + self.headers.get('file_path')
        # Open a file to write the incoming data
        with open(file_path, 'wb') as f:
            while True:
                # Read the chunk size line
                chunk_size_line = self.rfile.readline().strip()
                if not chunk_size_line:
                    break
                # Convert hex size to int
                try:
                    chunk_size = int(chunk_size_line, 16)
                except ValueError:
                    # Send appropriate response, or return error
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Invalid chunk size")
                    return
                if chunk_size == 0:
                    # End of chunks
                    break
                # Read the chunk data
                chunk_data = self.rfile.read(chunk_size)
                # Read the trailing CRLF after chunk data
                self.rfile.read(2)
                # Write chunk directly to file
                f.write(chunk_data)

        # After completing, send response
        self.send_response(200)
        self.end_headers()
        message = "File uploaded successfully."
        self.wfile.write(json.dumps(message).encode('utf-8'))



if __name__ == "__main__":


    parser = argparse.ArgumentParser(description="A file server for syncing folders across devices")
    
    parser.add_argument('--server', action='store_true', help='Start the server on this machine. If ommited you\'re running as a client.')
    parser.add_argument('--url', type=str, help='Server url if running as client. Otherwise the local network is scanned for a server')
    parser.add_argument('--password', type=str, help='Password used either as server or client. Otherwise no password is used.')
    args = parser.parse_args()


    if args.password:
        PASSWORD = args.password

    if args.server:
        # ifconfig


        server_address = ('', PORT)
        httpd = HTTPServer(server_address, Server)

        print("Serving on port " + str(PORT) + " ...")
        print_rainbow(get_local_ip())
        httpd.serve_forever()
    else:


        # scan for the server on local network if no url
        URL = args.url
        if not URL:
            
            def check_ip(ip):
                url = f"{ip}:{PORT}"
                if CLIENT_PING(url):
                    return url
                else:
                    return None
                
            # subnet = ipaddress.IPv4Network('192.168.1.0/24')
            network = get_network_ip()
            print(RED + "Searching for server on local network " + network + " ..." + ANSII_RESET)
            print()
            subnet = ipaddress.IPv4Network(network, strict=False)
            with ThreadPoolExecutor(max_workers=255) as executor:
                # Submit all IPs to the executor
                futures = [executor.submit(check_ip, str(ip)) for ip in subnet.hosts()]

                for future in concurrent.futures.as_completed(futures):
                    try:
                        if future.result():
                            URL = future.result()
                            
                            # Cancel all other pending futures
                            for f in futures:
                                if not f.done():
                                    f.cancel()

                            print(BLUE + NICE + ANSII_RESET + ' ', end='')
                            print_rainbow(URL, end='')
                            print(BLUE + ' ' + NICE_OTHER + ANSII_RESET)


                    except Exception as e:
                        pass
                
                done, not_done = concurrent.futures.wait(futures)
                if not URL:
                    print_rainbow(SHRUG)
                    print("no server found")
                    print()

        Client()








