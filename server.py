import io
from PIL import Image
import PIL
import pyscreenshot as ImageGrab
import pyautogui
import time
import mss
from screeninfo import get_monitors

select_bbox = None

# for m in get_monitors():
#     print(f"Monitor {m.name}: {m.width}x{m.height} at ({m.x},{m.y})")

#     bbox = (m.x, m.y, m.x + m.width, m.y + m.height)
#     screenshot = ImageGrab.grab(bbox=bbox)
#     screenshot.save(f"{m.name}.png")


#     if m.name == 'DP-2':
#         select_bbox = bbox


FPS = 30
FRAME_DURATION = 1.0 / FPS

frames = 200
start_time = time.time()
img = None
with mss.mss() as sct:
    # Capture the whole primary monitor
    monitor = sct.monitors[1]
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

img.save("test_capture.png")



# Wait for a moment
# time.sleep(1)

# Move the mouse to position (x=100, y=100)
# pyautogui.moveTo(100, 100, duration=1)

# Click at that position
# pyautogui.click()

# Type some text
# pyautogui.write('Hello from Raspberry Pi!', interval=0.1)

# Optional: move mouse around
# pyautogui.move(50, 50, duration=1)

print("Mouse moved and text typed.")