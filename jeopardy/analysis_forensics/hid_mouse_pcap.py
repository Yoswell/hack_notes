from PIL import Image

comments = """
    A small utility that parses raw HID (Human Interface Device) data (mouse events)
    from a text dump, reconstructs signed X/Y movement deltas and button states
    and then renders the traced pointer path to an image
"""

tags = """
    #usb #pcap #mouse #hid #python #image
"""

class Py_testing:
    def main():
        print('/*== Project to test ==*/')

        with open('hid_data.txt', 'r') as hid_file:
            data = hid_file.read().strip().split('\n')
            results = []

            for hid in data:
                btn = int(hid[0:2], 16)
                x = int(hid[4:6], 16)
                y = int(hid[8:10], 16)

                # Signed X/Y movement deltas
                x_signed = x - 256 if x & 0x80 else x
                y_signed = y - 256 if y & 0x80 else y

                results.append((btn, x_signed, y_signed))
                
            def paint(events, output='final.png', size=10000):
                img = Image.new('RGB', (size, size), 'white')
                canvas = img.load()

                x, y = size // 2, size // 2

                for btn, dx, dy in events:
                    x += dx
                    y += dy

                    # If btn == 1, the mouse clic to draw is presed
                    if btn != 1:
                        continue

                    for i in range(2):
                        for j in range(2):
                            # Verify the pixel is within the image bounds
                            if 0 <= x+i < img.width and 0 <= j+i < img.height:
                                canvas[x+i, y+j] = (0, 0, 0)

                img.save(output)
            paint(results)
                
if __name__ == "__main__":
    Py_testing.main()