### HID Mouse Events Analysis & Forensics Guide

HID (Human Interface Device) refers to USB devices like mice and keyboards that communicate with the host via interrupt transfers. Mouse events are generated when the mouse is moved, buttons are pressed/released, or the scroll wheel is used. In CTF forensics, analyzing HID data from PCAP files can reveal user interactions, such as mouse movements simulating keystrokes, hidden commands, or even drawing patterns that encode data.

-----

### HID Protocol Deep Dive

#### Report Descriptor and Data Structure

The HID protocol uses a **Report Descriptor** to define the data format sent by the device. This descriptor specifies what each byte/bit represents in the data packets. Mice typically send **Input Reports** periodically (e.g., every 10ms) via interrupt IN transfers.

##### 4-Byte Report (Most Common)

```plaintext
Byte 0: Button states (bitfield)
  Bit 0: Left button (1 = pressed)
  Bit 1: Right button
  Bit 2: Middle button
  Bit 3: Back button (if available)
  Bit 4: Forward button (if available)
  Bits 5-7: Reserved (usually 0)

Byte 1: X-axis movement delta (signed 8-bit integer)
  Range: -127 to +127
  Positive = move right, Negative = move left

Byte 2: Y-axis movement delta (signed 8-bit integer)
  Range: -127 to +127
  Positive = move down, Negative = move up

Byte 3: Scroll wheel delta (signed 8-bit integer)
  Range: -127 to +127
  Positive = scroll down/right, Negative = scroll up/left
```

##### 8-Byte Report (Extended/Gaming Mice)

Some gaming mice or multi-button mice use extended reports:

```plaintext
Bytes 0-1: Button states (16 bits for up to 16 buttons)
Byte 2: X-axis movement (signed 8-bit)
Byte 3: Y-axis movement (signed 8-bit)
Byte 4: Vertical scroll (signed 8-bit)
Byte 5: Horizontal scroll (signed 8-bit)
Byte 6-7: Manufacturer-specific or reserved
```

#### USB Packet Structure

USB mouse communication occurs through:

* **Endpoint 0x81:** Interrupt IN endpoint for data transfer to host
* **Transfer Type 0x01:** URB_INTERRUPT (Interrupt transfer)
* **Polling Interval:** Typically 1ms to 10ms

-----

### Raw HID Data Examples

#### Basic Mouse Interactions

```plaintext
# Left click sequence
0000010000000000  # Button byte: 0x01 (left pressed), no movement
0000000000000000  # Button released

# Right click
0000020000000000  # Button byte: 0x02 (right pressed)
0000000000000000  # Released

# Mouse movement (right 10 units, down 5 units)
000000000a050000  # X=10, Y=5 decimal (0x0a, 0x05 hex)

# Scroll down
0000000000000100  # Wheel byte: 0x01 (scroll down 1 unit)

# Combined: left click + movement
000001000a050000  # Left pressed, move right 10, down 5
```

#### Real-World CTF Example Sequences

```plaintext
# Example 1: Simple drag operation
0000010000000000  # Left button down at start position
000001000a000000  # Move right 10 units while holding
0000010014050000  # Move right 20, down 5 (0x14 = 20, 0x05 = 5)
0000000000000000  # Button released

# Example 2: Drawing a square
0000010000000000  # Start with button down
0000010064000000  # Move right 100 units (0x64 = 100)
0000010000640000  # Move down 100 units
000001009c000000  # Move left 100 units (0x9c = -100 in signed)
00000100009c0000  # Move up 100 units
0000000000000000  # Button up
```

#### Wireshark Display Examples

```plaintext
USB URB
    Endpoint: 0x81, Direction: IN
    URB transfer type: URB_INTERRUPT (0x01)
    HID Data: 0000010000000000  # Left click
    
USB URB
    Endpoint: 0x81, Direction: IN  
    URB transfer type: URB_INTERRUPT (0x01)
    HID Data: 000000001e000000  # Move right 30 units (0x1e = 30)
```

-----

### Extraction and Analysis Commands

#### Using TShark (Command Line)

```bash
# Extract all HID data
tshark -r capture.pcapng -T fields -e usbhid.data

# Filter for mouse interrupt IN transfers only
tshark -r mouse_capture.pcapng -Y 'usb.endpoint_address.direction == IN and usb.transfer_type == 1 and usb.endpoint_address.number == 0x81' -T fields -e usbhid.data

# Extract with timestamps for time-based analysis
tshark -r capture.pcapng -Y 'usbhid.data' -T fields -e frame.time_relative -e usbhid.data

# Save extracted data to file
tshark -r capture.pcapng -Y 'usbhid.data' -T fields -e usbhid.data > hid_data.txt
```

#### Using Wireshark (GUI)

1. Open PCAP file in Wireshark
2. Apply filter: `usb.transfer_type == 0x01 && usb.endpoint_address == 0x81`
3. Right-click on USBHID packet → Follow → USBHID
4. Export packet bytes or use built-in dissector

#### Linux USB Analysis Tools

```bash
# Monitor USB traffic in real-time
usbmon

# Dump HID device data
sudo usbhid-dump

# Specific device dump (find device with lsusb)
sudo usbhid-dump -i 001/002

# Parse HID report descriptors
hidrd-convert -o spec < report_descriptor.bin
```

-----

### CTF Analysis Techniques

#### 1. Mouse Movement as Data Carrier

* **X/Y movements as ASCII values:** Each X or Y delta value corresponds to an ASCII character
* **Movement patterns as binary:** Up movement = 1, down movement = 0, or similar encoding
* **Click sequences as Morse code:** Left clicks as dots, right clicks as dashes
* **Coordinate-based encoding:** Specific screen coordinates map to characters on a virtual keyboard

#### 2. Pattern Recognition

* **Geometric shapes:** Circles, squares, or lines may indicate drawing patterns
* **Repeated sequences:** Identical movement patterns could represent repeated characters or commands
* **Grid alignment:** Movements that align to a grid suggest on-screen keyboard usage
* **Timing patterns:** Regular intervals between clicks or movements

#### 3. Click Analysis

* **Single vs double clicks:** Check time between click events
* **Drag operations:** Button held while moving indicates drawing or selection
* **Click clusters:** Multiple clicks in same area suggest UI button pressing
* **Right-click context:** Right clicks often open menus or perform special actions

#### 4. Time-Based Analysis

* **Event timing:** Calculate time between HID reports to detect pauses
* **Speed analysis:** Fast movements vs slow deliberate movements
* **Burst patterns:** Groups of rapid events vs spaced-out events

#### 5. Coordinate Reconstruction

* **Absolute positioning:** Some systems use absolute coordinates instead of deltas
* **Screen mapping:** Convert mouse coordinates to screen positions
* **Path tracing:** Reconstruct complete cursor path from deltas

-----

### Common CTF Challenge Types

#### 1. Mouse Movements as Text Input

* **Scenario:** User typed a password using an on-screen keyboard controlled by mouse
* **Analysis Approach:**
    1. Extract all mouse movements and clicks
    2. Map movements to virtual keyboard layout
    3. Reconstruct typed characters from click positions
    4. Look for Enter/Submit clicks at the end

* **Example Solution:**

```plaintext
Movements detected: Click at (100,50), (150,50), (200,50)
Keyboard layout: A=(100,50), B=(150,50), C=(200,50)
Result: "ABC" was typed
```

#### 2. Mouse Drawing as Data Encoding

* **Scenario:** User drew a shape that encodes a flag
* **Analysis Approach:**
    1. Plot all mouse movements with button held
    2. Identify drawn shape (circle, square, etc.)
    3. Extract encoded data from shape properties
    4. Convert to text using challenge-specific encoding

* **Example Solution:**

```plaintext
Circle detected with radius 70 pixels
Radius 70 = ASCII 70 = 'F'
Continue analysis for full flag
```

#### 3. Mouse Clicks as Binary Code

* **Scenario:** Left and right clicks represent binary data
* **Analysis Approach:**
    1. Separate left clicks (0) and right clicks (1)
    2. Convert click sequence to binary
    3. Group into 8-bit bytes
    4. Convert bytes to ASCII

* **Example Solution:**

```plaintext
Clicks: L, L, R, L, R, R, L, L
Binary: 0 0 1 0 1 1 0 0 = 0x2C = ','
```

#### 4. Movement Deltas as Direct Encoding

* **Scenario:** X movement values directly represent character codes
* **Analysis Approach:**
    1. Extract all X delta values
    2. Filter only positive movements (or based on challenge rules)
    3. Convert values to ASCII
    4. Look for meaningful strings

* **Example Solution:**

```plaintext
X movements: 72, 69, 76, 76, 79
ASCII: 72=H, 69=E, 76=L, 76=L, 79=O
Result: "HELLO"
```

-----

### Step-by-Step Analysis Methodology

#### 1. Data Extraction

1. **Identify HID traffic** in PCAP using Wireshark filters
2. **Extract raw HID data** to a text file
3. **Parse report format** (4-byte vs 8-byte)
4. **Separate by endpoint** if multiple devices present

#### 2. Basic Parsing

1. **Convert hex to structured data**
2. **Separate buttons, X, Y, wheel data**
3. **Handle signed bytes** properly (values >127 are negative)
4. **Calculate absolute positions** from deltas

#### 3. Pattern Detection

1. **Visualize movement path** using simple plotting
2. **Identify click events** and their positions
3. **Look for repeating sequences**
4. **Check for geometric patterns**

#### 4. Interpretation

1. **Apply challenge-specific encoding**
2. **Test different decoding methods**
3. **Look for flag format** (CTF{...}, flag{...}, etc.)
4. **Verify results** with known patterns

#### 5. Verification

1. **Check for multiple encoding layers**
2. **Verify timing makes sense**
3. **Ensure complete data extraction**
4. **Document analysis process**

-----

### Essential Python Code Snippets

#### Basic HID Parser

```python
def parse_hid_mouse(hex_data):
    """Parse 8-byte HID mouse report"""
    data = bytes.fromhex(hex_data)
    buttons = data[0]
    
    # Handle signed bytes for movement
    x_delta = data[1] if data[1] <= 127 else data[1] - 256
    y_delta = data[2] if data[2] <= 127 else data[2] - 256
    
    return {
        'left_click': bool(buttons & 0x01),
        'right_click': bool(buttons & 0x02),
        'x': x_delta,
        'y': y_delta
    }
```

#### Mouse Path Reconstruction

```python
def reconstruct_path(hid_data_list):
    """Reconstruct cursor path from HID deltas"""
    x, y = 0, 0
    path = [(x, y)]
    
    for hex_data in hid_data_list:
        parsed = parse_hid_mouse(hex_data)
        x += parsed['x']
        y += parsed['y']
        path.append((x, y))
    
    return path
```

#### Click Sequence to Binary

```python
def clicks_to_binary(hid_data_list):
    """Convert left/right clicks to binary string"""
    binary = ""
    for hex_data in hid_data_list:
        parsed = parse_hid_mouse(hex_data)
        if parsed['left_click']:
            binary += "0"
        elif parsed['right_click']:
            binary += "1"
    return binary
```

#### Movement to ASCII Decoder

```python
def movements_to_ascii(hid_data_list, use_x=True):
    """Convert movement deltas to ASCII"""
    result = ""
    for hex_data in hid_data_list:
        parsed = parse_hid_mouse(hex_data)
        value = parsed['x'] if use_x else parsed['y']
        if 32 <= abs(value) <= 126:  # Printable ASCII range
            result += chr(abs(value))
    return result
```

-----

### Quick Reference Cheat Sheet

#### Common Filters

```plaintext
# Wireshark/TShark filters
usb.transfer_type == 0x01                     # Interrupt transfers
usb.endpoint_address == 0x81                  # Mouse IN endpoint
usb.endpoint_address.direction == IN          # All IN endpoints
usbhid.data                                   # HID data field exists
```

#### Key Byte Positions

```plaintext
4-byte report: [Buttons][X][Y][Wheel]
8-byte report: [Buttons_L][Buttons_H][X][Y][V_Wheel][H_Wheel][Reserved][Reserved]
```

#### Button Bitmask

```plaintext
Bit 0 (0x01): Left button
Bit 1 (0x02): Right button  
Bit 2 (0x04): Middle button
Bit 3 (0x08): Back button
Bit 4 (0x10): Forward button
```

#### Movement Interpretation

```plaintext
X positive: Move right
X negative: Move left
Y positive: Move down  
Y negative: Move up
Wheel positive: Scroll down/right
Wheel negative: Scroll up/left
```

#### Common Encodings to Try

1. **X movements as ASCII** (absolute values)
2. **Click sequences as binary** (left=0, right=1)
3. **Movement direction as base-4** (up=0, right=1, down=2, left=3)
4. **Coordinate pairs as characters** (x,y → char)
5. **Time intervals as values** (fast=0, slow=1)

-----

**Made with love by VIsh0k**