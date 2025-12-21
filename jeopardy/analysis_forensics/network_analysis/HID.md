### HID Mouse Events Analysis

HID (Human Interface Device) refers to USB devices like mice and keyboards that communicate with the host via interrupt transfers. Mouse events are generated when the mouse is moved, buttons are pressed/released, or the scroll wheel is used. In CTF forensics, analyzing HID data from PCAP files can reveal user interactions, such as mouse movements simulating keystrokes or hidden commands.

HID mouse reports typically consist of 4-8 bytes: button states, X/Y movement deltas, and wheel data. The first byte indicates button presses (e.g., bit 0 for left button).

#### HID Protocol Overview

  * **Report Descriptor**: Defines the data format sent by the device.
  * **Reports**: Periodic data packets (e.g., every 10ms for mice).
  
  * **Common Structure** (4-byte report):
    * Byte 0: Buttons (bit 0: Left, 1: Right, 2: Middle, etc.)
    * Byte 1: X-axis movement (signed 8-bit, -127 to 127)
    * Byte 2: Y-axis movement (signed 8-bit)
    * Byte 3: Wheel movement (signed 8-bit)

#### Example Raw Data

  * **Sample HID Reports** (hex)

    ```
    0000020001000000  # Left button down, no movement
    0000030000000000  # Right button down
    0000030001000000  # Right button up, slight Y movement
    0000030001000000  # Continued movement
    0000020001000000  # Left button up
    ```

    Interpretation: User clicked right button, moved mouse slightly.

  * **Wireshark Structure**

    ```
    USB URB
        Endpoint: 0x81, Direction: IN
        URB transfer type: URB_INTERRUPT (0x01)
    HID Data: 0000010000000000  # Left click
    ```

#### Extraction Commands

Use TShark to extract HID data from PCAP:

```bash
# Extract HID mouse data
tshark -r mickey_mouse.pcapng -T fields -Y 'usb.endpoint_address.direction == IN and usb.transfer_type == 1' -e usbhid.data | xxd -p -r
```

Filter for interrupt IN transfers on typical mouse endpoint (0x81).

#### Analysis Tips

  * **Mouse-to-Keyboard Simulation**: In some challenges, mouse movements encode keystrokes (e.g., moving right for 'A').
  * **Event Reconstruction**: Parse deltas to reconstruct cursor path or clicks.
  * **Tools**: Use `usbhid-dump` on Linux or Wireshark's USB dissector.
  * **CTF Use**: Look for patterns like repeated clicks or unusual movements indicating data exfiltration.

#### Other HID Event Types

  * **Keyboard**: Reports key presses (scancodes).
  * **Gamepad**: Buttons, axes, triggers.
  * Analyze with: `tshark -r capture.pcap -Y "usbhid" -T fields -e usbhid.data`

-----

**Made with love by VIsh0k**