import socket
import platform
import uuid
import wmi


def get_beacon_info():
    """Collect basic host system information."""
    beacon_info = {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.release(),
        "uuid": str(uuid.getnode())
    }
    return beacon_info


def collect_devices():
    """Enumerate connected devices via WMI."""
    print("[*] Enumerating connected devices...\n")
    devices = []
    c = wmi.WMI()

    for device in c.Win32_PnPEntity():
        device_info = {
            "name": device.Name,
            "device_id": device.DeviceID,
            "status": device.Status,
            "manufacturer": device.Manufacturer
        }
        devices.append(device_info)
        
        print(f"- Name: {device_info['name']}")
        print(f"  Device ID: {device_info['device_id']}")
        print(f"  Status: {device_info['status']}")
        print(f"  Manufacturer: {device_info['manufacturer']}\n")

    if not devices:
        print("[-] No devices found or insufficient permissions.")

    return devices


if __name__ == "__main__":
    print("[+] Collecting beacon information:\n")
    beacon_info = get_beacon_info()
    for key, value in beacon_info.items():
        print(f"{key.capitalize()}: {value}")

    print("\n[+] Device Enumeration:\n")
    collect_devices()
