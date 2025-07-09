import socket
import platform
import uuid
import logging

try:
    import wmi  # type: ignore
except ImportError:  # Non-Windows systems
    wmi = None

logger = logging.getLogger(__name__)


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
    """Enumerate connected devices via WMI if available."""
    logger.info("Enumerating connected devices...")
    devices = []
    if wmi is None:
        logger.warning("WMI module not available; skipping device enumeration")
        return devices

    c = wmi.WMI()

    for device in c.Win32_PnPEntity():
        device_info = {
            "name": device.Name,
            "device_id": device.DeviceID,
            "status": device.Status,
            "manufacturer": device.Manufacturer
        }
        devices.append(device_info)

        logger.info(
            "- Name: %s\n  Device ID: %s\n  Status: %s\n  Manufacturer: %s",
            device_info["name"],
            device_info["device_id"],
            device_info["status"],
            device_info["manufacturer"],
        )

    if not devices:
        logger.info("No devices found or insufficient permissions")

    return devices


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Collecting beacon information...")
    beacon_info = get_beacon_info()
    for key, value in beacon_info.items():
        logger.info("%s: %s", key.capitalize(), value)

    logger.info("Device Enumeration:")
    collect_devices()
