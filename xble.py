import logging
import os
import subprocess
import json
import re
import time
from datetime import datetime

import pwnagotchi.plugins as plugins
import pwnagotchi.ui.fonts as fonts
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK

class xble(plugins.Plugin):
    __author__ = 'nickmccollum'
    __version__ = '0.0.2'
    __license__ = 'GPL3'
    __description__ = 'A plugin that uses Bettercap to monitor for Bluetooth devices'

    DEFAULT_OPTIONS = {
        'timer': 45,
        'devices_file': '/root/handshakes/bluetooth_devices.json',
        'count_interval': 86400,
        'bt_x_coord': 160,
        'bt_y_coord': 66,
        'bettercap_path': '/usr/local/bin/bettercap',
        'bt_info_x_coord': 3,
        'bt_info_y_coord': 80,
        'last_ble_device_x_coord': 3,
        'last_ble_device_y_coord': 90
    }

    RECENT_DEVICE_WINDOW = 300  # 5 minutes in seconds
    def __init__(self):
        super().__init__()
        self.options = self.DEFAULT_OPTIONS.copy()
        self.data = {}
        self.last_scan_time = 0
        self.recent_devices = {}
        self.last_discovered_device = None  # Used in displaying the last discovered device

    def on_loaded(self):
        logging.info("[xble] Plugin loaded.")
        self._ensure_devices_file_exists()
        self._load_data()

    def on_ui_setup(self, ui):
        ui.add_element('xble', LabeledValue(
            color=BLACK,
            label='XBLE:',
            value=" ",
            position=(self.options.get("bt_x_coord", 160), self.options.get("bt_y_coord", 66)),
            label_font=fonts.Small,
            text_font=fonts.Small
        ))
        # This element will display pwnagotchi like sentences about the BLE devices.
        ui.add_element('ble_info', LabeledValue(
            color=BLACK,
            label='',
            value='',
            position=(self.options.get("bt_info_x_coord", 3), self.options.get("bt_info_y_coord", 80)),
            label_font=fonts.Small,
            text_font=fonts.Small
        ))
        ui.add_element('last_ble', LabeledValue(
            color=BLACK,
            label='Last:',
            value='',
            position=(self.options.get("last_ble_device_x_coord", 3), self.options.get("last_ble_device_y_coord", 90)),
            label_font=fonts.Small,
            text_font=fonts.Small
        ))

    def on_unload(self, ui):
        with ui._lock:
            ui.remove_element('xble')
            ui.remove_element('ble_info')
            ui.remove_element('last_ble')

    def on_ui_update(self, ui):
        if time.time() - self.last_scan_time >= self.options['timer']:
            self.last_scan_time = time.time()
            self.scan(ui)
        else:
            ui.set('xble', self.bt_sniff_info())

    def scan(self, ui=None):
        logging.info("[xble] Scanning for Bluetooth devices...")
        changed = False
        bettercap_path = self.options['bettercap_path']

        if not os.path.exists(bettercap_path):
            logging.error(f"[xble] Bettercap not found at {bettercap_path}")
            return

        cmd = f"{bettercap_path} -no-colors -eval 'ble.recon on; events.ignore ble.device.lost; sleep 30; ble.recon off; exit'"
        self._update_ui_for_scan(ui)
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode('utf-8')
        except subprocess.CalledProcessError as e:
            logging.error(f"[xble] Bettercap command failed: {e}")
            return

        current_time = time.time()
        for line in output.splitlines():
            if "new BLE device" in line and "detected as" in line:
                changed = self._process_device_line(line, current_time, ui, changed)

        # Remove devices older than 5 minutes
        self.recent_devices = {mac: timestamp for mac, timestamp in self.recent_devices.items() 
                               if current_time - timestamp <= self.RECENT_DEVICE_WINDOW}

        if changed:
            self._save_data()
            if ui:
                self._update_ble_info(ui, "BLE sniffed and stored!")

        # Update UI with recent device count and last discovered device
        recent_count = len(self.recent_devices)
        self._update_ble_info(ui, f"I see {recent_count} BLE devices!")

        if self.last_discovered_device and ui:
            device_info = self.last_discovered_device
            last_device_message = f"{device_info['name']}({device_info['manufacturer']})"
            self._update_last_device_info(ui, last_device_message)

    def bt_sniff_info(self):
        num_devices = len(self.data)
        num_unknown = sum(1 for device in self.data.values() if device['name'] == 'Unknown' or device['manufacturer'] == 'Unknown')
        num_recent = len(self.recent_devices)
        return f"5m:{num_recent} N:{num_devices - num_unknown}"

    def _update_ui(self, ui, message):
        ui.set('status', message)
        ui.update(force=True)

    def _update_ble_info(self, ui, message):
        ui.set('ble_info', message)
        ui.update(force=True)

    def _update_last_device_info(self, ui, message):
        if ui:
            truncated_message = message[:25] + ('...' if len(message) > 25 else '')
            ui.set('last_ble', truncated_message)
            ui.update(force=True)

    def _ensure_devices_file_exists(self):
        if not os.path.exists(self.options['devices_file']):
            os.makedirs(os.path.dirname(self.options['devices_file']), exist_ok=True)
            with open(self.options['devices_file'], 'w') as f:
                json.dump({}, f)
            logging.info("[xble] Created Bluetooth devices file.")

    def _load_data(self):
        with open(self.options['devices_file'], 'r') as f:
            self.data = json.load(f)

    def _save_data(self):
        with open(self.options['devices_file'], 'w') as f:
            json.dump(self.data, f)
        logging.info("[xble] Bluetooth devices updated and saved.")

    def _process_device_line(self, line, current_time, ui, changed):
        device_info = self._parse_device_info(line)
        if device_info:
            device_changed, new_named_device, device_name = self._update_device_data(device_info)
            changed |= device_changed

            # Update last discovered device
            self.last_discovered_device = device_info

            if ui:
                if new_named_device:
                    self._update_ui(ui, f"Hi BLE device {device_name}!")
                    #self._update_ble_info(ui, f"{device_name} from {device_info['manufacturer']}!")

                # Update last_ble element
                self._update_last_device_info(ui, f"{device_info['name']} ({device_info['manufacturer']})")
            # Update recent devices
            self.recent_devices[device_info['mac_address']] = current_time

        return changed

    def _update_ui_for_scan(self, ui):
        if ui:
            ui.set('face', '(ᛒ_ᛒ )')
            ui.set('status', 'Scanning for Bluetooth devices...')
            self._update_ble_info(ui, "BLE Scanning (30s)...")

    def _parse_device_info(self, line):
        name_part = line.split("new BLE device")[1].split("detected as")[0].strip()
        name = 'Unknown' if name_part == '' else name_part
        mac_address = line.split("detected as")[1].split()[0]
        manufacturer_match = re.search(r'\((.*?)\)', line)
        manufacturer = manufacturer_match.group(1) if manufacturer_match else 'Unknown'
        return {'name': name, 'mac_address': mac_address, 'manufacturer': manufacturer}

    def _update_device_data(self, device_info):
        mac_address = device_info['mac_address']
        current_time = time.time()
        changed = False
        new_named_device = False

        if mac_address in self.data:
            device = self.data[mac_address]
            if device['name'] == 'Unknown' and device_info['name'] != 'Unknown':
                device['name'] = device_info['name']
                changed = True
                new_named_device = True
            if device['manufacturer'] == 'Unknown' and device_info['manufacturer'] != 'Unknown':
                device['manufacturer'] = device_info['manufacturer']
                changed = True
            last_seen = int(datetime.strptime(device['last_seen'], '%H:%M:%S %d-%m-%Y').timestamp())
            if current_time - last_seen >= self.options['count_interval']:
                device['count'] += 1
                device['last_seen'] = time.strftime('%H:%M:%S %d-%m-%Y', time.localtime(current_time))
                changed = True
        else:
            self.data[mac_address] = {
                'name': device_info['name'],
                'count': 1,
                'manufacturer': device_info['manufacturer'],
                'first_seen': time.strftime('%H:%M:%S %d-%m-%Y', time.localtime(current_time)),
                'last_seen': time.strftime('%H:%M:%S %d-%m-%Y', time.localtime(current_time))
            }
            changed = True
            new_named_device = device_info['name']!= 'Unknown'

        return changed, new_named_device, device_info['name'] if new_named_device else None
