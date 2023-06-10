import os
import time
import hashlib
import requests
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

VIRUSTOTAL_API_KEY = 'Enter your API Key here'

class FileHandler(FileSystemEventHandler):

    def calculate_hash_and_check_virus_total(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            return
        sha256_hash = hashlib.sha256(data).hexdigest()

        params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': sha256_hash}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)

        # Check if the response is JSON
        try:
            json_response = response.json()
        except json.JSONDecodeError:
            print(f"Error decoding JSON for {filepath}")
            return

        if json_response['response_code']:
            print(f"{filepath} is malicious, deleting")
            if os.path.exists(filepath):  # Re-check if the file exists
                try:
                    os.remove(filepath)
                except OSError as e:
                    print(f"Error: {e.filename} - {e.strerror}")
        else:
            print(f"{filepath} is safe")

    def process(self, event):
        filepath = event.src_path
        if not os.path.isdir(filepath) and os.path.exists(filepath) and not filepath.endswith('.download'):
            self.calculate_hash_and_check_virus_total(filepath)

    def on_created(self, event):
        self.process(event)

    def on_moved(self, event):
        self.process(event)

    def on_modified(self, event):
        self.process(event)

if __name__ == "__main__":
    observer = Observer()
    observer.schedule(FileHandler(),
    path='Enter your Downloads folder path here', recursive=True)  
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

