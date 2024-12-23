import os
import hashlib
import pickle
import sys
import time
import signal
import re
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import win11toast
from tqdm import tqdm
from rich.traceback import install as rich_install

__all__ = ["FileMonitor"]

rich_install(width=300, show_locals=True)

# Configure logging
logging.getLogger("win11toast").setLevel(logging.ERROR)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Create file handler
file_handler = logging.FileHandler("file_monitor.log")
file_handler.setLevel(logging.DEBUG)

# Create console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

# Create a formatter and set it for both handlers
formatter = logging.Formatter('%(asctime)s - PID:%(process)d - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

class FileMonitor:
	def __init__(self, directory, ignore_patterns=None):
		self.directory = directory
		self.ignore_patterns = ignore_patterns if ignore_patterns else []
		self.file_paths = {}  # {file_path: (modified_time, hash)}
		self.hashes = {}  # {hash: [file_path]}
		self.duplicates = {}  # {hash: [file_path]}
		self.load_state()
		self.observer = Observer()  # Initialize the observer here
		self.paused = False  # New variable to track paused state

	def calculate_hash(self, file_path):
		"""Calculate SHA-1 hash of a file."""
		hash_sha1 = hashlib.sha1()
		try:
			with open(file_path, 'rb') as f:
				for chunk in iter(lambda: f.read(4096), b""):
					hash_sha1.update(chunk)
		except PermissionError:
			logging.error(f"Access denied to file: {file_path}")
			# time.sleep(0.05)
			# return self.calculate_hash(file_path)
			return None
		return hash_sha1.hexdigest()

	def matches_ignore_patterns(self, file_path):
		"""Check if the file path matches any ignore patterns."""
		return any(re.search(pattern, file_path) for pattern in self.ignore_patterns)

	def initial_scan(self):
		"""Perform an initial scan of the directory with a progress bar."""
		logging.info("Performing initial scan")
		total_files = sum(len(files) for _, _, files in os.walk(self.directory))

		with tqdm(total=total_files, desc="Scanning files", unit="file") as pbar:
			for dirpath, _, filenames in os.walk(self.directory):
				for filename in filenames:
					file_path = os.path.join(dirpath, filename)
					if self.matches_ignore_patterns(file_path):
						pbar.update(1)  # Update progress for ignored files
						continue  # Skip ignored files
					
					modified_time = os.path.getmtime(file_path)

					# Check if the file is already indexed
					if file_path in self.file_paths:
						# If the modified time is different, re-hash the file
						previous_modified_time, previous_hash = self.file_paths[file_path]
						if modified_time != previous_modified_time:
							file_hash = self.calculate_hash(file_path)
							if file_hash is None:
								continue  # Skip if access denied
							self.file_paths[file_path] = (modified_time, file_hash)
						else:
							pbar.update(1)  # Update progress for unchanged files
							continue
					else:
						# New file detected, calculate its hash
						file_hash = self.calculate_hash(file_path)
						if file_hash is None:
							continue  # Skip if access denied
						self.file_paths[file_path] = (modified_time, file_hash)

					# Update the hashes dictionary
					if file_hash in self.hashes:
						self.hashes[file_hash].append(file_path)
					else:
						self.hashes[file_hash] = [file_path]

					pbar.update(1)  # Update progress for processed files

		self.update_duplicates()
		self.save_state()  # Save the state immediately after the full scan
		logging.info("Initial scan completed")

	def on_created(self, event):
		"""Handle file creation events."""
		self.handle_file_event(event.src_path, "File created")

	def on_modified(self, event):
		"""Handle file modification events."""
		self.handle_file_event(event.src_path, "File modified")

	def on_deleted(self, event):
		"""Handle file deletion events."""
		file_path = event.src_path
		if file_path in self.file_paths:
			# Get the hash before deleting the file
			previous_hash = self.file_paths[file_path][1]
			logger.info(f"File deleted: {file_path}")
			
			# Remove from file_paths
			del self.file_paths[file_path]
			
			# Remove from hashes
			if previous_hash in self.hashes:
				self.hashes[previous_hash].remove(file_path)
				if not self.hashes[previous_hash]:  # If no more files with this hash
					del self.hashes[previous_hash]
			
			self.update_duplicates()  # Update duplicates after deletion
		
	def on_moved(self, event):
		"""Handle file move events."""
		src_path = event.src_path
		dest_path = event.dest_path

		if src_path in self.file_paths:
			logging.info(f"File moved from {src_path} to {dest_path}")
			# Get the modified time and hash of the moved file
			modified_time, file_hash = self.file_paths[src_path]
			# Update the file_paths dictionary
			del self.file_paths[src_path]
			self.file_paths[dest_path] = (modified_time, file_hash)

			# Update the hashes dictionary
			if file_hash in self.hashes:
				self.hashes[file_hash].remove(src_path)
				self.hashes[file_hash].append(dest_path)
			else:
				self.hashes[file_hash] = [dest_path]

			self.update_duplicates()  # Update duplicates after moving

	def handle_file_event(self, file_path, operation):
		"""Handle file creation or modification."""
		if not os.path.isfile(file_path) or self.matches_ignore_patterns(file_path):
			return  # Skip ignored files

		modified_time = os.path.getmtime(file_path)
		file_hash = self.calculate_hash(file_path)

		if file_hash is None:
			return  # Skip if access denied

		# Check for duplicates
		if file_hash in self.hashes:
			logging.warning("Warning: Duplicate file detected")
			win11toast.toast("Duplicate File Detected", f"Duplicate file detected: {file_path}")

		# Update the file_paths and hashes
		self.file_paths[file_path] = (modified_time, file_hash)
		if file_hash in self.hashes:
			self.hashes[file_hash].append(file_path)
		else:
			self.hashes[file_hash] = [file_path]

		logging.info(f"{operation}: {file_path}")
		self.update_duplicates()  # Update duplicates after addition

	def update_duplicates(self):
		"""Update the duplicates dictionary based on current hashes."""
		self.duplicates = {hash_value: paths for hash_value, paths in self.hashes.items() if len(paths) > 1}

	def load_state(self):
		"""Load the state from a file if it exists."""
		if os.path.exists('file_monitor_state.pkl'):
			with open('file_monitor_state.pkl', 'rb') as f:
				self.file_paths, self.hashes, self.duplicates = pickle.load(f)
			logging.info(f"Loaded state: {len(self.file_paths)} file paths, {len(self.hashes)} hashes, {len(self.duplicates)} duplicates")

			# Remove files that match ignore patterns from all indexes
			removed_count = 0  # Initialize a counter for removed files
			for file_path in list(self.file_paths.keys()):
				if self.matches_ignore_patterns(file_path):
					logger.info(f"Removing ignored file from index: {file_path}")
					# Remove from file_paths
					del self.file_paths[file_path]
					# Remove from hashes
					previous_hash = self.file_paths.get(file_path, (None, None))[1]
					if previous_hash in self.hashes:
						self.hashes[previous_hash].remove(file_path)
						if not self.hashes[previous_hash]:  # If no more files with this hash
							del self.hashes[previous_hash]
					removed_count += 1  # Increment the counter
			
			# Log the number of removed files with DEBUG priority
			logger.debug(f"Total files removed from index due to ignore patterns: {removed_count}")
			
			# Update duplicates after removal
			self.update_duplicates()


	def save_state(self):
		"""Save the current state to a file."""
		with open('file_monitor_state.pkl', 'wb') as f:
			pickle.dump((self.file_paths, self.hashes, self.duplicates), f)
		logging.info("State saved")
	
	def print_duplicates(self):
		"""Print the duplicate file groups."""
		for file_hash, paths in self.duplicates.items():
			print(f"Duplicate files for hash {file_hash}:")
			for path in paths:
				print(f"  {path}")
			print()  # Add a newline for better readability

	def pause_monitoring(self):
		"""Pause the monitoring of the directory."""
		if not self.paused:
			self.observer.stop()
			self.paused = True
			logging.info("Monitoring paused")

	def resume_monitoring(self):
		"""Resume monitoring of the directory."""
		if self.paused:
			self.observer.start()  # Restart the observer
			self.initial_scan()  # Perform an initial scan after resuming
			self.paused = False
			logging.info("Monitoring resumed")

	def start_monitoring(self):
		"""Start monitoring the directory for changes."""
		signal.signal(signal.SIGINT, self.signal_handler)  # Register the signal handler

		self.initial_scan()
		self.print_duplicates()
		
		event_handler = FileSystemEventHandler()
		event_handler.on_created = self.on_created
		event_handler.on_modified = self.on_modified
		event_handler.on_deleted = self.on_deleted
		event_handler.on_moved = self.on_moved

		self.observer.schedule(event_handler, self.directory, recursive=True)
		self.observer.start()
		
		logging.info("Monitor started")
		try:
			while True:
				time.sleep(1)
		except KeyboardInterrupt:
			self.observer.stop()
			logging.info("Stopping monitoring")
		except Exception as e:
			self.observer.stop()
			logging.critical(f"Critical error: {e}")
		finally:
			self.observer.stop()
			self.observer.join()
			self.save_state()  # Save the state before exiting
	
	def signal_handler(self, sig, frame):
		"""Handle the signal for graceful shutdown."""
		print("Signal received. Cleaning up...")
		self.observer.stop()
		self.save_state()  # Save the state before exiting
		print("Exiting...")
		sys.exit(0)
