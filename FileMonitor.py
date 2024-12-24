import os
import hashlib
import pickle
import sys
import time
import signal
import re
import logging
from watchdog.observers import Observer
import win11toast
from tqdm import tqdm
from rich.traceback import install as rich_install
import humanize

from FileEventHandler import FileEventHandler

__all__ = ["FileMonitor"]

rich_install(width=300, show_locals=True)

# Configure logging
logging.getLogger("win11toast").setLevel(logging.ERROR)

class LoggerSetup:
	def __init__(self, log_path='./file_monitor.log', console_level=logging.DEBUG, file_level=logging.DEBUG):
		"""Initialize the logger with specified settings."""
		self.logger = logging.getLogger()
		self.logger.setLevel(logging.DEBUG)  # Set the root logger level

		# Create file handler
		self.file_handler = logging.FileHandler(log_path)
		self.file_handler.setLevel(file_level)

		# Create console handler
		self.console_handler = logging.StreamHandler()
		self.console_handler.setLevel(console_level)

		# Create a formatter and set it for both handlers
		self.formatter = logging.Formatter('%(asctime)s - PID:%(process)d - %(levelname)s - %(message)s')
		self.file_handler.setFormatter(self.formatter)
		self.console_handler.setFormatter(self.formatter)

		# Add handlers to the logger
		self.logger.addHandler(self.file_handler)
		self.logger.addHandler(self.console_handler)

	def get_logger(self):
		"""Return the configured logger."""
		return self.logger


class FileMonitor:
	def __init__(self, directory, ignore_patterns=None, state_file_path=None, log_path=None):
		self.directory = directory
		self.ignore_patterns = ignore_patterns if ignore_patterns else []
		self.file_paths = {}  # {file_path: (modified_time, hash)}
		self.hashes = {}  # {hash: [file_path]}
		self.duplicates = {}  # {hash: [file_path]}
		self.duplicates_size = 0
		self.state_file_path = state_file_path or os.path.join(self.directory, '.file_monitor_state.pkl')
		
		log_path = log_path or os.path.join(self.directory, '.file_monitor.log')
		self.logger = LoggerSetup(log_path).get_logger()

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
			self.logger.error(f"Access denied to file: {file_path}")
			# time.sleep(0.05)
			# return self.calculate_hash(file_path)
			return None
		return hash_sha1.hexdigest()

	def matches_ignore_patterns(self, file_path):
		"""Check if the file path matches any ignore patterns."""
		return any(re.search(pattern, file_path) for pattern in self.ignore_patterns)

	def initial_scan(self):
		"""Perform an initial scan of the directory with a progress bar."""
		self.logger.info("Performing initial scan")
		total_files = sum(len(files) for _, _, files in os.walk(self.directory))

		with tqdm(total=total_files, desc="Scanning files", unit="file") as pbar:
			for dirpath, dirnames, filenames in os.walk(self.directory):
				# Check if the current directory should be ignored
				if self.matches_ignore_patterns(dirpath):
					print('\r', end='')
					self.logger.info(f"Ignoring directory: {dirpath}")
					dirnames[:] = []  # Clear dirnames to prevent os.walk from traversing into this directory
					pbar.update(len(filenames))  # Update progress for ignored directory
					continue  # Skip ignored directories

				for filename in filenames:
					file_path = os.path.join(dirpath, filename)
					if self.matches_ignore_patterns(file_path):
						pbar.update(1)  # Update progress for ignored files
						continue  # Skip ignored files
					
					modified_time = os.path.getmtime(file_path)

					# Check if the file is already indexed
					if file_path in self.file_paths:
						# If the modified time is different, re-hash the file
						previous_modified_time, _ = self.file_paths[file_path]
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
		self.logger.info("Initial scan completed")

	def handle_file_event(self, file_path, operation):
		"""Handle file creation or modification."""
		if not os.path.isfile(file_path) or self.matches_ignore_patterns(file_path):
			return  # Skip ignored files

		# Get the current modified time and hash
		modified_time = os.path.getmtime(file_path)
		file_hash = self.calculate_hash(file_path)

		if file_hash is None:
			return  # Skip if access denied

		# Check if the file is already indexed
		if file_path in self.file_paths:
			previous_modified_time, previous_hash = self.file_paths[file_path]
			
			# If the modified time hasn't changed and the hash is the same, skip processing
			if modified_time == previous_modified_time and file_hash == previous_hash:
				self.logger.debug(f"File opened (no content change detected): {file_path}")
				return  # Skip processing if only opened

		# Check for duplicates
		if file_hash in self.hashes:
			self.logger.warning("Warning: Duplicate file detected")
			win11toast.toast("Duplicate File Detected", f"Duplicate file detected: {file_path}")

		# Update the file_paths and hashes
		self.file_paths[file_path] = (modified_time, file_hash)
		if file_hash in self.hashes:
			self.hashes[file_hash].append(file_path)
		else:
			self.hashes[file_hash] = [file_path]

		self.logger.info(f"{operation}: {file_path}")
		self.update_duplicates()  # Update duplicates after addition
	
	def update_duplicates(self):
		"""Update the duplicates dictionary based on current hashes."""
		self.duplicates = {hash_value: paths for hash_value, paths in self.hashes.items() if len(paths) > 1}

		self.duplicates_size = 0
	
		for _, file_paths in self.duplicates.items():
			num_files = len(file_paths)
			# Get the size of the first file in the group
			first_file_size = os.path.getsize(file_paths[0])
			# Calculate size of (N-1) files
			self.duplicates_size += first_file_size * (num_files - 1)

	def load_state(self):
		"""Load the state from a file if it exists."""
		if os.path.exists(self.state_file_path):
			with open(self.state_file_path, 'rb') as f:
				# Load state including ignore patterns
				try:
					self.file_paths, self.hashes, self.duplicates, self.duplicates_size, loaded_ignore_patterns = pickle.load(f)
				except EOFError:
					pass

				if self.ignore_patterns:
					self.logger.debug("Overwriting loaded ignore patterns with provided patterns.")
				else:
					self.ignore_patterns = loaded_ignore_patterns
			self.logger.info(f"Loaded state: {len(self.file_paths)} file paths, {len(self.hashes)} hashes, {len(self.duplicates)} duplicated groups (total size of {humanize.naturalsize(self.duplicates_size)})")

			# Remove files that match ignore patterns from all indexes
			removed_count = 0  # Initialize a counter for removed files
			for file_path in list(self.file_paths.keys()):
				if self.matches_ignore_patterns(file_path):
					self.logger.info(f"Removing ignored file from index: {file_path}")
					# Remove from file_paths
					del self.file_paths[file_path]
					# Remove from hashes
					previous_hash = self.file_paths.get(file_path, (None, None))[1]
					if previous_hash in self.hashes:
						self.hashes[previous_hash].remove(file_path)
						if not self.hashes[previous_hash]:  # If no more files with this hash
							del self.hashes[previous_hash]
					removed_count += 1  # Increment the counter
			
			# Clean up hashes to remove any files not in file_paths
			for file_hash in list(self.hashes.keys()):
				# Remove any file paths from the hash that are not in file_paths
				self.hashes[file_hash] = [path for path in self.hashes[file_hash] if path in self.file_paths]
				# If no more files with this hash, remove the hash entry
				if not self.hashes[file_hash]:
					del self.hashes[file_hash]
			
			# Log the number of removed files with DEBUG priority
			self.logger.debug(f"Total files removed from index due to ignore patterns: {removed_count}")
			
			# Update duplicates after removal
			self.update_duplicates()

	def save_state(self):
		"""Save the current state to a file."""
		with open(self.state_file_path, 'wb') as f:
			# Save state including ignore patterns
			pickle.dump((self.file_paths, self.hashes, self.duplicates, self.duplicates_size, self.ignore_patterns), f)
		self.logger.info("State saved")
	
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
			self.logger.info("Monitoring paused")

	def resume_monitoring(self):
		"""Resume monitoring of the directory."""
		if self.paused:
			self.observer.start()  # Restart the observer
			self.initial_scan()  # Perform an initial scan after resuming
			self.paused = False
			self.logger.info("Monitoring resumed")

	def start_monitoring(self):
		"""Start monitoring the directory for changes."""
		signal.signal(signal.SIGINT, self.signal_handler)  # Register the signal handler

		self.initial_scan()
		self.print_duplicates()

		# code.interact(local=locals() | globals())
		
		event_handler = FileEventHandler(self)
		self.observer.schedule(event_handler, self.directory, recursive=True)
		self.observer.start()
		
		self.logger.info("Monitor started")
		try:
			while True:
				time.sleep(1)
		except KeyboardInterrupt:
			self.observer.stop()
			self.logger.info("Stopping monitoring")
		except Exception as e:
			self.observer.stop()
			self.logger.critical(f"Critical error: {e}")
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
		os._exit(0)
