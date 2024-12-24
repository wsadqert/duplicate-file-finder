from watchdog.events import FileSystemEventHandler

class FileEventHandler(FileSystemEventHandler):
	"""File event handler for the file system observer."""
	def __init__(self, monitor: "FileMonitor"):
		super().__init__()
		self.monitor = monitor
	
	def on_created(self, event):
		"""Handle file creation events."""
		self.monitor.handle_file_event(event.src_path, "File created")

	def on_modified(self, event):
		"""Handle file modification events."""
		self.monitor.handle_file_event(event.src_path, "File modified")

	def on_deleted(self, event):
		"""Handle file deletion events."""
		file_path = event.src_path
		if file_path in self.monitor.file_paths:
			# Get the hash before deleting the file
			previous_hash = self.monitor.file_paths[file_path][1]
			self.monitor.logger.info(f"File deleted: {file_path}")
			
			# Remove from file_paths
			del self.monitor.file_paths[file_path]
			
			# Remove from hashes
			if previous_hash in self.monitor.hashes:
				self.monitor.hashes[previous_hash].remove(file_path)
				if not self.monitor.hashes[previous_hash]:  # If no more files with this hash
					del self.monitor.hashes[previous_hash]
			
			self.monitor.update_duplicates()  # Update duplicates after deletion
		
	def on_moved(self, event):
		"""Handle file move events."""
		src_path = event.src_path
		dest_path = event.dest_path

		if src_path in self.monitor.file_paths:
			self.monitor.logger.info(f"File moved from {src_path} to {dest_path}")
			# Get the modified time and hash of the moved file
			modified_time, file_hash = self.monitor.file_paths[src_path]
			# Update the file_paths dictionary
			del self.monitor.file_paths[src_path]
			self.monitor.file_paths[dest_path] = (modified_time, file_hash)

			# Update the hashes dictionary
			if file_hash in self.monitor.hashes:
				self.monitor.hashes[file_hash].remove(src_path)
				self.monitor.hashes[file_hash].append(dest_path)
			else:
				self.monitor.hashes[file_hash] = [dest_path]

			self.monitor.update_duplicates()  # Update duplicates after moving
