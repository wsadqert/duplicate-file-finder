from FileMonitor import FileMonitor

# Example usage
if __name__ == "__main__":
	monitor = FileMonitor(r"D:\media\Pictures\Camera-sync", ignore_patterns=[r'desktop\.ini$'])
	monitor.start_monitoring()
