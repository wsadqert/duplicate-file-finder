from FileMonitor import FileMonitor
from pprint import pprint

# Example usage
if __name__ == "__main__":
	monitor = FileMonitor(
		r"C:/Users/user/Pictures", 
		ignore_patterns=[
			r"desktop\.ini$",
			r"\.tmp$",
			r"\.stfolder.*",
			r"\.trashed.*$",
		],
		# state_file_path="./file_monitor_state.pkl"
	)
	monitor.start_monitoring()
