import sys
import time
import sched
import signal
import psutil
import os
import threading
from threading import Thread
from typing import Callable
from functools import partial


class Scheduler:
    def __init__(self: "Scheduler", schedule_interval: int = 60, function_to_schedule: Callable = None, function_to_schedule_arguments: list = None) -> None:
        """Initialize the Scheduler."""
        if function_to_schedule is None:
            raise ValueError("Function missing")
        self._scheduler = sched.scheduler(timefunc=time.monotonic, delayfunc=time.sleep)
        self._schedule_interval = schedule_interval
        self._schedule_function = function_to_schedule
        self._schedule_arguments = function_to_schedule_arguments or []
        self._schedule_status_running = False

    def start_schedule(self: "Scheduler") -> None:
        """Start the scheduler."""
        self._schedule_status_running = True
        self._enter_task()
        scheduler_thread = Thread(
            target=self._scheduler.run,
            daemon=True,
            name=f"scheduler-{str(self._schedule_function.__name__)}")
        scheduler_thread.start()

    def _enter_task(self: "Scheduler") -> None:
        """Queue next task for scheduling."""
        if self._schedule_status_running:  # Check if the scheduler is still running
            self._scheduler.enter(delay=self._schedule_interval,
                                  priority=1,
                                  action=self.task_runner,
                                  argument=self._schedule_arguments)

    def task_runner(self: "Scheduler") -> None:
        """Execute the scheduled function with its arguments."""
        if self._schedule_function:
            try:
                self._schedule_function(*self._schedule_arguments)
            except Exception as e:
                print(f"Error while executing the scheduled function: {e}")

        # This is what schedules the next taks
        if self._schedule_status_running:
            self._enter_task()

    def stop_schedule(self: "Scheduler") -> None:
        """Stop the scheduler."""
        self._schedule_status_running = False
        print("Scheduler stopped.")


def print_current_process_usage():
    pid = os.getpid()
    process = psutil.Process(pid)
    cpu_percent = process.cpu_percent(interval=None)
    memory_info = process.memory_info()
    memory_usage = memory_info.rss
    print(f"{time.time()} PID:{pid} Usage:CPU Usage: {cpu_percent}% Memory Usage (RSS): {memory_usage / (1024 ** 2):.2f} MB")


def start():
    schedule_process = Scheduler(schedule_interval=1, function_to_schedule=print_current_process_usage)
    schedule_process.start_schedule()

    # SIGINT (Ctrl+C) SIGTERM
    signal.signal(signal.SIGINT, partial(terminate_signal_handler, schedulers=[schedule_process]))
    signal.signal(signal.SIGTERM, partial(terminate_signal_handler, schedulers=[schedule_process]))

    # Keep the main thread alive
    while True:
        time.sleep(1)


def terminate_signal_handler(signal_received, frame, schedulers):
    """Gracefully handle termination signal and stop all schedulers."""
    for scheduler in schedulers:
        scheduler.stop_schedule()
        print("Waiting for threads to finish...")

    for thread in threading.enumerate():
        if thread is not threading.main_thread():
            thread.join(timeout=1)  # Allow 1 second for each thread to finish
    print("Shutdown complete.")
    sys.exit(0)  # Safe exit after cleanup


start()
