import asyncio
from concurrent import futures
from threading import Event, Thread
from typing import Callable


class SyncWorkerThread:
    """Worker for synchronous functions. Returns a Future immediately, with optional timeout."""

    def __init__(self) -> None:
        self._stop_event = Event()
        self._loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
        self._worker = Thread(target=self._run, daemon=True)
        self._worker.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def submit_job(
            self,
            func: Callable,
            args: tuple | None = None,
            kwargs: dict | None = None,
            timeout: float = 15.0
        ) -> futures.Future:
            if self._stop_event.is_set():
                raise RuntimeError("Worker has been stopped. Cannot submit new jobs.")
            args = args or ()
            kwargs = kwargs or {}
            if not callable(func):
                raise TypeError("func must be callable")
            if not isinstance(args, tuple):
                raise TypeError("args must be tuple")
            if not isinstance(kwargs, dict):
                raise TypeError("kwargs must be dict")
            if timeout is not None and (not isinstance(timeout, (int, float)) or timeout <= 0):
                raise TypeError("timeout must be positive float or None")

            async def wrapper():
                coro = asyncio.to_thread(func, *args, **kwargs)
                if timeout:
                    return await asyncio.wait_for(coro, timeout)
                return await coro

            return asyncio.run_coroutine_threadsafe(wrapper(), self._loop)

    def submit_jobs(
            self,
            funcs: list[Callable],
            args: list[tuple] | None = None,
            kwargs: list[dict] | None = None,
            timeout: float = 15.0
        ) -> list[futures.Future]:
            args = args or [() for _ in funcs]
            kwargs = kwargs or [{} for _ in funcs]

            if timeout is not None and (not isinstance(timeout, (int, float)) or timeout <= 0):
                raise TypeError("timeout must be positive float or None")
            if len(args) != len(funcs) or len(kwargs) != len(funcs):
                raise ValueError("Length of args and kwargs must match length of funcs")

            return [
                self.submit_job(func=_func, args=_args, kwargs=_kwargs, timeout=timeout)
                for _func, _args, _kwargs in zip(funcs, args, kwargs)
            ]

    def stop(self,timeout:float=1.0) -> None:
        self._stop_event.set()
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._worker.join(timeout=timeout)
        self._loop.close()


class AsyncWorkerThread:
    """Runs asynchronous callables on a dedicated event loop in a background thread.

    Characteristics:
    - Each instance owns a single asyncio event loop running in its own thread.
    - Submitted coroutines execute asynchronously and concurrently on that loop.
    - Concurrency is bounded by an asyncio.Semaphore.
    - The submission boundary is synchronous and thread-safe.
    - Results are exposed via concurrent.futures.Future objects.

    Important semantics:
    - Returning a Future does NOT block execution.
    - Blocking occurs only if the caller calls Future.result().
    - Cancellation is cooperative and best-effort.
    - Timeouts cancel the awaiting coroutine, not the underlying work.

    This design is suitable when:
    - Callers are synchronous.
    - Async work must run concurrently off-thread.
    - The caller controls when or whether to block.
    """

    def __init__(self,max_concurrent: int = 500) -> None:
        """Initialize the worker and start the background event loop thread.

        Args:
            max_concurrent:
                Maximum number of coroutines allowed to execute concurrently.
                Additional submitted jobs are queued by the event loop until
                permits become available.

        Notes:
            - The event loop starts immediately.
            - No backpressure is applied at submission time.

        """
        self._max_concurrent = max_concurrent
        self._stop_event = Event()
        self._loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
        self._worker = Thread(target=self._run, daemon=True)
        self._worker.start()

    def _run(self) -> None:
        """Entry point for the worker thread.

        This method is executed in the background thread created by the worker.
        It binds the asyncio event loop to the current thread, initializes
        concurrency controls, and runs the event loop indefinitely.

        Behavior:
            - Sets the worker event loop as the current loop for this thread.
            - Creates an asyncio.Semaphore bound to this event loop to limit
            concurrent coroutine execution.
            - Starts the event loop and processes scheduled coroutines until
            the loop is explicitly stopped.

        Notes:
            - This method blocks the worker thread for the lifetime of the worker.
            - It must not be called directly.
            - Shutdown is triggered externally via loop.stop().

        """
        asyncio.set_event_loop(self._loop)
        self._semaphore = asyncio.Semaphore(self._max_concurrent)
        self._loop.run_forever()

    def submit_job(
            self,
            func: Callable,
            args: tuple | None = None,
            kwargs: dict | None = None,
            timeout: float = 15.0
        ) -> futures.Future:
        """Schedule an async callable for execution on the worker event loop.

        This method is synchronous and thread-safe.
        It schedules the coroutine immediately and returns a Future handle.

        Args:
            func:
                An async callable (coroutine function).
            args:
                Positional arguments passed to the callable.
            kwargs:
                Keyword arguments passed to the callable.
            timeout:
                Maximum time in seconds to await coroutine completion.
                The timeout cancels the await, not the underlying coroutine
                if it ignores cancellation.

        Returns:
            concurrent.futures.Future:
                A handle representing the eventual result.

        Behavior:
            - The coroutine executes asynchronously.
            - Multiple submitted jobs run concurrently.
            - Calling Future.result() blocks the caller thread.
            - Not calling result() keeps execution fully asynchronous.

        Raises:
            TypeError:
                If func is not async or arguments are invalid.

        """
        if self._stop_event.is_set():
            raise RuntimeError("Worker has been stopped. Cannot submit new jobs.")

        args = args or ()
        kwargs = kwargs or {}
        if not asyncio.iscoroutinefunction(func):
            raise TypeError("func must be async")
        if not isinstance(args, tuple):
            raise TypeError("args must be tuple")
        if not isinstance(kwargs, dict):
            raise TypeError("kwargs must be dict")
        if timeout is not None and (not isinstance(timeout, (int, float)) or timeout <= 0):
            raise TypeError("timeout must be positive float")

        async def wrapper():
            async with self._semaphore:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=timeout)

        return asyncio.run_coroutine_threadsafe(wrapper(), self._loop)

    def submit_jobs(
        self,
        funcs: list[Callable],
        args: list[tuple] | None = None,
        kwargs: list[dict] | None = None,
        timeout: float = 15.0,
    ) -> list[futures.Future]:
        """Schedule multiple async callables for execution.

        Each callable is submitted independently and immediately.
        All returned Futures complete independently.

        Args:
            funcs:
                List of async callables.
            args:
                Optional list of argument tuples, one per callable.
            kwargs:
                Optional list of keyword-argument dictionaries, one per callable.
            timeout:
                Timeout applied per callable.

        Returns:
            List[concurrent.futures.Future]:
                One Future per submitted callable.

        Notes:
            - Jobs are scheduled concurrently.
            - Execution order is not guaranteed.
            - Argument lists are zipped; mismatched lengths truncate.

        """
        args = args or [() for _ in funcs]
        kwargs = kwargs or [{} for _ in funcs]
        return [
            self.submit_job(func=_func, args=_args, kwargs=_kwargs, timeout=timeout)
            for _func, _args, _kwargs in zip(funcs, args, kwargs)
        ]

    def stop(self,timeout:float=1.0) -> None:
        """Stop the worker event loop and background thread.

        Behavior:
            - Attempts to cancel all running tasks.
            - Requests the event loop to stop.
            - Waits up to `timeout` seconds for the thread to exit.
            - Closes the event loop.

        Notes:
            - Cancellation is cooperative.
            - Long-running or non-cancellable coroutines may delay shutdown.
            - Submitting new jobs after stop() is undefined behavior.

        """
        def _cancel_tasks():
            for task in asyncio.all_tasks():
                task.cancel()
        self._stop_event.set()
        self._loop.call_soon_threadsafe(_cancel_tasks)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._worker.join(timeout=timeout)
        self._loop.close()
