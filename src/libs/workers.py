import asyncio
from concurrent.futures import Future
from threading import Thread
from typing import Callable


class SyncWorkerThread:
    """Worker for synchronous functions. Returns a Future immediately, with optional timeout."""

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
        self._worker = Thread(target=self._run_loop, daemon=True)
        self._worker.start()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def submit_job(
            self,
            func: Callable,
            args: tuple | None = None,
            kwargs: dict | None = None,
            timeout: float = 15.0
        ) -> Future:
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
        ) -> list[Future]:
            args = args or [() for _ in funcs]
            kwargs = kwargs or [{} for _ in funcs]
            return [
                self.submit_job(func=_func, args=_args, kwargs=_kwargs, timeout=timeout)
                for _func, _args, _kwargs in zip(funcs, args, kwargs)
            ]

    def stop(self,timeout:float=1.0) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._worker.join(timeout=timeout)
        self._loop.close()


class AsyncWorkerThread:
    """Worker for async functions. Returns a Future immediately, with optional timeout."""

    def __init__(self,max_concurrent: int = 500) -> None:
        self._loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
        self._semaphore = asyncio.Semaphore(max_concurrent)
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
        ) -> Future:
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
        args: list[tuple]| None = None,
        kwargs: list[dict] | None = None,
        timeout: float = 15.0,
    ) -> list[Future]:
        args = args or [() for _ in funcs]
        kwargs = kwargs or [{} for _ in funcs]
        return [
            self.submit_job(func=_func, args=_args, kwargs=_kwargs, timeout=timeout)
            for _func, _args, _kwargs in zip(funcs, args, kwargs)
        ]

    def stop(self,timeout:float=1.0) -> None:
        def _cancel_tasks():
            for task in asyncio.all_tasks(loop=self._loop):
                task.cancel()
        self._loop.call_soon_threadsafe(_cancel_tasks)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._worker.join(timeout=timeout)
        self._loop.close()
