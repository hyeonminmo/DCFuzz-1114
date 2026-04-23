#!/usr/bin/env python3

import argparse
import logging
import sys
import time
from abc import ABC
from pathlib import Path
from threading import Condition, Event, Lock
from typing import Dict, Iterable, List, Optional, Set, Union

import watchdog
from watchdog.events import DirCreatedEvent, FileCreatedEvent
from watchdog.observers import Observer
from .mytype import FuzzerType, SeedType, WatcherConfig


logger = logging.getLogger('dcfuzz.watcher')

ARGS = None

watcher_lock = Lock()

PROCESSED_DIR = set()


class WatcherException(Exception):
    pass

class _NewTestCaseHandler(watchdog.events.FileSystemEventHandler):
    def __init__( self, test_case_queue: List[Path],
        test_in_queue: Condition,
        test_case_blacklist: Set[Path]
    ):
        self._test_case_queue = test_case_queue
        self._test_in_queue = test_in_queue
        self._test_case_blacklist = test_case_blacklist

    def on_created(self, event: Union[DirCreatedEvent, FileCreatedEvent]):
        if isinstance(event, FileCreatedEvent):
            with self._test_in_queue:
                test_case_path = Path(event.src_path)

                # Filter out test cases that have already been recorded on startup
                if test_case_path not in self._test_case_blacklist:
                    # logger.debug(f"Found new test case: {test_case_path}")
                    self._test_case_queue.append(test_case_path)
                    self._test_in_queue.notify()


class Watcher(ABC):
    QUEUE_POLL_TIMEOUT = 0.5  # Queue polling in seconds
    WAIT_DIR_TIMEOUT = 0.5  # Directory waiting timeout in seconds
    FILE_READ_DELAY = 0.1  # Delay before reading a test case just created in seconds

    def __init__(self, target_directories: Iterable[Path]):
        self._target_directories = target_directories
        self._observer: Optional[watchdog.observers.Observer] = None

        self.test_case_queue: List[Path] = []
        self.test_case_blacklist: Set[Path] = set()
        self._stopping = Event()
        self._test_in_queue = Condition()

    def _wait_for_dir(self, dir_path) -> None:
        # This is a helper function that can be used inside _manage_directories
        # to wait for a directory to be created.
        while not dir_path.is_dir():
            time.sleep(self.WAIT_DIR_TIMEOUT)

    def _manage_directories(self) -> None:
        # When this function terminates, all the target directories should be
        # present and ready to be observed.
        pass

    def _initialize_observer(self) -> None:
        self._observer = Observer()
        new_test_case_scheduler = _NewTestCaseHandler(self.test_case_queue,
                                                      self._test_in_queue,
                                                      self.test_case_blacklist)

        for target_directory in self._target_directories:
            logger.debug(f"Observing directory: {target_directory}")
            self._observer.schedule(new_test_case_scheduler,
                                    str(target_directory))

    def _scan_target_folders(self) -> None:
        test_cases = []
        for target_directory in self._target_directories:
            for test_case in target_directory.iterdir():
                if test_case.is_file():
                    # logger.debug(f"Found existing test case: {test_case}")
                    test_cases.append(test_case)

        test_cases.sort(key=lambda file_path: file_path.stat().st_ctime)
        self.test_case_queue.extend(test_cases)

        # Ensure that test cases detected by this function are not reported again
        self.test_case_blacklist.update(test_cases)

    def start(self, daemon=False) -> None:
        if self.is_alive():
            logger.critical("Watcher has already been started, skip")
            return

        logger.debug("Starting watcher")

        logger.debug("Preparing directories")
        self._manage_directories()
        logger.debug("Initializing watcher")
        self._initialize_observer()
        assert self._observer is not None

        with self._test_in_queue:
            # The observer will not add new paths to the queue until
            # _test_in_queue is released, but it will start accumulating
            # events.
            logger.debug("Starting observer")
            self._observer.daemon = daemon
            self._observer.start()

            # Test cases created before the observer is started will be added
            # to the queue.
            logger.debug("Scanning for existing test cases")
            self._scan_target_folders()
            self._test_in_queue.notify()

        # _test_in_queue is released and the observer start queuing the paths
        # accumulated during initialization

    def is_alive(self) -> bool:
        return (self._observer is not None and self._observer.is_alive())

    def stop(self) -> None:
        logger.debug("Stopping watcher")

        self._stopping.set()

        if self._observer is not None:
            self._observer.stop()

    def _ignore_test_case(self, test_case_path: Path) -> bool:
        return False

    def _get_test_case_type(self, test_case_path: Path) -> SeedType:
        return SeedType.NORMAL

    def _get_test_case_parents(self, test_case_path: Path) -> Iterable[str]:
        return []

    def _process_test_case(self) -> None:
        test_case_path = self.test_case_queue.pop(0)
        logger.debug(f"Processing test case: {test_case_path}")

        if self._ignore_test_case(test_case_path):
            logger.debug(f"Test case ignored: {test_case_path}")
            return

        # Give some time to the fuzzer to finish writing the file
        time.sleep(self.FILE_READ_DELAY)

        with open(test_case_path, "rb") as test_case_file:
            test_case = test_case_file.read()



class AFLGoWatcher(Watcher):
    def __init__(self, config: WatcherConfig):
        # AFL reuses the output directory if it already exists, but creates the
        # directories in it
        fuzzer_dir = config.output_dir
        fuzzer_dir.mkdir(parents=True, exist_ok=True)

        target_directories = (
            fuzzer_dir / "queue",
            fuzzer_dir / "crashes",
            fuzzer_dir / "hangs",
        )
        
        super().__init__(target_directories)
        

    def _manage_directories(self) -> None:
        for target_directory in self._target_directories:
            logger.debug(f"Waiting on directory: {target_directory}")
            self._wait_for_dir(target_directory)

    def _ignore_test_case(self, test_case_path: Path) -> bool:
        # Ignore files that do not conform to the naming convention
        if not test_case_path.name.startswith("id:"):
            return True
        if 'orig' in test_case_path.name:
            return True
        if 'sync' in test_case_path.name:
            return True
        return False

    def _get_test_case_type(self, test_case_path: Path) -> SeedType:
        if test_case_path.parts[-2] == "crashes":
            test_case_type = SeedType.CRASH
        elif test_case_path.parts[-2] == "hangs":
            test_case_type = SeedType.HANG
        elif test_case_path.parts[-2] == "queue":
            test_case_type = SeedType.NORMAL
        else:
            raise ValueError("Unknown seed type observed.")

        return test_case_type

class DAFLWatcher(Watcher):
    def __init__(self, config: WatcherConfig):
        # AFL reuses the output directory if it already exists, but creates the
        # directories in it
        fuzzer_dir = config.output_dir
        fuzzer_dir.mkdir(parents=True, exist_ok=True)

        target_directories = (
            fuzzer_dir / "queue",
            fuzzer_dir / "crashes",
            fuzzer_dir / "hangs",
        )

        super().__init__(target_directories)

    def _manage_directories(self) -> None:
        for target_directory in self._target_directories:
            logger.debug(f"Waiting on directory: {target_directory}")
            self._wait_for_dir(target_directory)

    def _ignore_test_case(self, test_case_path: Path) -> bool:
        # Ignore files that do not conform to the naming convention
        if not test_case_path.name.startswith("id:"):
            return True
        if 'orig' in test_case_path.name:
            return True
        if 'sync' in test_case_path.name:
            return True
        return False

    def _get_test_case_type(self, test_case_path: Path) -> SeedType:
        if test_case_path.parts[-2] == "crashes":
            test_case_type = SeedType.CRASH
        elif test_case_path.parts[-2] == "hangs":
            test_case_type = SeedType.HANG
        elif test_case_path.parts[-2] == "queue":
            test_case_type = SeedType.NORMAL
        else:
            raise ValueError("Unknown seed type observed.")

        return test_case_type

class WindRangerWatcher(Watcher):
    def __init__(self, config: WatcherConfig):
        fuzzer_dir = config.output_dir
        fuzzer_dir.mkdir(parents=True, exist_ok=True)

        target_directories = (
            fuzzer_dir / "queue",
            fuzzer_dir / "crashes",
            fuzzer_dir / "hangs",
        )

        super().__init__(target_directories)

    def _manage_directories(self) -> None:
        for target_directory in self._target_directories:
            logger.debug(f"Waiting on directory: {target_directory}")
            self._wait_for_dir(target_directory)

    def _ignore_test_case(self, test_case_path: Path) -> bool:
        # Ignore files that do not conform to the naming convention
        if not test_case_path.name.startswith("id:"):
            return True
        if 'orig' in test_case_path.name:
            return True
        if 'sync' in test_case_path.name:
            return True
        return False

    def _get_test_case_type(self, test_case_path: Path) -> SeedType:
        if test_case_path.parts[-2] == "crashes":
            test_case_type = SeedType.CRASH
        elif test_case_path.parts[-2] == "hangs":
            test_case_type = SeedType.HANG
        elif test_case_path.parts[-2] == "queue":
            test_case_type = SeedType.NORMAL
        else:
            raise ValueError("Unknown seed type observed.")

        return test_case_type


CONFIG_WATCHERS: Dict[WatcherConfig, Watcher] = {}

WATCHERS: Dict[str, List[Watcher]] = {}



def get_watcher(config: WatcherConfig) -> Watcher:
    watcher: Watcher
    
    # logging.info(f'watcher 003 - get {config.fuzzer} watcher')

    if config in CONFIG_WATCHERS:
        return CONFIG_WATCHERS[config]

    if config.fuzzer == FuzzerType.AFLGo:    
        watcher = AFLGoWatcher(config)
    elif config.fuzzer == FuzzerType.DAFL:
        watcher = DAFLWatcher(config)
    elif config.fuzzer == FuzzerType.WindRanger:
        watcher = WindRangerWatcher(config)
    else:
        raise Exception(f"Invalid fuzzer: {config.fuzzer}")

    CONFIG_WATCHERS[config] = watcher
    return watcher

def init_watcher(fuzzer: str, fuzzer_output: Path) -> None:
    global WATCHERS, PROCESSED_DIR

    logging.info(f'watcher 001 - start init {fuzzer} watcher')

    if fuzzer_output in PROCESSED_DIR:
        return
    with watcher_lock:
        if not fuzzer in WATCHERS:
            WATCHERS[fuzzer] = []
        ft = FuzzerType(fuzzer)
        config: WatcherConfig = WatcherConfig(ft, fuzzer_output)    
        w = get_watcher(config)
        WATCHERS[fuzzer].append(w)
        w.start(daemon=True)
        PROCESSED_DIR.add(fuzzer_output)
    
    logging.info(f'watcher 004 - WATCHERS : {WATCHERS}, PROCESSED_DIR : {PROCESSED_DIR}')


def main() -> int:
    return 0

if __name__ == '__main__':
    sys.exit(main())