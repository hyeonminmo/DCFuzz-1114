import enum
from pathlib import Path
from typing import Any, Dict, List

Coverage = Dict[str, Any]


class FuzzerType(enum.Enum):
    AFLGo = 'aflgo'
    DAFL = 'dafl'
    WindRanger = 'windranger'


class SeedType(enum.Enum):
    NORMAL = enum.auto()
    CRASH = enum.auto()
    HANG = enum.auto()


class WatcherConfig:
    def __init__(self, fuzzer: FuzzerType, output_dir: Path):
        self.fuzzer = fuzzer
        self.output_dir = output_dir

    def __eq__(self, other):
        return (self.fuzzer == other.fuzzer
                and self.output_dir.resolve() == other.output_dir.resolve())

    def __hash__(self):
        return hash(self.fuzzer.value + str(self.output_dir.resolve()))

# def test():
#     assert FuzzerType('aflgo')

# if __name__ == '__main__':
#     test()