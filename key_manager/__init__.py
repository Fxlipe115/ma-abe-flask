from abc import ABC, abstractmethod
from typing import List

class KeyManager(ABC):
    @abstractmethod
    def store_key(self, key_name: str, key: str) -> None:
        pass

    @abstractmethod
    def retrieve_key(self, key_name: str) -> str:
        pass

    @abstractmethod
    def retrieve_keys(self, key_names: List[str]) -> List[str]:
        pass