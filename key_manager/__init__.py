from abc import ABC, abstractmethod

class KeyManager(ABC):
    @abstractmethod
    def store_key(self, key_name: str, key: str) -> None:
        pass

    @abstractmethod
    def retrieve_key(self, key_name: str) -> str:
        pass