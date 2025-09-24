from abc import ABC, abstractmethod
from typing import Any, Dict, List
import requests


class MarketplaceAdapter(ABC):
    @abstractmethod
    def get_orders(self, **kwargs) -> List[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def get_inventory(self, **kwargs) -> List[Dict[str, Any]]:
        raise NotImplementedError


class MercadoLibreAdapter(MarketplaceAdapter):
    def __init__(self, access_token: str, meli_user_id: str | None):
        self.access_token = access_token
        self.meli_user_id = meli_user_id

    def get_orders(self, days_back: int = 7, limit: int = 50) -> List[Dict[str, Any]]:
        from datetime import datetime, timedelta
        created_from = (datetime.utcnow() - timedelta(days=days_back)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        headers = {"Authorization": f"Bearer {self.access_token}"}
        url = f"https://api.mercadolibre.com/orders/search/recent?seller={self.meli_user_id}&order.date_created.from={created_from}&limit={limit}"
        res = requests.get(url, headers=headers, timeout=30)
        res.raise_for_status()
        return res.json().get('results', [])

    def get_inventory(self, **kwargs) -> List[Dict[str, Any]]:
        # Placeholder for a future implementation
        return []


class FalabellaAdapter(MarketplaceAdapter):
    def __init__(self, access_token: str | None = None):
        self.access_token = access_token

    def get_orders(self, **kwargs) -> List[Dict[str, Any]]:
        # Placeholder: estructura futura
        return []

    def get_inventory(self, **kwargs) -> List[Dict[str, Any]]:
        # Placeholder: estructura futura
        return []

