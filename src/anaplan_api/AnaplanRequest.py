import json
from dataclasses import dataclass
from typing import Union


@dataclass()
class AnaplanRequest:
	_url: str
	_header: dict
	_body: dict = None

	def __init__(self, url: str, header: dict, body: Union[dict, str] = None):
		"""
		:param url: URL for API request
		:type url: str
		:param header: JSON header for request
		:type header: dict
		:param body: Body for API request
		:type body: Union[dict, str]
		"""
		self._url = url
		self._header = header
		if body:
			body = json.loads(body) if type(body) is str else body
			self._body = body

	def get_url(self) -> str:
		return self._url

	def get_header(self) -> dict:
		return self._header

	def get_body(self) -> dict:
		return self._body
		'''
		if self._body:
			return self._body
		else:
			raise ValueError("Request body is empty")
		'''
