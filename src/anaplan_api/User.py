import logging
from .AnaplanConnection import AnaplanConnection
from .AnaplanRequest import AnaplanRequest
from .util.AnaplanVersion import AnaplanVersion
from .UserDetails import UserDetails

logger = logging.getLogger(__name__)


class User:
	"""
	Class representing an Anaplan user
	"""
	_url: str = f"https://api.anaplan.com/{AnaplanVersion.major()}/{AnaplanVersion.minor()}/users/"
	_conn: AnaplanConnection
	_user_id: str
	_user_details: UserDetails

	def get_current_user_url(self) -> AnaplanRequest:
		"""Get the ID of the current user
		"""
		if self._user_id is None:
			url = ''.join([self._url, "me"])

			get_header = {
				"Content-Type": "application/json"
			}

			return AnaplanRequest(url=url, header=get_header)

	def set_current_user(self, user_details: dict):
		"""Set current user ID and user details

		:param user_details: JSON response containing user details
		:type user_details: dict
		:raises KeyError: Error locating User or ID in Response
		"""
		if 'user' in user_details:
			if 'id' in user_details['user']:
				self._user_id = user_details['user']['id']
				self._user_details = UserDetails(user_details['user'])
			else:
				raise KeyError("'id' not found in response")
		else:
			raise KeyError("'user' not found in response")

	def get_url(self) -> str:
		"""Get base URL for user requests

		:return: User details url
		:rtype: str
		"""
		return self._url

	def get_id(self) -> str:
		"""Get ID of the specified user

		:return: User ID
		:rtype: str
		"""
		return self._user_id

	def get_user(self) -> UserDetails:
		"""Get details for the specified user

		:return: Friendly user details
		:rtype: UserDetails
		"""
		return self._user_details
