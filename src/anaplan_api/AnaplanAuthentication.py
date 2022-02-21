# ===============================================================================
# Created:			1 Nov 2021
# @author:			Jesse Wilson (Anaplan Asia Pte Ltd)
# Description:		Abstract Anaplan Authentication Class
# Input:			Username & Password, or SHA keypair
# Output:			Anaplan JWT and token expiry time
# ===============================================================================
import re
import logging
from .AnaplanRequest import AnaplanRequest
from .AuthToken import AuthToken
from .util.Util import AuthenticationFailedError

logger = logging.getLogger(__name__)


class AnaplanAuthentication(object):
	"""
	Represents an authentication attempt for Anaplan API
	"""

	def __init__(self):
		pass

	def auth_header(self, username: str, password: str):
		pass

	@staticmethod
	def auth_request(header: dict, body: dict = None) -> AnaplanRequest:
		"""Sends authentication request to Anaplan auth server

		:param header: Authorization header for request to auth server
		:type header: dict
		:param body: JSON body of auth request
		:type body: str
		:return: Object with request details for authentication
		:rtype: AnaplanRequest
		"""
		anaplan_url = 'https://auth.anaplan.com/token/authenticate'

		return AnaplanRequest(url=anaplan_url, header=header, body=body)

	@staticmethod
	def parse_authentication(response: dict) -> AuthToken:
		"""Parses the authentication response

		:param response: JSON string with auth request response.
		:type response: str
		:return: AnaplanAuthToken and expiry in epoch
		:rtype: AuthToken
		"""

		# Check that the request was successful, is so extract the AnaplanAuthToken value
		if 'status' in response:
			err_regex = re.compile('FAILURE.+')
			if not bool(re.match(err_regex, response['status'])):
				token = response['tokenInfo']['tokenValue']
				expires = response['tokenInfo']['expiresAt']
				logger.info("User successfully authenticated.")
				return AuthToken(f"AnaplanAuthToken {token}", expires)
			else:
				logger.error(f"Error {response['statusMessage']}")
				raise AuthenticationFailedError(f"Error logging in {response['statusMessage']}")

	@staticmethod
	def get_token_refresh(token: str) -> AnaplanRequest:
		"""Create object for sending token refresh request

		:param token: AnaplanAuthToken
		:type token: str
		:return: Object with url and header for token refresh
		:rtype: AnaplanRequest
		"""
		url = "https://auth.anaplan.com/token/refresh"
		header = {"Authorization": ''.join([token])}

		return AnaplanRequest(url=url, header=header)

	@staticmethod
	def parse_token_refresh(refresh: dict) -> AuthToken:
		"""Refreshes the authentication token and updates the token expiry time

		:param refresh: JSON response for token refresh request
		:type refresh: dict
		:return: New authentication details
		:rtype: AuthToken
		"""
		new_token = ""
		new_expiry = ""

		if 'status' in refresh:
			err_regex = re.compile('FAILURE.+')
			if not bool(re.match(err_regex, refresh['status'])):
				if 'tokenInfo' in refresh:
					if 'tokenValue' in refresh['tokenInfo']:
						new_token = refresh['tokenInfo']['tokenValue']
					if 'expiresAt' in refresh['tokenInfo']:
						new_expiry = refresh['tokenInfo']['expiresAt']
					return AuthToken(f"AnaplanAuthToken {new_token}", new_expiry)
			else:
				logger.error(f"Error {refresh['statusMessage']}")
				raise AuthenticationFailedError(f"Error logging in {refresh['statusMessage']}")
