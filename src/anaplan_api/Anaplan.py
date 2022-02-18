# ===============================================================================
# Created:        11 Sep 2018
# @author:        Jesse Wilson (Anaplan Asia Pte Ltd)
# Description:    Library to implement Anaplan API to get lists of model resources, upload files to Anaplan server,
#                 download files from Anaplan server, and execute actions.
# ===============================================================================
import logging
import requests
import requests.sessions
from requests.exceptions import HTTPError, SSLError, Timeout, ConnectTimeout, ReadTimeout
from time import time
from typing import Union
from .AnaplanConnection import AnaplanConnection
from .BasicAuthentication import BasicAuthentication
from .CertificateAuthentication import CertificateAuthentication
from .Resources import Resources
from .ResourceParserList import ResourceParserList
from .AnaplanResourceList import AnaplanResource
from .AnaplanRequest import AnaplanRequest
from .User import User
from .UserDetails import UserDetails
from .util.Util import InvalidTokenError, RequestFailedError

logger = logging.getLogger(__name__)


class Anaplan:
    _session: requests.sessions.Session
    _conn: AnaplanConnection

    def __init__(self, workspace_id: str, model_id: str, auth_type: str = "Basic", email: str = None,
                 password: str = None, private_key: Union[bytes, str] = None, cert: Union[bytes, str] = None):
        self._conn = AnaplanConnection(authorization=self._generate_authorization(auth_type=auth_type, email=email,
                                                                                  password=password,
                                                                                  private_key=private_key, cert=cert),
                                       workspace_id=workspace_id, model_id=model_id)

    def __enter__(self):
        self._session.headers.update({'Authorization': self._conn.get_auth().get_auth_token()})
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._session.close()

    @staticmethod
    def _check_expired(expiry: float):
        return expiry - (10 * 60) > time()

    def _get(self, req: AnaplanRequest):
        expiry: float
        result: requests.Response

        try:
            expiry = self._conn.get_auth().get_token_expiry()
        except InvalidTokenError:
            raise InvalidTokenError("Unable to read token expiry time")

        if self._check_expired(expiry):
            try:
                result = self._session.get(req.get_url(), headers=req.get_header(), timeout=(5, 30))
            except (HTTPError, ConnectionError, SSLError, Timeout, ConnectTimeout, ReadTimeout) as e:
                logger.error(f"Error with request {e}")

        if result.ok:
            try:
                result_text = result.text
                return result_text
            except ValueError as e:
                logger.error(f"Error reading request body {e}")
        else:
            raise RequestFailedError(f"Error with request HTTP error {result.status_code}")

    def _post(self, req: AnaplanRequest):
        expiry: float
        result: requests.Response

        try:
            expiry = self._conn.get_auth().get_token_expiry()
        except InvalidTokenError:
            raise InvalidTokenError("Unable to read token expiry time")

        if self._check_expired(expiry):
            try:
                result = self._session.get(req.get_url(), headers=req.get_header(), json=req.get_body(),
                                           timeout=(5, 30))
            except (HTTPError, ConnectionError, SSLError, Timeout, ConnectTimeout, ReadTimeout) as e:
                logger.error(f"Error with request {e}")

        if result.ok:
            try:
                result_text = result.text
                return result_text
            except ValueError as e:
                logger.error(f"Error reading request body {e}")
        else:
            raise RequestFailedError(f"Error with request HTTP error {result.status_code}")

    def _put(self, req: AnaplanRequest):
        expiry: float
        result: requests.Response

        try:
            expiry = self._conn.get_auth().get_token_expiry()
        except InvalidTokenError:
            raise InvalidTokenError("Unable to read token expiry time")

        if self._check_expired(expiry):
            try:
                result = self._session.put(req.get_url(), headers=req.get_header(), data=req.get_body(),
                                           timeout=(5, 30))
            except (HTTPError, ConnectionError, SSLError, Timeout, ConnectTimeout, ReadTimeout) as e:
                logger.error(f"Error with request {e}")

        if result.ok:
            try:
                result_text = result.text
                return result_text
            except ValueError as e:
                logger.error(f"Error reading request body {e}")
        else:
            raise RequestFailedError(f"Error with request HTTP error {result.status_code}")

    # ===========================================================================
    # This function reads the authentication type, Basic or Certificate, then passes
    # the remaining variables to anaplan_auth to generate the authorization for Anaplan API
    # ===========================================================================
    def _generate_authorization(self, auth_type: str = "Basic", email: str = None, password: str = None,
                                private_key: Union[bytes, str] = None, cert: Union[bytes, str] = None) -> None:
        """
        :param auth_type: Basic or Certificate authentication
        :param email: Anaplan email address for Basic auth
        :param password: Anaplan password for Basic auth
        :param private_key: Private key string or path to key file
        :param cert: Public certificate string or path to file
        :return:
        """

        if auth_type.lower() == 'basic' and email and password:
            basic = BasicAuthentication()
            header_string = basic.auth_header(email, password)
            self._conn.set_auth(basic.parse_authentication(basic.auth_request(header_string)))
        elif auth_type.lower() == 'certificate' and cert and private_key:
            cert_auth = CertificateAuthentication()
            header_string = cert_auth.auth_header(cert)
            post_data = cert_auth.generate_post_data(private_key)
            self._conn.set_auth(cert_auth.parse_authentication(cert_auth.auth_request(header_string, post_data)))
        else:
            logger.error(f"Invalid authentication method: {auth_type}")
            raise ValueError(f"Invalid authentication method: {auth_type}")

    # ===========================================================================
    # This function queries the Anaplan model for a list of the desired resources:
    # files, actions, imports, exports, processes and returns the JSON response.
    # ===========================================================================
    def get_list(self, resource: str) -> AnaplanResource:
        """
        :param resource: The Anaplan model resource to be queried and returned to the user
        """

        resources = Resources(self._conn, resource)
        resources_list = resources.get_resources()
        resource_parser = ResourceParserList()
        return resource_parser.get_parser(resources_list)

    def get_user(self, conn: AnaplanConnection) -> UserDetails:
        """Get details for current user

        :param conn: Object which contains AuthToken object, workspace ID, and model ID
        :return: Details for current user
        :rtype: UserDetails
        """
        current_user = User(conn)
        current_user.get_current_user()

        return current_user.get_user()
