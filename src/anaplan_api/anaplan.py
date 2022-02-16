# ===============================================================================
# Created:        11 Sep 2018
# @author:        Jesse Wilson (Anaplan Asia Pte Ltd)
# Description:    Library to implement Anaplan API to get lists of model resources, upload files to Anaplan server,
#                 download files from Anaplan server, and execute actions.
# ===============================================================================
import logging
from typing import Union
from . import UserDetails
from .AnaplanConnection import AnaplanConnection
from .BasicAuthentication import BasicAuthentication
from .CertificateAuthentication import CertificateAuthentication
from .Resources import Resources
from .ResourceParserList import ResourceParserList
from .AnaplanResourceList import AnaplanResource
from .AuthToken import AuthToken
from User import User
from .util.Util import InvalidAuthenticationError

logger = logging.getLogger(__name__)


# ===========================================================================
# This function reads the authentication type, Basic or Certificate, then passes
# the remaining variables to anaplan_auth to generate the authorization for Anaplan API
# ===========================================================================
def generate_authorization(auth_type: str = "Basic", email: str = None, password: str = None,
                           private_key: Union[bytes, str] = None, cert: Union[bytes, str] = None) -> AuthToken:
    """Generate an Anaplan AuthToken object

    :param auth_type: Basic or Certificate authentication
    :param email: Anaplan email address for Basic auth
    :param password: Anaplan password for Basic auth
    :param private_key: Private key string or path to key file
    :param cert: Public certificate string or path to file
    :return: AnaplanAuthToken value and expiry time in epoch
    :rtype: AuthToken
    """

    if auth_type.lower() == 'basic' and email and password:
        basic = BasicAuthentication()
        header_string = basic.auth_header(email, password)
        return basic.authenticate(basic.auth_request(header_string))
    elif auth_type.lower() == 'certificate' and cert and private_key:
        cert_auth = CertificateAuthentication()
        header_string = cert_auth.auth_header(cert)
        post_data = cert_auth.generate_post_data(private_key)
        return cert_auth.authenticate(cert_auth.auth_request(header_string, post_data))
    else:
        if (email and password) or (cert and private_key):
            logger.error(f"Invalid authentication method: {auth_type}")
            raise InvalidAuthenticationError(f"Invalid authentication method: {auth_type}")
        else:
            logger.error("Email address and password or certificate and key must not be blank")
            raise InvalidAuthenticationError("Email address and password or certificate and key must not be blank")


# ===========================================================================
# This function queries the Anaplan model for a list of the desired resources:
# files, actions, imports, exports, processes and returns the JSON response.
# ===========================================================================
def get_list(conn: AnaplanConnection, resource: str) -> AnaplanResource:
    """Get list of the specified resource in the Anaplan model

    :param conn: AnaplanConnection object which contains AuthToken object, workspace ID, and model ID
    :type conn: AnaplanConnection
    :param resource: The Anaplan model resource to be queried and returned to the user
    :type resource: str
    :return: Detailed list of the requested resource
    :rtype: AnaplanResource
    """

    resources = Resources(conn=conn, resource=resource)
    resources_list = resources.get_resources()
    resource_parser = ResourceParserList()
    return resource_parser.get_parser(resources_list)


def get_user(conn) -> UserDetails:
    """Get details for current user

    :param conn: Object which contains AuthToken object, workspace ID, and model ID
    :return: Details for current user
    :rtype: UserDetails
    """
    current_user = User(conn)
    current_user.get_current_user()

    return current_user.get_user()
