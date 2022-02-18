import logging
from .AnaplanConnection import AnaplanConnection
from .util.Util import ResourceNotFoundError
from .util.AnaplanVersion import AnaplanVersion
from .AnaplanRequest import AnaplanRequest

logger = logging.getLogger(__name__)


class Resources:
    @staticmethod
    def get_resource_request(conn: AnaplanConnection, resource: str) -> AnaplanRequest:
        """Get the list of items of the specified resource


        """
        base_url = f"https://api.anaplan.com/{AnaplanVersion.major()}/{AnaplanVersion.minor()}/workspaces/"
        valid_resources = ["imports", "exports", "actions", "processes", "files", "lists", "modules"]
        get_header = {
            'Content-Type': 'application/json'
        }

        if resource.lower() in valid_resources:
            url = ''.join([base_url, conn.get_workspace(), "/models/", conn.get_model(), "/", resource.lower()])
            return AnaplanRequest(url=url, header=get_header)
        else:
            raise ResourceNotFoundError(f"Invalid selection, resource must be one of {', '.join(valid_resources)}")

    @staticmethod
    def parse_resource_request():
        pass
