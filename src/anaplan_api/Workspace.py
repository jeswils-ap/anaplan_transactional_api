import logging
from typing import List
from .AnaplanRequest import AnaplanRequest
from .User import User
from .WorkspaceDetails import WorkspaceDetails

logger = logging.getLogger(__name__)


class Workspace(User):
	def get_workspaces_url(self) -> AnaplanRequest:
		"""
		:return: Object with request details for getting workspaces
		:rtype: AnaplanRequest
		"""
		url = ''.join([super().get_url(), super().get_id(), "/workspaces"])

		get_header = {
			"Content-Type": "application/json"
		}

		return AnaplanRequest(url=url, header=get_header)

	@staticmethod
	def parse_workspaces(workspace_list: dict) -> List[WorkspaceDetails]:
		"""Parse list of workspaces into friendly object.

		:param workspace_list: JSON list of workspaces available to the current user.
		:type workspace_list: dict
		:raises AttributeError: Error locating Workspaces in JSON response
		:return: List of workspace details
		:rtype: List[WorkspaceDetails]
		"""
		workspace_details_list = [WorkspaceDetails]

		logger.info("Parsing workspaces...")
		if 'workspaces' in workspace_list:
			workspaces = workspace_list['workspaces']
			for item in workspaces:
				workspace_details_list.append(WorkspaceDetails(item))
			logger.info("Finished parsing workspaces.")
			return workspace_details_list
		else:
			raise AttributeError("Workspaces not found in response.")
