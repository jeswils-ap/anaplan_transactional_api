import logging
from typing import List
from .AnaplanRequest import AnaplanRequest
from .User import User
from .ModelDetails import ModelDetails

logger = logging.getLogger(__name__)


class Model(User):
	def get_models_url(self) -> AnaplanRequest:
		"""Get list of all Anaplan model for the specified user.

		:return: Object containing API request details
		:rtype: AnaplanRequest
		"""

		url = ''.join([super().get_url(), super().get_id(), "/models"])

		get_header = {
			"Content-Type": "application/json"
		}

		return AnaplanRequest(url=url, header=get_header)

	@staticmethod
	def parse_models(model_list: dict) -> List[ModelDetails]:
		"""Get list of all Anaplan model for the specified user.

		:param model_list: JSON list of models accessible to the current user
		:type model_list: dict
		:raises AttributeError: No models available for specified user.
		:return: Details for all models the user can access.
		:rtype: List[ModelDetails]
		"""

		model_details_list = [ModelDetails]
		logger.info(f"Parsing models...")

		if 'models' in model_list:
			models = model_list['models']
			logger.info("Finished parsing models.")
			for item in models:
				model_details_list.append(ModelDetails(item))
			return model_details_list
		else:
			raise AttributeError("Models not found in response.")
