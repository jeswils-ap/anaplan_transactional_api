import logging
from util.AnaplanVersion import AnaplanVersion
from .AnaplanConnection import AnaplanConnection
from Model import Model

logger = logging.getLogger(__name__)


class Modules(Model):
	@staticmethod
	def get_modules(conn: AnaplanConnection) -> str:
		model__id = conn.get_model()

		url = ''.join([f'https://api.anaplan.com/{AnaplanVersion.major()}/{AnaplanVersion.minor()}/models/', model__id,
		               '/modules'])
		return url
