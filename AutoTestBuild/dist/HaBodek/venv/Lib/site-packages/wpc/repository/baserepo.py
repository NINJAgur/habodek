from wpc.db.db import Database
from wpc.config.config import Configurator


class BaseRepo(object):
    _db = Database()
    _clazz = None
    _configurator = Configurator()

    def __init__(self, clazz):
        """
        BaseRepo Constructor. Initializes the repository with the model.
        :param clazz: The repo model class.
        """
        self._clazz = clazz

    def _q(self, clazz=None):
        """
        :return: The query instanced with the model class.
        """
        return self._db.session.query(clazz if clazz is not None else self._clazz)

    def _s(self):
        """
        :return: A session.
        """
        return self._db.session

    def query(self):
        """
        :return: A blank query.
        """
        return self._q()


