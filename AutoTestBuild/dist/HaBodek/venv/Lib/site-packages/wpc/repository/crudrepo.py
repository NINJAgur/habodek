from .baserepo import BaseRepo
from wpc.model import Customer


class CrudRepo(BaseRepo):

    def create(self, x):
        self._s().add(x)
        self._s().commit()

    def remove(self, x):
        self._s().delete(x)
        self._s().commit()

    def update(self, x):
        # self._s().commit()
        # TODO: implement or remove this method.
        pass

    def find(self, id_):
        return self._q().filter(self._clazz.id == id_).first()

    def getAll(self, *criterion):
        return self._q().filter(*criterion).all()
