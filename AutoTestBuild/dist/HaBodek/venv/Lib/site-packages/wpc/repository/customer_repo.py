from .crudrepo import CrudRepo
from wpc.model import Customer


class CustomerRepo(CrudRepo):

    def __init__(self, clazz=Customer):
        super().__init__(clazz)
