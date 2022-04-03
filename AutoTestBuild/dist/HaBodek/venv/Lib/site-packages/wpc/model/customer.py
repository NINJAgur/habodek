from sqlalchemy import Column, Integer, String
from wpc.model.base import Base


class Customer(Base):
    __tablename__ = 'customers'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)

    def __repr__(self) -> str:
        return '<{0}.{1} #{2} :: name:{3}>'.format(self.__module__, type(self).__name__, self.id, self.name)
