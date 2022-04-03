from sqlalchemy import Column, ForeignKey, Integer, Float, String, DateTime, Boolean
from sqlalchemy.orm import relationship
from wpc.model.base import Base


class Work(Base):
    __tablename__ = 'works'
    id = Column(Integer, primary_key=True, autoincrement=True)
    date = Column(DateTime, nullable=False)
    from_dt = Column(DateTime, nullable=False)
    to_dt = Column(DateTime, nullable=False)
    minutes = Column(Integer)
    add = Column(Float)
    note = Column(String)
    registry = Column(String, nullable=False)
    price = Column(Float, nullable=False)
    prod = Column(Boolean, nullable=False, default=True)
    km = Column(Integer, nullable=False, default=0)

    customer_id = Column(Integer, ForeignKey("customers.id"))
    customer = relationship("Customer", foreign_keys=[customer_id])

    client_id = Column(Integer, ForeignKey("clients.id"))
    client = relationship("Client", foreign_keys=[client_id])

    def __repr__(self) -> str:
        return '<{0}.{1} #{2} :: registry:{3}>'.format(self.__module__, type(self).__name__, self.id, self.registry)

    @staticmethod
    def create(date, from_dt, to_dt, registry, prod, km, client_id, customer_id, minutes=None, add=None,
               note=None, price=12.0):
        x = Work()

        x.date = date
        x.from_dt = from_dt
        x.to_dt = to_dt
        x.registry = registry
        x.prod = prod
        x.km = km
        x.client_id = client_id
        x.customer_id = customer_id
        x.minutes = minutes
        x.add = add
        x.note = note
        x.price = price

        return x

    @property
    def date_str(self):
        """
        :return: A string representation for *date* date.
        """
        return self.date.strftime("%d/%m/%Y %H:%M")

    @property
    def from_dt_str(self):
        """
        :return: A string representation for *begin* date.
        """
        return self.from_dt.strftime("%d/%m/%Y %H:%M")

    @property
    def to_dt_str(self):
        """
        :return: A string representation for *end* date.
        """
        return self.to_dt.strftime("%d/%m/%Y %H:%M")

    @property
    def hours(self):
        """
        :return: The difference between end and begin, i.e., number of
            worker hours.
        """
        if self.from_dt is None or self.to_dt is None:
            return self.minutes

        return self.to_dt - self.from_dt
