from sqlalchemy import Column, ForeignKey, Integer, Float, String, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from wpc.model.base import Base


class Report(Base):

    __tablename__ = 'reports'

    id = Column(Integer, primary_key=True, autoincrement=True)

    emitted_at = Column(DateTime, nullable=False, default=datetime.today())

    from_dt = Column(DateTime, nullable=False)
    to_dt = Column(DateTime, nullable=False)

    gross = Column(Float, nullable=False)
    tax = Column(Float, nullable=False)
    net = Column(Float, nullable=False)

    hours_non_prod = Column(Float, nullable=False)
    hours_prod = Column(Float, nullable=False)
    hours = Column(Float, nullable=False)

    reason = Column(String)
    note = Column(String)

    customer_id = Column(Integer, ForeignKey("customers.id"))
    customer = relationship("Customer", foreign_keys=[customer_id])

    def __repr__(self) -> str:
        return '<{0}.{1} #{2} :: {3}>'.format(self.__module__, type(self).__name__, self.id, self.emitted_at_str)

    @staticmethod
    def create(emitted_at, from_dt, to_dt, gross, tax, net, hours_np, hours_p, hours, reason, note, customer_id):
        x = Report()
        x.emitted_at = emitted_at
        x.from_dt = from_dt
        x.to_dt = to_dt
        x.gross = gross
        x.tax = tax
        x.net = net
        x.hours_non_prod = hours_np
        x.hours_prod = hours_p
        x.hours = hours
        x.reason = reason
        x.note = note
        x.customer_id = customer_id
        return x

    @property
    def emitted_at_str(self):
        """
        :return: A string representation for *emitted_at* date.
        """
        return self.emitted_at.strftime("%d/%m/%Y %H:%M")

    @property
    def from_dt_str(self):
        """
        :return: A string representation for *from_dt* date.
        """
        return self.from_dt.strftime("%d/%m/%Y %H:%M")

    @property
    def to_dt_str(self):
        """
        :return: A string representation for *to_dt* date.
        """
        return self.to_dt.strftime("%d/%m/%Y %H:%M")
