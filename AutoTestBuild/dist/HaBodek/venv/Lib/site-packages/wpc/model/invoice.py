from sqlalchemy import Column, ForeignKey, Integer, Float, String, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from wpc.model.base import Base


class Invoice(Base):

    __tablename__ = 'invoices'

    id = Column(Integer, primary_key=True, autoincrement=True)

    emitted_at = Column(DateTime, nullable=False, default=datetime.today())
    prog = Column(Integer)

    gross = Column(Float)
    tax = Column(Float)
    net = Column(Float)

    reason = Column(String, nullable=False)
    note = Column(String)

    customer_id = Column(Integer, ForeignKey("customers.id"))
    customer = relationship("Customer", foreign_keys=[customer_id])

    def __repr__(self) -> str:
        return '<{0}.{1} #{2} :: prog:{3}>'.format(self.__module__, type(self).__name__, self.id, self.prog)

    @staticmethod
    def create(emitted_at, prog, gross, tax, net, reason, note, customer_id):
        x = Invoice()
        x.emitted_at = emitted_at
        x.prog = prog
        x.gross = gross
        x.tax = tax
        x.net = net
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
