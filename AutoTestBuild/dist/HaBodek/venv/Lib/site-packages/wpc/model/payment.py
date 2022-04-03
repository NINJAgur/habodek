from sqlalchemy import Column, ForeignKey, Integer, Float, String, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from wpc.model.base import Base


class Payment(Base):

    __tablename__ = 'payments'

    id = Column(Integer, primary_key=True, autoincrement=True)

    paid_at = Column(DateTime, nullable=False, default=datetime.today())

    gross = Column(Float)
    tax = Column(Float)
    net = Column(Float, nullable=False)

    note = Column(String)

    # foreign key to customers.
    customer_id = Column(Integer, ForeignKey("customers.id"))
    customer = relationship("Customer", foreign_keys=[customer_id])

    # foreign key to invoices.
    invoice_id = Column(Integer, ForeignKey("invoices.id"))
    invoice = relationship("Invoice", foreign_keys=[invoice_id])

    def __repr__(self) -> str:
        return '<{0}.{1} #{2} :: net:{3}>'.format(self.__module__, type(self).__name__, self.id, self.net)

    @staticmethod
    def create(customer_id, paid_at, gross, tax, net, invoice, note=None):
        x = Payment()
        x.customer_id = customer_id
        x.paid_at = paid_at
        x.gross = gross
        x.tax = tax
        x.net = net
        x.note = note
        x.invoice = invoice
        x.invoice_id = invoice.id if invoice is not None else None
        return x

    @property
    def paid_at_str(self):
        """
        :return: A string representation for *paid_at* date.
        """
        return self.paid_at.strftime("%d/%m/%Y %H:%M")
