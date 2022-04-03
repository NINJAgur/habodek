from sqlalchemy import func, extract

from wpc.model import Invoice, InvoiceWithHours
from .crudrepo import CrudRepo


class InvoiceRepo(CrudRepo):

    def __init__(self, clazz=Invoice):
        super().__init__(clazz)

    def _q(self, clazz=None):
        q = super(CrudRepo, self)._q(clazz)

        if clazz is None:
            q = q.filter(Invoice.customer_id == super()._configurator.customer)
            q = q.order_by(Invoice.emitted_at.asc())  # asc useful in CLI apps.

        return q

    def getAll(self, *criterion):
        return self._q().all()

    # def getAllWithHours(self):
    #     return self._q(InvoiceWithHours) \
    #         .filter(InvoiceWithHours.customer_id == super()._configurator.customer) \
    #         .order_by(InvoiceWithHours.emitted_at.desc(), InvoiceWithHours.from_dt.desc())\
    #         .all()
    #
    # def getEmittedBetweenWithHours(self, begin, end):
    #     return self._q(InvoiceWithHours) \
    #         .filter(InvoiceWithHours.customer_id == super()._configurator.customer) \
    #         .filter(InvoiceWithHours.emitted_at >= begin) \
    #         .filter(InvoiceWithHours.emitted_at <= end) \
    #         .order_by(InvoiceWithHours.emitted_at.desc(), InvoiceWithHours.from_dt.desc())\
    #         .all()

    def getNextProg(self, date):
        max_ = self._q(Invoice)\
            .filter(extract('year', Invoice.emitted_at) == date.year)\
            .with_entities(func.max(Invoice.prog).label('max'))\
            .first().max
        max_ = max_ if max_ is not None else 0
        return max_ + 1
