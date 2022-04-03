from sqlalchemy import func, extract

from wpc.model import Report
from wpc.repository.crudrepo import CrudRepo


class ReportRepo(CrudRepo):

    def __init__(self, clazz=Report):
        super().__init__(clazz)

    def _q(self, clazz=None):
        q = super(CrudRepo, self)._q(clazz)

        if clazz is None:
            q = q.filter(Report.customer_id == super()._configurator.customer)
            q = q.order_by(Report.emitted_at.asc(), Report.from_dt.asc())  # asc useful in CLI apps.

        return q

    def getAll(self, *criterion):
        return self._q().all()
