import os
import re
from pathlib import Path

from wpc.doc.doc_tex import DocTex
from datetime import datetime

class RegistryTexDoc(DocTex):

    date_file_out = datetime.today()

    DATE = 'DATE'
    FROM_DT = 'FROMDT'
    TO_DT = 'TODT'
    TABLEROWS = 'TABLEROWS'

    GROSS = 'GROSS'
    TAX = 'TAX'
    NET = 'NET'

    HOURS = 'HOURS'
    HOURS_PROD = 'HOURSPROD'
    HOURS_NON_PROD = 'HOURSNONPROD'

    # dict for data to replace in template.
    _data = {

    }

    @property
    def date_file(self):
        return self.date_file_out.strftime('%Y%m%d-%H%M%S')

    @date_file.setter
    def date_file(self, value):
        self.date_file_out = value

    @property
    def file_path(self):
        home_path = str(Path.home())
        out_dir = os.path.join(home_path, 'wpc-reports')
        return out_dir

    @property
    def file_name(self):
        return 'report_' + self.date_file

    def template(self):
        return os.path.join(os.getcwd(), 'res', 'templates', 'tex', 'default', 'registry', 'registry.tex')

    def replace(self, file_data):
        # doc
        file_data = super()._replace_whole(self.DATE, self.date, file_data)
        file_data = super()._replace_whole(self.FROM_DT, self.from_dt, file_data)
        file_data = super()._replace_whole(self.TO_DT, self.to_dt, file_data)
        file_data = super()._replace_whole(self.TABLEROWS, self.registry, file_data)
        # profit
        file_data = super()._replace_whole(self.GROSS, self.gross, file_data)
        file_data = super()._replace_whole(self.TAX, self.tax, file_data)
        file_data = super()._replace_whole(self.NET, self.net, file_data)
        # hours
        file_data = super()._replace_whole(self.HOURS, self.hours, file_data)
        file_data = super()._replace_whole(self.HOURS_PROD, self.hours_prod, file_data)
        file_data = super()._replace_whole(self.HOURS_NON_PROD, self.hours_non_prod, file_data)

        return file_data

    @property
    def date(self):
        return self._data[self.DATE].strftime('%d/%m/%Y %H:%M')

    @date.setter
    def date(self, value):
        self._data[self.DATE] = value

    @property
    def from_dt(self):
        return self._data[self.FROM_DT].strftime('%d/%m/%Y')

    @from_dt.setter
    def from_dt(self, value):
        self._data[self.FROM_DT] = value

    @property
    def to_dt(self):
        return self._data[self.TO_DT].strftime('%d/%m/%Y')

    @to_dt.setter
    def to_dt(self, value):
        self._data[self.TO_DT] = value

    @property
    def registry(self):
        return self._data[self.TABLEROWS]

    @registry.setter
    def registry(self, value):
        tablerows = ''
        i = 0
        for x in value:
            i += 1
            tablerows += x.date.strftime('%d/%m/%Y') + ' & '
            tablerows += x.from_dt_str + ' & '
            tablerows += x.to_dt_str + ' & '
            tablerows += str(round(x.hours.total_seconds() / 60.0 / 60.0, 2)) + ' & '
            tablerows += str(x.km) + ' & '
            tablerows += ('SI' if x.prod is True else 'NO') + ' & '
            tablerows += x.registry + (re.escape('\\\\')+' \n ' if i < len(value) else '')

        self._data[self.TABLEROWS] = tablerows

    @property
    def gross(self):
        return str(round(self._data[self.GROSS], 2))

    @gross.setter
    def gross(self, value):
        self._data[self.GROSS] = value

    @property
    def tax(self):
        return str(round(self._data[self.TAX], 2))

    @tax.setter
    def tax(self, value):
        self._data[self.TAX] = value

    @property
    def net(self):
        return str(round(self._data[self.NET], 2))

    @net.setter
    def net(self, value):
        self._data[self.NET] = value

    @property
    def hours(self):
        return str(round(self._data[self.HOURS],2))

    @hours.setter
    def hours(self, value):
        self._data[self.HOURS] = value

    @property
    def hours_prod(self):
        return str(round(self._data[self.HOURS_PROD],2))

    @hours_prod.setter
    def hours_prod(self, value):
        self._data[self.HOURS_PROD] = value

    @property
    def hours_non_prod(self):
        return str(round(self._data[self.HOURS_NON_PROD],2))

    @hours_non_prod.setter
    def hours_non_prod(self, value):
        self._data[self.HOURS_NON_PROD] = value
