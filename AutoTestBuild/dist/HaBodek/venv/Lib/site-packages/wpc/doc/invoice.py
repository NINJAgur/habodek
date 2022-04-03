import os
from pathlib import Path

from num2words import num2words
from wpc.doc import DocTex


class InvoiceTexDoc(DocTex):

    def __init__(self) -> None:
        super().__init__()
        self.gross = 0
        self.gross_words = 0
        self.tax = 0
        self.net = 0
        self.date = None
        self.reason = None
        self.progressive = 0

    # const to replace in template.

    INVOICE_DOC_NAME = 'INVOICEDOCUMENTNAME'
    OPENING_GRADE = 'OPENINGGRADE'

    GROSS = 'GROSS'
    TAX = 'TAX'
    NET = 'NET'
    GROSS_WORDS = 'GROSSWORDS'
    REASON = 'INVOICEREASON'
    PROGRESSIVE = 'PROGRESSIVE'
    DATE = 'DATE'

    RECIPIENT_NAME = 'RECIPIENTNAME'
    RECIPIENT_STREET = 'RECIPIENTSTREET'
    RECIPIENT_STREET_NO = 'RECIPIENTSTREETNO'
    RECIPIENT_ZIP = 'RECIPIENTZIP'
    RECIPIENT_CITY = 'RECIPIENTCITY'
    RECIPIENT_PROV = 'RECIPIENTPROV'
    RECIPIENT_COUNTRY = 'RECIPIENTCOUNTRY'
    RECIPIENT_VAT = 'RECIPIENTVAT'
    RECIPIENT_FISCAL_CODE = 'RECIPIENTFISCODE'
    RECIPIENT_FISCAL_NAME = 'RECIPIENTFISNAME'

    # dict for data to replace in template.
    _data = {
        GROSS: 0,
        TAX: 0,
        NET: 0,
        GROSS_WORDS: 'zero/00',
        REASON: None,
        PROGRESSIVE: 0,
        DATE: None,

        # TODO: take this defaults from configs or even from database.
        INVOICE_DOC_NAME: 'Notula',
        OPENING_GRADE: 'Spett.le',

        # TODO: take this defaults from database!
        RECIPIENT_FISCAL_NAME: 'Nexio Informatica S.r.l Unipersonale',
        RECIPIENT_STREET: 'Via G. Marconi',
        RECIPIENT_STREET_NO: '50',
        RECIPIENT_ZIP: '25050',
        RECIPIENT_CITY: 'Temù',
        RECIPIENT_PROV: 'BS',
        RECIPIENT_COUNTRY: 'Italia',
        RECIPIENT_VAT: 'IT 04030320982',
        RECIPIENT_FISCAL_CODE: 'IT 04030320982',
        RECIPIENT_NAME: 'Antonio Toselli',
    }

    def template(self):
        return os.path.join(os.getcwd(), 'res', 'templates', 'tex', 'default', 'invoice', 'invoice.tex')

    @property
    def file_path(self):
        home_path = str(Path.home())
        out_dir = os.path.join(home_path, 'wpc-invoices')
        return out_dir

    @property
    def file_name(self):
        return 'invoice_' + self.date_file

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
    def gross_words(self):
        return self._data[self.GROSS_WORDS]

    @gross_words.setter
    def gross_words(self, value):
        self._data[self.GROSS_WORDS] = num2words(int(round(float(value), 0)), lang='it')

    @property
    def reason(self):
        return self._data[self.REASON]

    @reason.setter
    def reason(self, value):
        self._data[self.REASON] = value

    @property
    def progressive(self):
        return str(self._data[self.PROGRESSIVE])

    @progressive.setter
    def progressive(self, value):
        self._data[self.PROGRESSIVE] = value

    @property
    def date(self):
        return self._data[self.DATE].strftime('%d/%m/%Y')

    @date.setter
    def date(self, value):
        self._data[self.DATE] = value

    # invoice doc name
    @property
    def invoice_doc_name(self):
        return self._data[self.INVOICE_DOC_NAME]

    @invoice_doc_name.setter
    def invoice_doc_name(self, value):
        self._data[self.INVOICE_DOC_NAME] = value

    # recipient name
    @property
    def recipient_name(self):
        return self._data[self.RECIPIENT_NAME]

    @recipient_name.setter
    def recipient_name(self, value):
        self._data[self.RECIPIENT_NAME] = value

    # recipient street
    @property
    def recipient_street(self):
        return self._data[self.RECIPIENT_STREET]

    @recipient_street.setter
    def recipient_street(self, value):
        self._data[self.RECIPIENT_STREET] = value

    # recipient street number.
    @property
    def recipient_street_number(self):
        return self._data[self.RECIPIENT_STREET_NO]

    @recipient_street_number.setter
    def recipient_street_number(self, value):
        self._data[self.RECIPIENT_STREET_NO] = value

    # recipient zip
    @property
    def recipient_zip(self):
        return self._data[self.RECIPIENT_ZIP]

    @recipient_zip.setter
    def recipient_zip(self, value):
        self._data[self.RECIPIENT_ZIP] = value

    # recipient city
    @property
    def recipient_city(self):
        return self._data[self.RECIPIENT_CITY]

    @recipient_city.setter
    def recipient_city(self, value):
        self._data[self.RECIPIENT_CITY] = value

    # recipient prov
    @property
    def recipient_prov(self):
        return self._data[self.RECIPIENT_PROV]

    @recipient_prov.setter
    def recipient_prov(self, value):
        self._data[self.RECIPIENT_PROV] = value

    # recipient country
    @property
    def recipient_country(self):
        return self._data[self.RECIPIENT_COUNTRY]

    @recipient_country.setter
    def recipient_country(self, value):
        self._data[self.RECIPIENT_COUNTRY] = value

    # recipient vat
    @property
    def recipient_vat(self):
        return self._data[self.RECIPIENT_VAT]

    @recipient_vat.setter
    def recipient_vat(self, value):
        self._data[self.RECIPIENT_VAT] = value

    # recipient fis code
    @property
    def recipient_fiscal_code(self):
        return self._data[self.RECIPIENT_FISCAL_CODE]

    @recipient_fiscal_code.setter
    def recipient_fiscal_code(self, value):
        self._data[self.RECIPIENT_FISCAL_CODE] = value

    # recipient fiscal name
    @property
    def recipient_fiscal_name(self):
        return self._data[self.RECIPIENT_FISCAL_NAME]

    @recipient_fiscal_name.setter
    def recipient_fiscal_name(self, value):
        self._data[self.RECIPIENT_FISCAL_NAME] = value

    # opening grade
    @property
    def opening_grade(self):
        return self._data[self.OPENING_GRADE]

    @opening_grade.setter
    def opening_grade(self, value):
        self._data[self.OPENING_GRADE] = value

    def set_invoice(self, gross, tax, net, datetime, reason, prog):
        self.gross = gross
        self.gross_words = gross
        self.tax = tax
        self.net = net
        self.date = datetime
        self.reason = reason
        self.progressive = prog

    def set_invoice_from(self, invoice):
        self.set_invoice(invoice.gross, invoice.tax, invoice.net, invoice.emitted_at, invoice.reason, invoice.prog)

    @property
    def date_file(self):
        return self._data[self.DATE].strftime('%Y%m%d-%H%M%S')

    def replace(self, file_data):

        # doc
        file_data = super()._replace_whole(self.INVOICE_DOC_NAME, self.invoice_doc_name, file_data)
        file_data = super()._replace_whole(self.OPENING_GRADE, self.opening_grade, file_data)

        # recipient
        file_data = super()._replace_whole(self.RECIPIENT_FISCAL_NAME, self.recipient_fiscal_name, file_data)
        file_data = super()._replace_whole(self.RECIPIENT_STREET, self.recipient_street, file_data)
        file_data = super()._replace_whole(self.RECIPIENT_STREET_NO, self.recipient_street_number, file_data)
        file_data = super()._replace_whole(self.RECIPIENT_ZIP, self.recipient_zip, file_data)
        file_data = super()._replace_whole(self.RECIPIENT_CITY, self.recipient_city, file_data)
        file_data = super()._replace_whole(self.RECIPIENT_PROV, self.recipient_prov, file_data)
        file_data = super()._replace_whole(self.RECIPIENT_COUNTRY, self.recipient_country, file_data)
        file_data = super()._replace_whole(self.RECIPIENT_VAT, self.recipient_vat, file_data)
        file_data = super()._replace_whole(self.RECIPIENT_FISCAL_CODE, self.recipient_fiscal_code, file_data)

        # data
        file_data = super()._replace_whole(self.RECIPIENT_NAME, self.recipient_name, file_data)
        file_data = super()._replace_whole(self.GROSS, self.gross, file_data)
        file_data = super()._replace_whole(self.TAX, self.tax, file_data)
        file_data = super()._replace_whole(self.NET, self.net, file_data)
        file_data = super()._replace_whole(self.REASON, self.reason, file_data)
        file_data = super()._replace_whole(self.PROGRESSIVE, self.progressive, file_data)
        file_data = super()._replace_whole(self.DATE, self.date, file_data)
        file_data = super()._replace_whole(self.GROSS_WORDS, self.gross_words, file_data)

        return file_data
