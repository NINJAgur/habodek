"""
Module containing all the repositories for data interaction.
"""

from wpc.repository.crudrepo import CrudRepo
from wpc.repository.customer_repo import CustomerRepo
from wpc.repository.invoice_repo import InvoiceRepo
from wpc.repository.payment_repo import PaymentRepo
from wpc.repository.workrepo import WorkRepo
from wpc.repository.report_repo import ReportRepo

__all__ = [CrudRepo, CustomerRepo, InvoiceRepo, WorkRepo, PaymentRepo, ReportRepo]
