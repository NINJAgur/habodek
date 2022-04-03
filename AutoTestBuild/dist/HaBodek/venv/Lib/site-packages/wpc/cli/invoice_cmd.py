"""
Entry point for the command line interface.
"""
# import wpc

from calendar import monthrange
from datetime import date, datetime, time

import click
from dateutil import parser
from dateutil.relativedelta import relativedelta
from tabulate import tabulate


from wpc.config.config import Configurator
from wpc.doc.invoice import InvoiceTexDoc
from wpc.repository import WorkRepo, InvoiceRepo
from wpc.model.invoice import Invoice

work_repo = WorkRepo()
invoice_repo = InvoiceRepo()
configurator = Configurator()
doc = InvoiceTexDoc()


class InvoiceCli:
    pass


@click.group()
def invoice():
    """
    Invoice's commands group.
    """
    return


@click.command()
@click.option('--id', 'id_', type=int, help='The id of the invoice.')
@click.option('--date', type=str, help='The date of the invoice.')
def show(id_, date):
    """
    Show invoices. If no filter specified all invoices are shown.

    :param id_: The id of the invoice.
    :param date: The date of the invoice.
    """

    # TODO: implements filters.

    invoices = invoice_repo.getAll()

    if len(invoices) <= 0:
        click.echo("No invoices found.")
        return

    headers = ['Id', 'Date', 'Prog.', 'Gross', 'Tax', 'Net', 'Reason', 'Note']
    rows = [
        [
            str(x.id),
            x.emitted_at_str,
            x.prog,
            x.gross,
            x.tax,
            x.net,
            x.reason,
            x.note
        ]
        for x in invoices]

    click.echo(tabulate(rows, headers))

    return


@click.command()
@click.option('-e/--explicit', 'explicit', is_flag=True,
              help='Define all data for the invoice and show calculated as defaults.')
@click.option('--report', type=int, help='Generate an invoice based on report data.')
def add(explicit, report):
    """
    Insert an invoice.
    """

    parserinfo = parser.parserinfo(dayfirst=True)

    # defaults
    gross = 0
    tax = 0
    net = 0
    if report is not None:
        pass
        # TODO: get defaults from report.

    # read values
    date_ = datetime.today()
    if explicit:
        date_ = parser.parse(click.prompt("Date", default=date_.strftime('%d/%m/%Y')), parserinfo)
    date_ = date_.date()

    prog = click.prompt("Progressive", default=invoice_repo.getNextProg(date_))
    net = click.prompt("Net", net, type=float)
    tax = click.prompt("Tax", tax, type=float)
    gross = click.prompt("Gross", gross, type=float)
    reason = click.prompt("Reason", default="assistenza presso Vostri clienti")
    note = click.prompt("Note", default="")

    click.echo()
    click.echo("Summary:")
    click.echo()

    click.echo(tabulate(
        [[
            date_.strftime("%d/%m/%Y"),
            str(prog),
            str(gross),
            str(tax),
            str(net),
            reason,
            note
        ]],
        ['Date', 'Prog', 'Gross', 'Tax', 'Net', 'Reason', 'Note']))

    click.echo()

    if not click.confirm("Emit invoice?"):
        click.echo("Invoice not emitted.")
        return

    inv = Invoice.create(date_, prog, gross, tax, net, reason, note, configurator.customer)
    invoice_repo.create(inv)

    click.echo("Invoice registered.")

    if click.confirm("Generate invoice file?"):
        doc.set_invoice_from(inv)
        doc.date = date_

        ret = doc.generate()
        click.echo()

        if ret is False:
            click.echo("Error occurred: could not generate invoice file.")
        else:
            click.echo("Invoice emitted. Locate it at %s" % ret)

    return


@click.command()
@click.argument('id_', type=int, required=True)
def remove(id_):
    """
    Remove an invoice.

    :param id_: The id of the invoice.
    """

    x = invoice_repo.find(id_)
    if x is not None:
        click.echo("Deleting invoice #{} (from %s to %s)".format(x.from_dt_str, x.to_dt_str))
        if click.confirm("Are you sure?"):
            invoice_repo.remove(x)
            click.echo("Deleted successful.")
        else:
            click.echo("Not deleted.")
    else:
        click.echo("No invoice found.")

    return


@click.command()
@click.argument('id_', type=int, required=True)
def edit(id_):
    """
    Edit an invoice.
    :param id_: The id of the invoice.
    """

    raise NotImplementedError


invoice.add_command(show)
invoice.add_command(add)
invoice.add_command(remove)
invoice.add_command(edit)
