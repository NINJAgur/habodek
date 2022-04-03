import click
from datetime import datetime
from dateutil import parser
from tabulate import tabulate

from wpc.config.config import Configurator
from wpc.repository import PaymentRepo, InvoiceRepo
from wpc.model import Payment, Invoice


payment_repo = PaymentRepo()
invoice_repo = InvoiceRepo()
configurator = Configurator()


@click.group()
def payment():
    """
    Payment's commands group.
    """
    return


@click.command()
@click.option('--id', 'id_', type=int, help='The payment id.')
@click.option('--date', type=str, help='The payment date.')
def show(id_, date):
    """
    Show payments. If no filter specified all payments are shown.

    :param id_: The payment id.
    :param date: The payment date.
    """

    # TODO: implements filters.
    # Find results.
    # if id_ is not None:
    #     res = cli_repo.find(id_)
    #     if res is not None:
    #         clients = [res]
    # elif name is not None:
    #     clients = cli_repo.query()\
    #                 .filter(Customer.name.like("%"+name+"%"))\
    #                 .all()
    # else:
    #     clients = cli_repo.query().all()
    #
    # Print results.

    payments = payment_repo.getAll()

    if len(payments) <= 0:
        click.echo("No payments found.")
        return

    headers = ['Date', 'Gross', 'Tax', 'Net', 'Invoice', 'Note']
    rows = [
        [
            x.paid_at_str,
            x.gross,
            x.tax,
            x.net,
            x.invocie.reason if x.invoice is not None else '',
            x.note
        ]
        for x in payments]

    click.echo(tabulate(rows, headers))

    return


@click.command()
def add():
    """
    Insert a payment.
    """

    # read values.

    parserinfo = parser.parserinfo(dayfirst=True)
    paid_at = datetime.today()
    paid_at = parser.parse(click.prompt("Date", default=paid_at.strftime("%d/%m/%Y %H:%M")), parserinfo)

    net = click.prompt("Net", 0, type=float)  # TODO: add defaults from selected invoice.
    tax = click.prompt("Tax", 0, type=float)  # TODO: add defaults from selected invoice.
    gross = click.prompt("Gross", 0, type=float)  # TODO: add defaults from selected invoice.

    note = click.prompt("Note", default="")
    note = (note if note != "" else None)

    invoice = None  # TODO: select invoice, maybe before.

    # display summary.

    click.echo()
    click.echo("Summary:")
    click.echo()

    click.echo(tabulate(
        [[
            paid_at.strftime("%d/%m/%Y %H:%M"),
            str(gross),
            str(tax),
            str(net),
            note,
            ""  # TODO: invoice
        ]],
        ['Date', 'Gross', 'Tax', 'Net', 'Note', 'Invoice']))

    click.echo()

    if not click.confirm("Register payment?"):
        click.echo("Payment not registered.")
        return

    # register data.

    pay = Payment.create(configurator.customer, paid_at, gross, tax, net, invoice, note)
    payment_repo.create(pay)

    click.echo("Payment registered.")

    return


@click.command()
@click.argument('id_', type=int, required=True)
def remove(id_):
    """
    Remove an invoice.

    :param id_: The id of the payment.
    """

    x = payment_repo.find(id_)
    if x is not None:
        click.echo("Deleting payment #{} (gross %d, at %s)".format(x.gross, x.paid_at_str))
        if click.confirm("Are you sure?"):
            payment_repo.remove(x)
            click.echo("Deleted successful.")
        else:
            click.echo("Not deleted.")
    else:
        click.echo("No payment found.")
    return


@click.command()
@click.argument('id_', type=int, required=True)
def edit(id_):
    """
    Edit a payment.
    :param id_: The id of the payment.
    """

    raise NotImplementedError


payment.add_command(show)
payment.add_command(add)
payment.add_command(remove)
payment.add_command(edit)
