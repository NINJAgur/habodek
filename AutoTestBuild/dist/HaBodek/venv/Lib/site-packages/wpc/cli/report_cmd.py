from calendar import monthrange
from datetime import date, datetime

import click
from dateutil import parser
from dateutil.relativedelta import relativedelta
from tabulate import tabulate

from wpc.config.config import Configurator
from wpc.doc.registry import RegistryTexDoc
from wpc.model.report import Report
from wpc.repository import WorkRepo, ReportRepo

work_repo = WorkRepo()
report_repo = ReportRepo()
configurator = Configurator()


@click.group()
def report():
    """
    Report's commands group.
    """
    return


@click.command()
@click.option('--id', 'id_', type=int, help='The id of the report.')
@click.option('--date', type=str, help='The date of the report.')
def show(id_, date):
    """
    Show reports. If no filter specified all reports are shown.

    :param id_: The id of the report.
    :param date: The date of the report.
    """

    # TODO: implements filters.

    reports = report_repo.getAll()

    if len(reports) <= 0:
        click.echo("No reports found.")
        return

    headers = ['Id', 'Date', 'From', 'To', 'Gross', 'Tot. Hours', 'P. Hours', 'Non P. Hours']
    rows = [
        [
            str(x.id),
            x.emitted_at.strftime("%d/%m/%Y"),
            x.from_dt.strftime("%d/%m/%Y"),
            x.to_dt.strftime("%d/%m/%Y"),
            x.gross,
            x.hours,
            x.hours_prod,
            x.hours_non_prod
        ]
        for x in reports]

    click.echo(tabulate(rows, headers))

    return


@click.command()
@click.option('-e/--explicit', 'explicit', is_flag=True,
              help='Define all data for the report and show calculated as defaults.')
def add(explicit):
    """
    Insert a report.
    """

    parserinfo = parser.parserinfo(dayfirst=True)

    # emitted at
    date_ = datetime.today()
    if explicit:
        date_ = parser.parse(click.prompt("Date", default=date_.strftime('%d/%m/%Y %H:%M')), parserinfo)

    # calculate begin and end of a month ago.
    a_month_ago = date.today()
    a_month_ago = date(a_month_ago.year, a_month_ago.month, 1)
    a_month_ago = a_month_ago + relativedelta(months=-1)
    # defaults
    begin_default = datetime(a_month_ago.year, a_month_ago.month, 1)
    end_default = datetime(a_month_ago.year, a_month_ago.month, monthrange(a_month_ago.year, a_month_ago.month)[1])
    # read begin/end
    begin = parser.parse(click.prompt("From", default=begin_default.strftime("%d/%m/%Y")), parserinfo)
    end = parser.parse(click.prompt("To", default=end_default.strftime('%d/%m/%Y')), parserinfo)
    # only date
    begin = begin.date()
    end = end.date()
    # validate
    if begin > end:
        raise ValueError("From date cannot be greater than end date")

    gross = work_repo.getTotalGrossBetween(begin, end)
    tax = work_repo.getTotalTaxBetween(begin, end)
    net = work_repo.getTotalNetBetween(begin, end)

    hours_tot = work_repo.getHoursBetween(begin, end).total_seconds() / 60 / 60
    hours_p = work_repo.getHoursProdBetween(begin, end).total_seconds() / 60 / 60
    hours_np = work_repo.getHoursNonProdBetween(begin, end).total_seconds() / 60 / 60

    reason = click.prompt("Reason", default="")
    reason = (reason if reason != "" else None)

    note = click.prompt("Note", default="")
    note = (note if note != "" else None)

    if explicit:
        gross = click.prompt("Gross", gross, type=float)
        net = click.prompt("Net", net, type=float)
        tax = click.prompt("Tax", tax, type=float)
        hours_tot = click.prompt("Total hours", hours_tot, type=float)
        hours_p = click.prompt("Production hours", hours_p, type=float)
        hours_np = click.prompt("Non production hours", hours_np, type=float)

    # display results.

    click.echo()
    click.echo("Summary:")
    click.echo()

    click.echo(tabulate(
        [[
            begin.strftime("%d/%m/%Y"),
            end.strftime("%d/%m/%Y"),
            str(gross),
            str(tax),
            str(net),
            str(hours_tot),
            str(hours_p),
            str(hours_np),
        ]],
        ['Form', 'To', 'Tot. Hours', 'Gross', 'Tax', 'Net', 'P. Hours', 'Non P. Hours']))

    click.echo()

    if not click.confirm("Emit report?"):
        click.echo("Report not emitted.")
        return

    r = Report.create(date_, begin, end, gross, tax, net, hours_np, hours_p, hours_tot, reason, note, configurator.customer)
    report_repo.create(r)

    click.echo("Report registered.")

    return


@click.command()
@click.argument('id_', type=int, required=True)
def remove(id_):
    """
    Remove a report.

    :param id_: The id of the report.
    """

    x = report_repo.find(id_)
    if x is not None:
        click.echo("Deleting report #{}".format(x.emitted_at_str))
        if click.confirm("Are you sure?"):
            report_repo.remove(x)
            click.echo("Deleted successful.")
        else:
            click.echo("Not deleted.")
    else:
        click.echo("No report found.")

    return


@click.command()
@click.argument('id_', type=int, required=True)
def edit(id_):
    """
    Edit a report.
    :param id_: The id of the report.
    """

    raise NotImplementedError


@click.command()
@click.argument('id_', type=int, required=True)
def doc(id_):
    """
    Generate a report document.
    :param id_: The id of the report.
    """

    doc = RegistryTexDoc()

    x = report_repo.find(id_)
    if x is not None:
        works = work_repo.getBetweenStart(x.from_dt, x.to_dt)

        doc.date = x.emitted_at
        doc.from_dt = x.from_dt
        doc.to_dt = x.to_dt
        doc.registry = works
        doc.gross = x.gross
        doc.tax = x.tax
        doc.net = x.net
        doc.hours = x.hours
        doc.hours_prod = x.hours_prod
        doc.hours_non_prod = x.hours_non_prod

        ret = doc.generate()
        click.echo()

        if ret is False:
            click.echo("Error occurred: could not generate invoice file.")
        else:
            click.echo("Invoice emitted. Locate it at %s" % ret)

        click.echo("Report emitted.")
    else:
        click.echo("No report found.")

    return


report.add_command(show)
report.add_command(add)
report.add_command(remove)
report.add_command(edit)
report.add_command(doc)
