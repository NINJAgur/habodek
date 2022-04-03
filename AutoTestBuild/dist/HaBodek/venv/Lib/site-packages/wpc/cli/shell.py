import click

from wpc.cli.config_cmd import config
from wpc.cli.customer_cmd import customer
from wpc.cli.work_cmd import work
from wpc.cli.report_cmd import report
from wpc.cli.invoice_cmd import invoice
from wpc.cli.payment_cmd import payment


@click.group()
def cli_commands():
    """
    Command line interface for wpc.


    Luca Parolari <luca.parolari23@gmail.com>

    Work Pay Calculator @ 2018-2019
    """
    pass


cli_commands.add_command(config)
cli_commands.add_command(customer)
cli_commands.add_command(work)
cli_commands.add_command(report)
cli_commands.add_command(invoice)
cli_commands.add_command(payment)



