import click

from wpc.config.config import Configurator
from wpc.model.customer import Customer
from wpc.repository.customer_repo import CustomerRepo


configurator = Configurator()
cust_repo = CustomerRepo()


@click.command()
@click.option('-c', '--customer', help="The name or id of customer to set")
@click.option('--debug/--no-debug', help="Print debug stuff", default=None)
def config(customer, debug):
    """
    Configure some parameters and customize the application.
    """

    if customer is not None:
        _set_customer(customer)
    elif debug is not None:
        _set_debug(debug)
    else:
        _show_all()

    return


def _show_all():
    click.echo("Current configuration:")
    click.echo(f"\tcustomer = {configurator.customer}")
    click.echo(f"\toil_cost_litre = {configurator.oil_cost_litre}")
    click.echo(f"\tkm_litre = {configurator.km_litre}")


def _set_customer(c_name_or_id):

    if c_name_or_id.isdigit():
        customer = cust_repo.find(c_name_or_id)
    else:
        customers = cust_repo.getAll(Customer.name.ilike('%' + c_name_or_id + '%'))
        customer = next(iter(customers or []), None)  # get first of None.

    if customer is None:
        click.echo("No customer with id or name \"%s\" found." % c_name_or_id)
    else:
        configurator.customer = str(customer.id)
        click.echo("Customer \"%s\" set." % customer.name)


def _set_debug(is_debug):

    configurator.debug = is_debug
    click.echo("Debug set to %s." % is_debug)
