import click

from wpc.model.customer import Customer
from wpc.repository.repo import Repo


cli_repo = Repo(Customer)


@click.group()
def customer():
    """
    Customer's commands group.
    """
    return


@click.command()
@click.option('--id', 'id_', type=int, help='The id of the customer.')
@click.option('--name', type=str, help='The name of the customer.')
def show(id_, name):
    """
    Show customers.

    :param id_: The id of the customer.
    :param name: The name of the customer.
    """

    customers = []

    # Find results.
    if id_ is not None:
        res = cli_repo.find(id_)
        if res is not None:
            customers = [res]
    elif name is not None:
        customers = cli_repo.query()\
                    .filter(Customer.name.like("%"+name+"%"))\
                    .all()
    else:
        customers = cli_repo.query().all()

    # Print results.
    if len(customers) > 0:
        click.echo("Customers: ")
        [click.echo(" {}, {}".format(x.id, x.name)) for x in customers]
    else:
        click.echo("No customers found.")

    return


@click.command()
def add():
    """
    Insert a customer into the system.
    """

    name = click.prompt("Name", type=str)

    if name is None:
        click.echo("Name cannot be empty")
        return

    new_customer = Customer(name=name)

    cli_repo.create(new_customer)

    click.echo("Added %s" % name)

    return


@click.command()
@click.argument('id_', type=int, required=True)
def remove(id_):
    """
    Remove a customer, i.e., marks it as "obsolete". This does not remove the customer effectively
    from the system because the data related to it.

    :param id_: The id of the customer.
    """
    # TODO: implement obsolete customer.

    c = cli_repo.find(id_)
    if c is None:
        click.echo("Customer with id %s not found." % id_)
        return

    if click.confirm("Are you sure?"):
        cli_repo.remove(c)
        click.echo("Deleted successful.")
    else:
        click.echo("Not deleted.")

    return


@click.command()
@click.argument('id_', type=int, required=True)
def edit(id_):
    """
    Edit a customer.
    :param id_: The id of the customer.
    """

    c = cli_repo.find(id_)
    if c is None:
        click.echo("Customer with id %s not found." % id_)
        return

    name = click.prompt("Name?", default=c.name, type=str)

    c.name = name
    cli_repo.update(c)

    click.echo("Success.")

    return


customer.add_command(show)
customer.add_command(add)
customer.add_command(remove)
customer.add_command(edit)
