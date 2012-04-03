'''
Module to provide Postgres compatibility to salt.

In order to connect to Postgres, certain configuration is required
in /etc/salt/minion on the relevant minions. Some sample configs
might look like::

    postgres.host: 'localhost'
    postgres.port: '5432'
    postgres.user: 'postgres'
    postgres.pass: ''
    postgres.db: 'postgres'

'''

import logging
from salt.utils import check_or_die
from salt.exceptions import CommandNotFoundError


log = logging.getLogger(__name__)
__opts__ = {}


def __virtual__():
    """
    only load this module if the psql bin exists
    """
    try:
        check_or_die('psql')
        return 'postgres'
    except CommandNotFoundError:
        return False


def version():
    '''
    Return the version of a Postgres server using the output
    from the ``psql --version`` cmd.

    CLI Example::

        salt '*' postgres.version
    '''
    version_line =  __salt__['cmd.run']('psql --version').split("\n")[0]
    name = version_line.split(" ")[1]
    ver = version_line.split(" ")[2]
    return "%s %s" % (name, ver)


'''
Database related actions
'''


def db_list(user=None, host=None, port=None):
    '''
    Return a list of databases of a Postgres server using the output
    from the ``psql -l`` query.

    CLI Example::

        salt '*' postgres.db_list
    '''
    if not user:
        user = __opts__['postgres.user']
    if not host:
        host = __opts__['postgres.host']
    if not port:
        port = __opts__['postgres.port']

    ret = []
    cmd = "psql -l -h {host} -U {user} -p {port}".format(
            host=host, user=user, port=port)

    lines = [x for x in __salt__['cmd.run'](cmd).split("\n") if len(x.split("|")) == 6]
    header = [x.strip() for x in lines[0].split("|")]
    for line in lines[1:]:
        line = [x.strip() for x in line.split("|")]
        if not line[0] == "":
            ret.append(zip(header[:-1], line[:-1]))

    return ret


def db_exists(name, user=None, host=None, port=None):
    '''
    Checks if a database exists on the Postgres server.

    CLI Example::

        salt '*' postgres.db_exists 'dbname'
    '''
    databases = __salt__['postgres.db_list'](user=user, host=host, port=port)
    for db in databases:
        if name == dict(db).get('Name'):
            return True

    return False


def db_dump(name,
            user=None,
            host=None,
            port=None,
            file_name=None,
            format=None,
            compress=None,
            data_only=False,
            blobs=False,
            clean=False,
            create=False,
            encoding=None,
            schema=None,
            exclude_schema=None,
            oids=False,
            no_owner=False,
            schema_only=False,
            superuser=None,
            exclude_table=None,
            table=None,
            no_privileges=False,
            binary_upgrade=False,
            column_inserts=False,
            disable_triggers=False,
            inserts=False,
            no_security_labels=False,
            no_tablespaces=False,
            no_unlogged_table_data=False,
            quote_all_identifiers=False,
            serializable_deferrable=False,
            use_set_session_authorization=False,
            ):

    # check if db exists
    if not db_exists(name, user, host, port):
        log.info("DB '{0}' does not exist".format(name,))
        return False

    if not user:
        user = __opts__['postgres.user']
    if not host:
        host = __opts__['postgres.host']
    if not port:
        port = __opts__['postgres.port']

    cmd = 'pg_dump {0}'.format(name)
    print cmd
    if file_name:
        cmd = "{0} -f {1}".format(cmd, file_name)

    if format:
        cmd = "{0} -F {1}".format(cmd, format)

    if compress:
        try:
            int(compress)
        except ValueError:
            log.error('Compress value must be an integer')
            return False

        if int(compress) > 9 or int(compress) < 0:
            log.error('Compress value must be between 0 and 9')
            return False

        cmd = "{0} -Z {1}".format(cmd, compress)

    if data_only:
        cmd = "{0} -a".format(cmd)

    if blobs:
        cmd = "{0} -b".format(cmd)

    if clean:
        cmd = "{0} -c".format(cmd)

    if create:
        cmd = "{0} -C".format(cmd)

    if encoding:
        cmd = "{0} -E {1}".format(cmd, encoding)

    if schema:
        cmd = "{0} -n {1}".format(cmd, schema)

    if exclude_schema:
        cmd = "{0} -N {1}".format(cmd, exclude_schema)

    if oids:
        cmd = "{0} -o".format(cmd)

    if no_owner:
        cmd = "{0} -O {1}".format(cmd)

    if schema_only:
        cmd = "{0} -s {1}".format(cmd)

    if superuser:
        cmd = "{0} -S {1}".format(cmd, superuser)

    if exclude_table:
        cmd = "{0} -T {1}".format(cmd, exclude_table)

    if table:
        cmd = "{0} -t {1}".format(cmd, table)

    if no_privileges:
        cmd = "{0} -x {1}".format(cmd)

    if binary_upgrade:
        cmd = "{0} --binary-upgrade".format(cmd)

    if column_inserts:
        cmd = "{0} --column-inserts".format(cmd)

    if disable_triggers:
        cmd = "{0} --disable-triggers".format(cmd)

    if inserts:
        cmd = "{0} --inserts".format(cmd)

    if no_security_labels:
        cmd = "{0} --no-security-labels".format(cmd)

    if no_tablespaces:
        cmd = "{0} --no-tablespaces".format(cmd)

    if no_unlogged_table_data:
        cmd = "{0} --no-unlogged-table-data".format(cmd)

    if quote_all_identifiers:
        cmd = "{0} --quote-all-identifiers".format(cmd)

    if serializable_deferrable:
        cmd = "{0} --serializable-deferrable".format(cmd)

    if use_set_session_authorization:
        cmd = "{0} --use-set-session-authorization".format(cmd)

    __salt__['cmd.run'](cmd)


def db_create(name,
              user=None,
              host=None,
              port=None,
              tablespace=None,
              encoding=None,
              local=None,
              lc_collate=None,
              lc_ctype=None,
              owner=None,
              template=None):
    '''
    Adds a databases to the Postgres server.

    CLI Example::

        salt '*' postgres.db_create 'dbname'

        salt '*' postgres.db_create 'dbname' template=template_postgis

    '''
    # check if db exists
    if db_exists(name, user, host, port):
        log.info("DB '{0}' already exists".format(name,))
        return False

    cmd = 'createdb {0}'.format(name)

    if tablespace:
        cmd = "{0} -D {1}".format(cmd, tablespace)

    if encoding:
        cmd = "{0} -E {1}".format(cmd, encoding)

    if local:
        cmd = "{0} -l {1}".format(cmd, local)

    if lc_collate:
        cmd = "{0} --lc-collate {1}".format(cmd, lc_collate)

    if lc_ctype:
        cmd = "{0} --lc-ctype {1}".format(cmd, lc_ctype)

    if owner:
        cmd = "{0} -O {1}".format(cmd, owner)

    if template:
        if db_exists(template, user, host, port):
            cmd = "{cmd} -T {template}".format(cmd=cmd, template=template)
        else:
            log.info("template '{0}' does not exist.".format(template, ))
            return False

    __salt__['cmd.run'](cmd)

    if db_exists(name, user, host, port):
        return True
    else:
        log.info("Failed to create DB '{0}'".format(name,))
        return False


def db_remove(name, user=None, host=None, port=None):
    '''
    Removes a databases from the Postgres server.

    CLI Example::

        salt '*' postgres.db_remove 'dbname'
    '''
    # check if db exists
    if not db_exists(name):
        log.info("DB '{0}' does not exist".format(name,))
        return False

    # db doesnt exist, proceed
    cmd = 'dropdb {0}'.format(name)
    __salt__['cmd.run'](cmd)
    if not db_exists(name, user, host, port):
        return True
    else:
        log.info("Failed to delete DB '{0}'.".format(name, ))
        return False

'''
User related actions
'''


def user_create(username,
                user=None,
                host=None,
                port=None,
                createdb=False,
                createuser=False,
                encrypted=False,
                password=None):
    '''
    Creates a Postgres user.

    CLI Examples::

        salt '*' postgres.user_create 'username' user='user' host='hostname' port='port' password='password'
    '''
    if not user:
        user = __opts__['postgres.user']
    if not host:
        host = __opts__['postgres.host']
    if not port:
        port = __opts__['postgres.port']

    sub_cmd = "CREATE USER {0} WITH".format(username, )
    if password:
        sub_cmd = "{0} PASSWORD '{1}'".format(sub_cmd, password)
    if createdb:
        sub_cmd = "{0} CREATEDB".format(sub_cmd, )
    if createuser:
        sub_cmd = "{0} CREATEUSER".format(sub_cmd, )
    if encrypted:
        sub_cmd = "{0} ENCRYPTED".format(sub_cmd, )

    if sub_cmd.endswith("WITH"):
        sub_cmd = sub_cmd.replace(" WITH", "")

    cmd = 'psql -h {host} -U {user} -p {port} -c "{sub_cmd}"'.format(
        host=host, user=user, port=port, sub_cmd=sub_cmd)
    return __salt__['cmd.run'](cmd)



