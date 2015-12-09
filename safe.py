#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Safe
  a commandline password manager using AES encryption, written in python.

:: author   Erick Daniszewski
:: date     05 December 2015
"""
import json
import getpass
import argparse
import struct

from os import mkdir, remove
from os.path import join as join_path
from os.path import isdir, isfile, expanduser, getsize
from random import randint

from Crypto.Cipher import AES
from hashlib import md5, sha256

# Safe Constants
SAFE_ROOT   = join_path(expanduser('~'), '.safe')
SAFE_CONFIG = join_path(SAFE_ROOT, 'config.json')
SAFE_META   = join_path(SAFE_ROOT, 'meta.json')
SAFES_PATH  = join_path(SAFE_ROOT, 'safes')
ALL_SAFES   = '__all'

# Define the argument parser
parser = argparse.ArgumentParser(description='Safe :: A minimalistic commandline password manager')

parser.add_argument('-i', '--init', nargs='*', help='initialize a new safe.')
parser.add_argument('-o', '--open', nargs='*', help='open the specified safe. this is needed for both read and write operations.')
parser.add_argument('-c', '--close', nargs='?', const=ALL_SAFES, help='close the specified safe. if no safe is specified, all open safes '
                                                                      'are closed. safes will not close automatically - it is up to the user '
                                                                      'to close their safes.')
parser.add_argument('-a', '--add', nargs='*', help='add a new entry to the safe. add can take 0..3 arguments, where the user will be prompted '
                                                   'to fill in any missing arguments. the arguments are positional. the order is as follows: '
                                                   '(1) entry name, (2) username/id, (3) password')
parser.add_argument('-d', '--delete', help='remove an entry from the safe.')
parser.add_argument('--default', help='set the default safe. the default safe is used by commands, such as open, to determine which safe '
                                      'to use if none is specified.')
parser.add_argument('-D', '--delete_safe', help='remove an existing safe. this removes the safe and all of its entries permanently.')
parser.add_argument('-m', '--modify', nargs='?', const=False, help='modify an existing entry for the open safe. this can be used '
                                                                   'to change username/password information.')
parser.add_argument('-M', '--modify_safe', nargs='*', help='modify an existing safe. this should be used if one wants to change the '
                                                           'master password to a safe, without losing the safe contents.')
parser.add_argument('-u', '--username', action='store_true', help='a flag which, when present, will include username info in an entry\'s output.')
parser.add_argument('-w', '--whole', action='store_true', help='a flag which, when present, will show the full entry (all data).')
parser.add_argument('-e', '--entries', action='store_true', help='show all entries (by name) which exist in the open safe.')
parser.add_argument('-s', '--safes', action='store_true', help='show all safes (by name) which exist.')
parser.add_argument('-f', '--force', action='store_true', help='force an action. typically, this is used with deletes in order to suppress '
                                                               'the verification prompt.')
parser.add_argument('-v', '--verbose', action='store_true', help='a flag which toggles the verbosity of safe. if set to true, additional messages '
                                                                 'will be output, such as verification of action success.')
parser.add_argument('entry', nargs='?', help='the name of the entry in the safe for which the stored information will be retrieved.')


# Define 'clean' state of configuration and metadata files
default_cfg  = dict(default_safe=None, verbose=False)
default_meta = dict(safes=[])

# By default, set the verbosity to False. This will get updated based on the value
# stored in the Safe configuration file at runtime.
is_verbose = False


# ========================================================================
# Convenience Methods
# ========================================================================

def get_meta():
    """ Get the Safe metadata from the metadata file.

    :return: A dictionary containing the metadata stored in the metadata file.
    :rtype: dict
    """
    with open(SAFE_META, 'r') as f:
        meta = json.load(f)
    return meta


def set_meta(data):
    """ Write a metadata to the metadata file.

    This will overwrite any existing metadata which may exist in the file.

    :param data: The metadata to write to the metadata file.
    :type data: dict
    :return: None
    """
    with open(SAFE_META, 'w') as f:
        json.dump(data, f)


def get_config_value(key):
    """ Get a value from the config file.

    :param key: The key to search for in the config file.
    :return: The value found in the config file, if exists. Otherwise None.
    """
    with open(SAFE_CONFIG, 'r') as f:
        cfg_data = json.load(f)
    if key in cfg_data:
        return cfg_data[key]
    return None


def overwrite_config(**kwargs):
    """ Update the config file based on the specified kwargs.

    If a key specified in the kwargs does not exist in the config file, that
    key:value pair will be skipped (will not be added to the config file, but
    also will not fail).

    :param kwargs: The entries in the config JSON to update.
    :return: None
    """
    with open(SAFE_CONFIG, 'r+') as f:
        cfg_data = json.load(f)
        for k, v in kwargs.items():
            if k in cfg_data:
                cfg_data[k] = v
        f.seek(0)
        json.dump(cfg_data, f)
        f.truncate()


def toggle_config_value(to_toggle):
    """ Toggle values in the config file based on the specified kwargs.

    The only values which may be toggled are boolean values. Attempts to toggle
    any other type will be ignored.

    :param to_toggle: The entry in the config JSON to toggle.
    :return: The new value of the updated config field.
    :rtype: bool
    """
    result = None
    with open(SAFE_CONFIG, 'r+') as f:
        cfg_data = json.load(f)
        if to_toggle in cfg_data and isinstance(cfg_data[to_toggle], bool):
            cfg_data[to_toggle] = not cfg_data[to_toggle]
            result = cfg_data[to_toggle]
        f.seek(0)
        json.dump(cfg_data, f)
        f.truncate()
    return result


def get_open_safe():
    """ Get the name of the Safe that is currently open, if it exists.

    There should never be more than one Safe open at a time. If multiple Safes
    are found to be open, this will indiscriminately close all of them to prevent
    erroneous writes.

    :return: The name of the open safe, if any. Otherwise None
    """
    meta = get_meta()

    unlocked = []
    for safe in meta['safes']:
        if safe['is_open']:
            unlocked.append(safe['name'])
    if not unlocked:
        return None
    if len(unlocked) > 1:
        info('more than one safe is open. closing all safes.')
        close_safe()
        return None
    else:
        return unlocked[0]


def get_safe_file_paths(safe_name):
    """ Get the path for the open and closed Safe files.

    :param safe_name: Name of the Safe.
    :return: A tuple which contains the path of the open safe file and the path
        of the closed safe file.
    """
    return join_path(SAFES_PATH, safe_name + '.open'), join_path(SAFES_PATH, safe_name)


def fail(message):
    """ A convenience method to exit with a failure message.

    :param message: The message to output.
    :type message: str
    :return: None
    """
    exit('\n[FAILED] - {}'.format(message))


def info(message):
    """ A convenience method to print out info messages to console.

    :param message: The message to output.
    :type message: str
    :return: None
    """
    print '>> {}'.format(message)


def exit_info(message):
    """ A convenience method to print out an info message to console and exit.

    :param message: The message to output.
    :type message: str
    :return: None
    """
    exit('>> {}'.format(message))


def prompt(message):
    """ A convenience method to prompt the used for information.

    :param message: The message to output for the prompt.
    :type message: str
    :return: The value given by the user.
    """
    return raw_input(':: {}: '.format(message))


# ========================================================================
# Encryption/Hashing Methods
# ========================================================================

def get_md5_hash(to_hash):
    """ Generate an MD5 hash of the given value.

    :param to_hash: Value to crate an MD5 hash of.
    :type to_hash: str
    :return: The hexadecimal representation of the MD5 hash.
    """
    return md5(to_hash).hexdigest()


def encrypt_file(password, in_file, out_file):
    """ Encrypt the contents of the given file.

    Encrypts the contents of the in_file into the out_file.

    :param password: The password for the file being encrypted.
    :type password: str
    :param in_file: The name of the file to encrypt.
    :type in_file: str
    :param out_file: The name of the file to create, which contains the encrypted data.
    :type out_file: str
    :return: None
    """
    bs = AES.block_size
    chunk_size = bs * 1024
    key = sha256(password).digest()

    iv = ''.join(chr(randint(0, 0xff)) for _ in range(16))
    cipher = AES.new(key, AES.MODE_CBC, iv)
    file_size = getsize(in_file)

    with open(in_file, 'rb') as in_f, open(out_file, 'wb') as out_f:
        out_f.write(struct.pack('<Q', file_size))
        out_f.write(iv)

        while True:
            chunk = in_f.read(chunk_size)
            if len(chunk) == 0:
                break
            elif len(chunk) % 16 != 0:
                chunk += ' ' * (16 - len(chunk) % 16)
            out_f.write(cipher.encrypt(chunk))


def decrypt_file(password, in_file, out_file):
    """ Decrypt the contents of the given file.

    Decrypts the contents of the in_file into the out_file.

    :param password: The password for the file being decrypted.
    :param in_file: The name of the file to decrypt.
    :param out_file: The name of the file to create, which contains the decrypted
        data.
    :return: None
    """
    bs = AES.block_size
    chunk_size = bs * 1024
    key = sha256(password).digest()

    with open(in_file, 'rb') as in_f, open(out_file, 'wb') as out_f:
        orig_size = struct.unpack('<Q', in_f.read(struct.calcsize('Q')))[0]
        iv = in_f.read(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        while True:
            chunk = in_f.read(chunk_size)
            if len(chunk) == 0:
                break
            out_f.write(cipher.decrypt(chunk))
        out_f.truncate(orig_size)


# ========================================================================
# Safe Methods
# ========================================================================

def initialize():
    """ Initialize Safe, ensuring the Safe directory is created.

    This should:
     * create the Safe root dir, if it does not exist
     * create the safes dir to hold all user Safes, if it doesnt exist
     * create the base config and metadata files, if they do not exist

    :return: None
    """
    if not isdir(SAFE_ROOT):
        mkdir(SAFE_ROOT)
    if not isdir(SAFES_PATH):
        mkdir(SAFES_PATH)
    if not isfile(SAFE_CONFIG):
        with open(SAFE_CONFIG, 'w') as conf:
            json.dump(default_cfg, conf)
    if not isfile(SAFE_META):
        with open(SAFE_META, 'w') as meta:
            json.dump(default_meta, meta)


def initialize_safe(name=None, password=None):
    """ Create a new Safe.

    Creates a new Safe given a name and password. If no name and password are
    provided via commandline args, the user will be prompted for both.

    Safes cannot be overwritten. If a user desires to overwrite an existing
    Safe with a clean Safe of the same name, the Safe should first be deleted
    (using the -R or --remove-safe option) and a new safe initialized.

    :param name: The name of the Safe to initialize.
    :param password: The password for the new Safe.
    :return: None
    """
    if name is None:
        name = prompt('set safe name')
        if not name:
            name = 'safe'

    if name == ALL_SAFES:
        fail('cannot create safe with name "{}". this is a reserved name.'.format(name))

    if password is None:
        password = getpass.getpass(':: set password for safe "{}": '.format(name))
        re_password = getpass.getpass(':: re-enter password: ')
        if password != re_password:
                fail('entered passwords do not match.')

    # load in the data from the meta file
    meta = get_meta()

    # check if a safe with that name already exists
    for safe in meta['safes']:
        if safe['name'] == name:
            fail('a safe with name "{}" already exists.'.format(name))

    # hash the password
    password_hash = get_md5_hash(password)

    # close the open safe, if there is one
    active_safe = get_open_safe()
    if active_safe:
        set_meta(meta)
        close_safe(active_safe)
        meta = get_meta()

    # create an entry in the meta file
    new_safe = {
        'name': name,
        'hash': password_hash,
        'is_open': True
    }
    meta['safes'].append(new_safe)
    set_meta(meta)

    # create a safe file for this safe. note that the default behavior for the init
    # is to leave that safe open. otherwise, we would encrypt and close.
    with open(join_path(SAFES_PATH, name + '.open'), 'w+') as f:
        json.dump({'password': password, 'entries': []}, f)

    if is_verbose:
        info('created safe "{}"'.format(name))


def open_safe(name=None, password=None):
    """ Open an existing Safe.

    If no Safe is specified, the default Safe will be used. If no default Safe
    is specified, the user will be notified of failure and safe will exit. Opening
    a Safe will close any other Safe that is open, to prevent erroneous writes.

    :param name: Name of the safe to open. If no name is provided, the user will
        be prompted for a name.
    :param password: Password for the safe to open. If no password is provided, the
        user will be prompted for a password.
    :return: None
    """
    if name is None:
        name = get_config_value('default_safe')
        if not name:
            fail('no safe name provided, and no default safe found.')
        info('no safe provided; choosing default ({})'.format(name))

    if password is None:
        password = getpass.getpass(':: password: ')

    # close the open safe, if any
    active_safe = get_open_safe()
    if active_safe:
        close_safe(active_safe)

    meta = get_meta()
    for safe in meta['safes']:
        if safe['name'] == name:
            if safe['hash'] == get_md5_hash(password):
                if not safe['is_open']:
                    safe_paths = get_safe_file_paths(name)
                    decrypt_file(password, safe_paths[1], safe_paths[0])
                    remove(safe_paths[1])
                    safe['is_open'] = True
                else:
                    info('the safe is already open.')
            else:
                fail('password incorrect for safe')
        elif safe['is_open']:
            close_safe(safe['name'])

    set_meta(meta)

    if is_verbose:
        info('opened safe "{}"'.format(name))


def close_safe(name=None):
    """ Close an existing open Safe.

    Closes the specified Safe. All Safes will be closed if no specific Safe is
    specified. If a specified Safe does not exist, a message may be logged,
    otherwise nothing will happen, as a non-existent Safe can technically be
    considered a closed Safe.

    :param name: The name of the Safe to close.
    :return: None
    """
    meta = get_meta()

    def encrypt_safe(safe_name):
        safe_paths = get_safe_file_paths(safe_name)
        if isfile(safe_paths[0]):
            with open(safe_paths[0], 'r') as s:
                data = json.load(s)
            password = data['password']

            encrypt_file(password, safe_paths[0], safe_paths[1])
            remove(safe_paths[0])

    if name is None:
        for safe in meta['safes']:
            if safe['is_open']:
                encrypt_safe(safe['name'])
                safe['is_open'] = False
    else:
        for safe in meta['safes']:
            if safe['name'] == name:
                encrypt_safe(name)
                safe['is_open'] = False
                break

    set_meta(meta)

    if is_verbose:
        info('closed safe "{}"'.format(name))


def set_default(safe_name):
    """ Set the default Safe.

    This updates the 'default_safe' field in the Safe config file.

    :param safe_name: The name of the safe to be the default.
    :return: None
    """
    meta = get_meta()
    safe_exists = False
    for safe in meta['safes']:
        if safe['name'] == safe_name:
            safe_exists = True
            break

    if safe_exists:
        overwrite_config(default_safe=safe_name)
        if is_verbose:
            info('"{}" is now the default safe'.format(safe_name))
    else:
        fail('could not set default safe. "{}" does not exist.'.format(safe_name))


def add_entry(name=None, username=None, password=None):
    """ Add an entry to the currently open Safe.

    An entry consists of:
      1. name (entry identifier, i.e. 'github')
      2. username (user identifier; be it a username or email)
      3. password (the password associated with the given username)

    Currently, only one username/password can be associated with a given entry
    identifier. If no Safe is open, adding an entry fails. If an entry name is
    already used in the open Safe, adding an entry fails.

    :param name: Name of the Safe entry.
    :param username: Username associated with the entry.
    :param password: Password associated with the entry.
    :return: None
    """
    if name is None:
        name = prompt('entry name')

    if username is None:
        username = prompt('username')

    if password is None:
        password = prompt('password')

    entry_data = {
        'name': name,
        'username': username,
        'pass': password
    }

    safe = get_open_safe()
    if safe:
        safe_file = join_path(SAFES_PATH, safe + '.open')
        with open(safe_file, 'r') as f:
            safe_data = json.load(f)

        for entry in safe_data['entries']:
            if entry['name'] == name:
                fail('entry "{}" already exists'.format(name))
        safe_data['entries'].append(entry_data)
        with open(safe_file, 'w') as f:
            json.dump(safe_data, f)
    else:
        exit_info('no open safes found. open a safe with the --open option.')

    if is_verbose:
        info('added entry "{}" to safe "{}"'.format(name, safe))


def get_entry(name, show_all=False, show_username=False):
    """ Retrieves an entry by name from the currently open Safe.

    By default, this will print out only the password associated with the
    specified entry. Additional commandline flags can be added in order to
    show additional information:
      * -u, --username -> show the username along with the password
      * -w, --whole    -> show the whole json entry

    :param name: Name of the entry to retrieve information for.
    :param show_all: Flag designating that all JSON info be shown.
    :param show_username: Flag designating that username info be shown.
    :return: None
    """
    safe = get_open_safe()
    if safe:
        safe_file = join_path(SAFES_PATH, safe + '.open')
        with open(safe_file, 'r') as f:
            safe_data = json.load(f)

        found = False
        for entry in safe_data['entries']:
            if entry['name'] == name:
                found = True
                if show_all:
                    print json.dumps(entry, indent=2, separators=(',', ':\t'))
                elif show_username:
                    print entry['username']
                    print entry['pass']
                else:
                    print entry['pass']
        if not found:
            fail('no entry found with name "{}".'.format(name))
    else:
        exit_info('no open safes found. open a safe with the --open option.')


def modify_entry(name=None):
    """ Modify an entry in the currently opened Safe.

    :param name: The name of the entry to modify.
    :return: None
    """
    safe = get_open_safe()
    if safe:
        if name is None:
            name = prompt('entry to modify')

        info('leave a prompt blank to leave the record unchanged.')
        new_username = prompt('new username')
        new_password = prompt('new password')

        if not new_username and not new_password:
            exit_info('no fields specified for modification.')

        safe_file = join_path(SAFES_PATH, safe + '.open')
        with open(safe_file, 'r') as f:
            safe_data = json.load(f)

        for entry in safe_data['entries']:
            if entry['name'] == name:
                if new_password:
                    entry['pass'] = new_password
                if new_username:
                    entry['username'] = new_username
                break

        with open(safe_file, 'w') as f:
            json.dump(safe_data, f)
    else:
        exit_info('no open safes found. open a safe with the --open option.')

    if is_verbose:
        info('successfully modified "{}" in safe "{}"'.format(name, safe))


def modify_safe(name=None, password=None):
    """ Modify a Safe.

    :param name: The name of the Safe to modify.
    :return: None
    """
    if name is None:
        name = prompt('safe to modify')

    if password is None:
        password = getpass.getpass(':: password: ')

    meta = get_meta()
    found = False
    for safe in meta['safes']:
        if safe['name'] == name:
            found = True
            if safe['hash'] == get_md5_hash(password):
                info('leave a prompt blank to leave the record unchanged.')
                new_password = getpass.getpass(':: new password: ')
                re_rew_password = getpass.getpass(':: re-enter new password: ')
                if new_password != re_rew_password:
                    fail('entered passwords do not match.')

                safe_paths = get_safe_file_paths(name)
                if not safe['is_open']:
                    decrypt_file(password, safe_paths[1], safe_paths[0])

                with open(safe_paths[0], 'r') as f:
                    file_data = json.load(f)
                file_data['password'] = new_password
                with open(safe_paths[0], 'w') as f:
                    json.dump(file_data, f)

                if not safe['is_open']:
                    encrypt_file(new_password, safe_paths[0], safe_paths[1])

                safe['hash'] = get_md5_hash(new_password)

            else:
                fail('password incorrect for safe')

    if not found:
        exit_info('safe with name "{}" not found.'.format(name))

    set_meta(meta)
    if is_verbose:
        info('successfully modified safe "{}"'.format(name))


def delete_entry(name):
    """ Delete an entry from the currently open Safe.

    :param name: Name of the entry to delete.
    :type name: str
    :return: None
    """
    safe = get_open_safe()
    if safe:
        safe_file = get_safe_file_paths(safe)[0]
        with open(safe_file, 'r') as f:
            safe_data = json.load(f)

        entry_list = safe_data['entries']
        entry_list[:] = [x for x in entry_list if not x['name'] == name]

        with open(safe_file, 'w') as f:
            json.dump(safe_data, f)
    else:
        exit_info('no open safes found. open a safe with the --open option.')

    if is_verbose:
        info('successfully removed entry "{}"'.format(name))


def delete_safe(name, force=False):
    """ Delete a Safe and all of its contents.

    :param name: The name of the safe to delete.
    :param force: Flag which designates whether to prompt for validation or not.
        (default: False)
    :return: None
    """
    if not force:
        verify = prompt('delete safe "{}" and all of its contents? (y/N)'.format(name)) or 'n'
        if verify.lower() == 'n':
            exit_info('aborting safe delete.')

    safe_paths = get_safe_file_paths(name)
    if isfile(safe_paths[0]):
        remove(safe_paths[0])
    if isfile(safe_paths[1]):
        remove(safe_paths[1])

    meta = get_meta()
    safes = meta['safes']
    safes[:] = [x for x in safes if not x['name'] == name]

    set_meta(meta)

    if is_verbose:
        info('successfully deleted safe "{}"'.format(name))


def list_entries():
    """ List all entries in the Safe that is currently open.

    :return: None
    """
    safe = get_open_safe()
    if safe:
        safe_file = get_safe_file_paths(safe)[0]
        with open(safe_file, 'r') as f:
            safe_data = json.load(f)

        if len(safe_data['entries']) == 0:
            exit_info('no entries in the safe "{}".'.format(safe))

        entries = [entry['name'] for entry in safe_data['entries']]
        print '\n   '.join(['Entries:'] + entries)
    else:
        exit_info('no open safes found. open a safe with the --open option.')


def list_safes():
    """ List all initialized Safes.

    The Safe that is currently open will be denoted with a '*' next to the
    name. By design, either 0 or 1 Safe should be open at any given time, so
    there should never be more than one safe marked as open.

    :return: None
    """
    meta = get_meta()
    safes = []
    for safe in meta['safes']:
        name = ''
        if safe['is_open']:
            name += '* '
        name += safe['name']
        safes.append(name)

    if len(safes) == 0:
        exit_info('no safes exist.')

    print '\n   '.join(['Safes:'] + safes)


# ========================================================================
# Safe Main
# ========================================================================

if __name__ == '__main__':
    # initialize Safe and get any arguments passed to it.
    initialize()
    args = parser.parse_args()

    # ---------------------------------
    # Get/Set the verbosity of Safe
    # ---------------------------------
    if args.verbose:
        is_verbose = toggle_config_value('verbose')
        info('set verbosity to {}'.format(is_verbose))
    else:
        is_verbose = get_config_value('verbose')

    # ---------------------------------
    # Initialize a new Safe
    # ---------------------------------
    if args.init is not None:
        count = len(args.init)
        if count == 0:
            initialize_safe()
        elif count == 1:
            initialize_safe(name=args.init[0])
        elif count == 2:
            initialize_safe(name=args.init[0], password=args.init[1])
        else:
            parser.error('too many arguments given for --init. (accepts 0, 1, or 2 arguments)')

    # ---------------------------------
    # Open a Safe
    # ---------------------------------
    if args.open is not None:
        count = len(args.open)
        if count == 0:
            open_safe()
        elif count == 1:
            open_safe(name=args.open[0])
        elif count == 2:
            open_safe(name=args.open[0], password=args.open[1])
        else:
            parser.error('too many arguments given for --open. (accepts 0, 1, or 2 arguments)')

    # ---------------------------------
    # Add data to a Safe
    # ---------------------------------
    if args.add is not None:
        count = len(args.add)
        if count == 0:
            add_entry()
        elif count == 1:
            add_entry(name=args.add[0])
        elif count == 2:
            add_entry(name=args.add[0], username=args.add[1])
        elif count == 3:
            add_entry(name=args.add[0], username=args.add[1], password=args.add[2])
        else:
            parser.error('too many arguments given for --add. (accepts 0, 1, 2, or 3 arguments)')

    # ---------------------------------
    # Modify an entry from a Safe
    # ---------------------------------
    if args.modify is not None:
        if args.modify:
            modify_entry(args.modify)
        else:
            modify_entry()

    # ---------------------------------
    # Modify a Safe
    # ---------------------------------
    if args.modify_safe is not None:
        count = len(args.modify_safe)
        if count == 0:
            modify_safe()
        elif count == 1:
            modify_safe(name=args.modify_safe[0])
        elif count == 2:
            modify_safe(name=args.modify_safe[0], password=args.modify_safe[1])
        else:
            parser.error('too many arguments given for --modify_safe. (accepts 0, 1, or 2 arguments)')

    # ---------------------------------
    # Delete data from a Safe
    # ---------------------------------
    if args.delete:
        delete_entry(args.delete)

    # ---------------------------------
    # Delete a Safe
    # ---------------------------------
    if args.delete_safe:
        delete_safe(args.delete_safe, args.force)

    # ---------------------------------
    # Set the default Safe
    # ---------------------------------
    if args.default:
        set_default(args.default)

    # ---------------------------------
    # Close an open Safe
    # ---------------------------------
    if args.close:
        if args.close == ALL_SAFES:
            close_safe()
        else:
            close_safe(args.close)

    # ---------------------------------
    # Lookup info from a Safe
    # ---------------------------------
    if args.entry:
        get_entry(args.entry, show_all=args.whole, show_username=args.username)

    # ---------------------------------
    # Lookup entries in a Safe
    # ---------------------------------
    if args.entries:
        list_entries()

    # ---------------------------------
    # Lookup all Safes
    # ---------------------------------
    if args.safes:
        list_safes()
