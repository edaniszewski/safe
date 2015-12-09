safe
====
yet another commandline password manager using AES encryption, written in python.

### installation
to install and use safe, clone the repository

```shell
$ git clone https://github.com/edaniszewski/safe.git
```

### setup
safe can be run by executing the `safe.py` script, but a nicer solution
would be to run it off the path.

first, copy the `safe` script onto your path.
 
```shell
$ cp safe.py /usr/local/bin/safe
```

it may also be necessary to modify the permissions on the `safe` script to
allow it to run as a non-sudo user

```shell
$ chmod +x /usr/local/bin/safe
```

copying the `safe` script to a location on your path and modifying the
permissions can also be done by running the simple setup script provided

```shell
$ ./setup.sh
```

### usage

usage information is provided with the `--help` flag

```
usage: safe [-h] [-i [INIT [INIT ...]]] [-o [OPEN [OPEN ...]]] [-c [CLOSE]]
            [-a [ADD [ADD ...]]] [-d DELETE] [--default DEFAULT]
            [-D DELETE_SAFE] [-m [MODIFY]]
            [-M [MODIFY_SAFE [MODIFY_SAFE ...]]] [-u] [-w] [-e] [-s] [-f] [-v]
            [entry]

Safe :: A minimalistic commandline password manager

positional arguments:
  entry                 the name of the entry in the safe for which the stored
                        information will be retrieved.

optional arguments:
  -h, --help            
                        show this help message and exit
  -i, --init            
                        initialize a new safe.
  -o, --open
                        open the specified safe. this is needed for both read
                        and write operations.
  -c, --close
                        close the specified safe. if no safe is specified, all
                        open safes are closed. safes will not close
                        automatically - it is up to the user to close their
                        safes.
  -a, --add
                        add a new entry to the safe. add can take 0..3
                        arguments, where the user will be prompted to fill in
                        any missing arguments. the arguments are positional.
                        the order is as follows: (1) entry name, (2)
                        username/id, (3) password
  -d, --delete
                        remove an entry from the safe.
  --default             
                        set the default safe. the default safe is used by
                        commands, such as open, to determine which safe to use
                        if none is specified.
  -D, --delete_safe
                        remove an existing safe. this removes the safe and all
                        of its entries permanently.
  -m, --modify
                        modify an existing entry for the open safe. this can
                        be used to change username/password information.
  -M, --modify_safe
                        modify an existing safe. this should be used if one
                        wants to change the master password to a safe, without
                        losing the safe contents.
  -u, --username        
                        a flag which, when present, will include username info
                        in an entry's output.
  -w, --whole           
                        a flag which, when present, will show the full entry
                        (all data).
  -e, --entries         
                        show all entries (by name) which exist in the open
                        safe.
  -s, --safes           
                        show all safes (by name) which exist.
  -f, --force           
                        force an action. typically, this is used with deletes
                        in order to suppress the verification prompt.
  -v, --verbose         
                        a flag which toggles the verbosity of safe. if set to
                        true, additional messages will be output, such as
                        verification of action success.
```

### examples
below are a few examples demonstrating the intended usage of `safe`. the examples
assume `safe` has been added to the path.

#### set verbosity
setting the verbosity to true will have `safe` print out additional messages, particularly
on the success of an action

```
$ safe -v
>> set verbosity to True
```

verbosity can be turned off again by passing the same flag

```
$ safe -v
>> set verbosity to False
```

#### creating a safe
`safe` allows you to maintain multiple safes, should you desire. (e.g. one for personal, 
one for work, ...) when a safe is initialized, it is automatically opened. as with many
of the commands in `safe`, there are multiple ways to initialize a safe.

*specifying no parameters (will be prompted for all)*
```
safe --init
:: set safe name: new-safe
:: set password for safe "new-safe": 
:: re-enter password: 
>> created safe "new-safe"
```

*specifying some parameters (will be prompted for remaning)*
```
$ safe --init new-safe
:: set password for safe "new-safe": 
:: re-enter password: 
>> created safe "new-safe"
```

*specifying all parameters (will not be prompted)*
```
safe --init new-safe password
>> created safe "new-safe"
```

the `-i` flag can be used in place of `--init`.


#### closing a safe
currently, `safe` will not close any open safes on its own (e.g. after timeout, etc.). it is up
to the user to close a safe once they are done using it. when a safe is closed, the contents of 
the file which contains the safe's information is encrypted with an AES cipher.

```
$ safe --close new-safe
>> closed safe "new-safe"
```

if no arguments are specified with the close command, all open safes are closed. in practice, there
should only ever be a single safe that is open at a time to prevent clashes.


#### opening a safe
to open an existing safe, provide the safe name, and you will be prompted for the password.

```
$ safe --open new-safe
:: password: 
>> opened safe "new-safe"
```


#### viewing existing safes
to see which safes currently exist, use the `-s` or `--safes` flag. the open safe, if any, will be 
denoted with a '*' next to the name.

```
$ safe -s
Safes:
   * new-safe
```


#### adding entries to a safe
entries (records) can be added to the currently open safe using the `-a` or `--add` flags.

```
$ safe --add
:: entry name: github
:: username: edaniszewski
:: password: n1c3-tRy
>> added entry "github" to safe "new-safe"
```

this can also be done passing args to the `--add` flag

```
>> safe --add github edaniszewski n1c3-tRy
>> added entry "github" to safe "new-safe"
```


#### viewing existing entries
having a safe open, it is possible to view which entries exist in it

```
$ safe -e
Entries:
   github
```


#### getting information about an entry
to get the password for a store entry, simply invoke safe with the name of the entry

```
$ safe github
n1c3-tRy
```

the username can be included in the output with the `-u` or `--username` flag.

```
$ edaniszewski
n1c3-tRy
```

to view all information for the specified entry, include the `-w` or `--whole` flag.

```
$ safe -w github
{
  "username":   "edaniszewski",
  "name":       "github",
  "pass":       "n1c3-tRy"
}
```

to copy the password directly to the clipboard, simply pipe the output to something like
pbcopy (for mac).

```
$ safe github | pbcopy
```


#### modifying an entry
entries can be updated if you so desire

```
$ safe -m
:: entry to modify: github
>> leave a prompt blank to leave the record unchanged.
:: new username: 
:: new password: password1
>> successfully modified "github" in safe "new-safe"
```

another variation of modifying an entry

```
$ safe -m github
>> leave a prompt blank to leave the record unchanged.
:: new username: 
:: new password: password1
>> successfully modified "github" in safe "new-safe"
```

#### modifying a safe
safes can be modified as well. currently, the only supported modification is a password change.

```
$ safe -M new-safe
:: password: 
>> leave a prompt blank to leave the record unchanged.
:: new password: 
:: re-enter new password: 
>> successfully modified safe "new-safe"
```

#### deleting an entry
entries can be deleted from the currently open safe

```
$ safe -d github
>> successfully removed entry "github"
```


#### deleting a safe
entire safes may be deleted as well

```
$ safe -D new-safe
:: delete safe "new-safe" and all of its contents? (y/N): y
>> successfully deleted safe "new-safe"
```