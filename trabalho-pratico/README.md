# Setup

Start by cloning this repository, and creating a Python virtual environment:

```
$ python -m venv .venv
```

To run the project, start by running:

```
$ source .venv/bin/activate
$ pip install .
```


To exit the virtual environment, you can run:

```
$ deactivate
```

# Developers

All code must be verified with the `pylint` and `mypy` static checkers, which can be installed
(inside the `venv`) with the following command:

```
$ pip install pylint mypy
```

Before opening a Pull Request, please run your code though `pylint`, `mypy` and `black` fixing any error
that may appear:

```
$ black server client certificate_authority
$ pylint server client certificate_authority
$ mypy server client certificate_authority   
```

Our configuration for these checkers disallows the use of dynamic typing, and your PR won't be
accepted if these checks are failing.
