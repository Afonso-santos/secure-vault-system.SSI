# Setup

Start by cloning this repository and creating a Python virtual environment:
```
$ python -m venv .venv
```

Then activate the virtual environment and install the project dependencies:
```
$ source .venv/bin/activate
$ pip install .
```

## How to Run the Project

Follow these steps to set up and run the project:

1. Create Certificates (optional if already available).
    First, generate the necessary certificates using the Certificate Authority (CA). This will create:
    - 1 server certificate
    - 3 client certificates

If you already have these certificates, you can skip this step.
```
$ python certificate_authority create -s 1 -c 3 -o certificates
```
2. Run the server, passing the path to the server certificate file:
```
$ python server certificates/VAULT_SERVER.p12 
```
3. Then, run the certificate authority server:
```
$ python certificate_authority run -d certificates
```
4. Finally, run the client, which connects first to the CA and then to the server
```
$ python client certificates/VAULT_CLI1.p12   
```

To exit the virtual environment, you can run:

```
$ deactivate
```

# Developers

All code must be verified with the `pylint` static checkers, which can be installed
(inside the `venv`) with the following command:

```
$ pip install pylint 
```

Before opening a Pull Request, please run your code though `pylint`and `black` fixing any error
that may appear:

```
$ black server client certificate_authority common
$ pylint server client certificate_authority common
```

Our configuration for these checkers disallows the use of dynamic typing, and your PR won't be
accepted if these checks are failing.



