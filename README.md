# mpc

Welcome to Faction's open source Secure Multi Party Computation toolkit. We're bringing MPC techniques to real world problems.

**This repository is currently under active development and is likely unstable** 

[What is Secure Multi Party Computation?](https://en.wikipedia.org/wiki/Secure_multi-party_computation)

## Requirements

- python 3.7+
- gf256 module (`pip3 install gf256`)
- asyncio and related modules (`pip3 install asyncio aiohttp cchardet aiodns`)
- ecies module (`pip3 install eciespy`)

## Clone and test

Clone the root repository and enter the directory

Before running tests make sure to unzip any zipped files in the `bristol_circuits` directory (some tests will fail if not).

Test files are any python files that end with `..._test.py`. Run them as you'd run any python file (`$ python3 <filename>`). They each test individual components of the MPC engine.

## Integration Test

We do not currently have proper integration testing (in general we can still improve testing across this project). To quickly verify that the entire platform runs properly run these three commands (in three processes, simultaneously):

```
$ python3 runtriples.py 8000 1 3 1 '[("127.0.0.1", 8001, 2), ("127.0.0.1", 8002, 3)]'
$ python3 runtriples.py 8001 1 3 2 '[("127.0.0.1", 8000, 1), ("127.0.0.1", 8002, 3)]'
$ python3 runtriples.py 8002 1 3 3 '[("127.0.0.1", 8000, 1), ("127.0.0.1", 8001, 2)]'
```

this should start generating triples with coordinated prints to the std out every few seconds in each terminal.

## Package Overview

This Multi Party Computation implementation relies on a number of classes:

1. `MPCPeer` class: An MPC node with a predefied set of peers (see: mpc.py)
2. `Circuit` class: A boolean circuit evaluator supporting MPC distributed evaluation (see: circuit.py)
3. `Shamir` class: Shamir Secret Sharing over field GF256 (see: shamir.py)
4. `MPCProgram` class: A modest custom compiler for conveniently constructing simple boolean circuits into our MPC executable bytecode format (see `bristol_compiler` folder)

## Circuits

The `Circuit` class is instanciated with two arguments, a path to a bytecode file and a list of input types:
- Bytecode Files are loaded from 'Bristol Fashion' txt files. Learn more about the bytecode format here: https://homes.esat.kuleuven.be/~nsmart/MPC/
- Input types are a list of 'V' or 'S' characters where 'S' stands for share and 'V' for value (i.e. a plaintext bit).

You can verify that an MPC circuit compiled in the Bristol Fashion works properly by instanciating and evaluating an instance of this circuit with only plaintext inputs (see input types above) with a `RuntimeCircuit`. Without share inputs a `RuntimeCircuit` operates as an entirely local bytecode evaluator, however the same `RuntimeCircuit` class is used with share inputs for MPC evaluation.

## Custom Compiler

We have a naive but functional custom compilation method for compiling your own circuits into the Bristol Fashion bytecode. In the `bristol_compiler` directory the MPCProgram class can be used to write little pythonic programs that automatically compile down to the bristol bytecode and output it as a .txt file. Our rudimentary scripting laguage looks like this (`example_program.py`):

```
from compiler import MPCProgram

mpc = MPCProgram()
x = mpc.input(64)
y = mpc.input(64)
addition = mpc.add64(x, y)
subtraction = mpc.sub64(x, y)
mpc.output(addition, subtraction)
mpc.compile("example.txt")
```

This program outputs 124 bits. The first 64 bits of the output are the result of a 64 bit (modular) addition  of inputs x and y and the second 64 bits are ther result of a 64 bit subtraction of inputs x and y. Regular pythonic syntax can be used for simple loops (does not support looping over an input value since then the number of loops and thus the exact circuit to compile would be unknown until runtime). 

