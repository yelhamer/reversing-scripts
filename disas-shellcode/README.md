# disas-shellcode

This script takes as parameters a file which contains shellcode, as well as the architecture of that shellcode. It them dissassembles that file using the capstone engine and prints the disassembly.

## Requirements

The required software/packages are:

```
python
pip
capstone
```

## Installation

Assuming Python is already present on the system, all that remains is to install the capstone engine and the python binding. The core capstone engine can be installed from the official repositories by issuing the command:

```
sudo apt-get install libcapstone2
```

The python binding can be installed by means of pip:

```
pip -r capstone
```

Or by using the provided pip-requirements file:

```
pip -r requirements.txt
```


## Usage

The usage is as follows:

```
./disas-shellcode.py <shellcode_filename>
```

Optionally, the following two parameters can be supplied to respectively: specify the offset and length of the shellcode (should it only be a portion of the source file), set the architecture to be 32-bit.

```
./disas-shellcode.py <shellcode_filename> --offset <value> --length <value> --x86
```
