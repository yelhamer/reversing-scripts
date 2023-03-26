### Section Entropy

This script computes the entropy for different sections of an executable/object file, and outputs the results in a simple format which could then be piped to other bash scripts. This script supports PE and ELF formats by means of the vivisect engine.

### Usage

The script takes as parameters the filename of the input binary, as well as an optional parameter **-s** specifying the sections' whose entropy should be calculated.

Example:

```bash
$ ./section-entropy.py /bin/bash -s '.text .data'
6.321 .text
1.710 .data
```

In the absence of the optional **-s** parameter, the script computes the entropy for all the sections in the input binary.

### Pre-requisites:

The script makes use of the [vivisect](https://vivisect.readthedocs.io/en/latest/) framework, as well as the argparse python package. Both of these dependencies can be installed using the command:

```bash
$ pip3 -r requirements.txt
```
