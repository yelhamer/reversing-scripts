#!/usr/bin/python3


from typing import Tuple, Iterator

import argparse
import vivisect


def computeEntropy(buf: list[int], size: int) -> float:
    # https://stackoverflow.com/questions/15450192/fastest-way-to-compute-entropy-in-python
    import numpy as np
    import math

    # empty/1-element section ==> null entropy
    if size <= 1:
        return 0.

    # compute the probability of occurance for all possible
    # array values (i.e. 256 values)
    values, occurances = np.unique(buf, return_counts=True)
    probabilities = occurances / size
    numClasses = np.count_nonzero(probabilities)

    # 1-or-less probability classes ==> null entropy 
    if numClasses <= 1:
        return 0.

    # compute entropy with a logarithmic base of 2
    entropy = 0.
    for probability in probabilities:
        entropy -= probability * math.log(probability, 2)

    return entropy


def sectionsEntropy(vw, sectionNames: list[str] = []) -> Iterator[Tuple[str, float]]:
    # compute the entropy for the requested sections
    for vaddr, size, name, _ in vw.getSegments():
        if (name in sectionNames) or (sectionNames == []):
            off, buf = vw.getByteDef(vaddr)
            yield name, computeEntropy(list(buf[off:off+size]), size)


def main(filename: str, sectionNames: list[str]):
    # attempt to load the binary into a vivisect workspace
    vw = vivisect.VivWorkspace()
    try:
        vw.loadFromFile(filename)
    except Exception as e:
        print(e)

    for name, entropy in sectionsEntropy(vw, sectionNames):
        # the printing format has been kept simple in order to make integration with bash-scripts 
        # easier. The entropy's accuracy is hardcoded to 3 digits for the time being.
        print(f"{entropy:.3f} {name}")
	

if __name__ == "__main__":
    # parse cli args
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', help="The path of the binary")
    parser.add_argument('-s', default='', help="A space separated list of the sections whose entropy should be computed")
    args = parser.parse_args()

    # call main: compute entropy for the specified functions
    main(args.filename, args.s.split())
