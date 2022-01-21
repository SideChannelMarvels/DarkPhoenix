# Dark Phoenix

*The Phoenix became Dark Phoenix due to allowing human emotions to cloud its judgment. In this state, Phoenix was the strongest, but also an evil entity that thirsted for power and destruction. Totally uncontrollable, Dark Phoenix was a force to be reckoned with as it was not bound by a human conscience.*

DarkPhoenix is a tool to perform differential fault analysis attacks (DFA) against AES whiteboxes **with external encodings**, as described in

- *A DFA Attack on White-Box Implementations of AES with External Encodings*, Alessandro Amadori, Wil Michiels, Peter Roelse [1]

## Dependencies

In order to solve some equations, you should have [SageMath](https://www.sagemath.org/) installed on your computer and available in your PATH (under the name `sage`).

## Install

```bash
$ pip install darkphoenixAES
```

## Test

```bash
$ python3 -m darkphoenixAES --selftest
```

## Usage

To use this attack, you should

1. Implement your own class inheriting from `WhiteBoxedAES` to provide the script an access to the whitebox to attack.
2. Instantiate the `Attack` class with your own class as parameter, and run it.

### 1. Implement a class inheriting from WhiteBoxedAES

The class inheriting from `WhiteBoxedAES` will be the interface between the whitebox and the attack script.
This class must be able to introduce a fault at a given position in the whitebox.

Here is an example of implementation.
More information is available in the file [WhiteBoxedAES.py](darkphoenixAES/WhiteBoxedAES.py).
A complete example is implemented in [WhiteBoxedAESTest.py](darkphoenixAES/test/WhiteBoxedAESTest.py).

```python
from darkphoenixAES import WhiteBoxedAES

class MyWhiteBoxedAES(WhiteBoxedAES):

    def __init__(self, ...):
        self.aeswb = ...

    def getRoundNumber(self):
        # return the number of rounds of the whitebox (10 for AES128,
        #   12 for AES192 and 14 for AES256)
        return 10

    def isEncrypt(self):
        # Does the whitebox encrypt of decrypt data
        # (needed and validate with the MixColumns result)
        return True

    def hasReverse(self):
        # Is there an applyReverse method that can be called?
        return False

    def apply(self, data):
        # Apply the whitebox on a buffer
        # [param] data  a buffer of 16 bytes (type bytes)
        # return  16 bytes of the encrypted/decrypted data

        return # TODO : return the encrypted value of data

    def applyFault(self, data, faults):
        # Apply the whitebox on a buffer and inject fault at the given position
        # [param] data      a buffer of 16 bytes (type bytes)
        # [param] faults    a list of faults to apply:
        #       fround, fbytes, fxorval = faults[0]
        #       fround      the round to apply the fault. 0 is the first round
        #       fbytes      the position of the internal state byte to fault (between 0 and 15)
        #       fxorval     the fault to apply by xor (between 1 and 255)
        # return  16 bytes of the faulted encrypted data

        return # TODO : return the encrypted faulted value of data with the given faults
```

### 2. Instantiate and run the Attack class

```python
from darkphoenixAES import Attack
import MyWhiteBoxedAES

# initialize your whitebox
myWB = MyWhiteBoxedAES(...)

# run the attack
# The file "backup.json" will be used the save the result of
# each step and must be removed before running on a new instance.
attack = Attack(myWB)
attack.run("backup.json")

# print extracted roundKey
attack.printKey()

# get the extracted Key
key = attack.getKey()
print("key:", key.hex())

# get the external encoding
inputE, outputE = attack.externalEncoding()
```

When instantiating the Attack class, you can specify the following optional arguments:

* `nprocess` : The number of processes used by multiprocess (default: autodetect (`None`))
  The special value `0` disables the use of multiprocess.
* `noprogress` : Enable or disable the progress bar (default: autodetect TTY (`None`))
* `sageSubProc` : Use Sage in a subprocess (default: `True`). The attack needs SageMath to solve some equations. If `True`, a separate process is used to solve these equations, otherwise, the Sage library is loaded within the current Python process
* `step1DoubleValue` : apply Step 1 with the property used in the paper (two fixed values by column) (default: `False`). If this option is `False`, only one fixed value is needed in Step 1 (reducing the complexity by 256). However, this optimization delays the detection of a wrong injection position during Step 2.

## Advanced Usage

### Selecting fault position during the attack (manually)

To perform the attack, the fault must first be injected one MixColumn before the output, then two MixColumn before, etc.
While the position of the first faults can be found by looking at the output, this not the case for the next ones.

If you want to manually select the fault position during the attack, you can use the base class `WhiteBoxedAESDynamic` instead of `WhiteBoxedAES`:

```python
from darkphoenixAES import WhiteBoxedAESDynamic

class MyWhiteBoxedAES(WhiteBoxedAESDynamic):

    # ... same as WhiteBoxedAES

    def prepareFaultPosition(self, fround, reverseRoundMethod, reverseRoundMethod2=None):
        # TODO search fault for the round `fround`
        pass
```

When the attack needs to inject faults in a new round, the method
`prepareFaultPosition` will first be called. In order to verify if the fault is valid for this round, two methods are given:
- `reverseRoundMethod`: reverse the result up to `fround+1`. A valid fault position must fault 4 bytes of the reversed output with this method.
- `reverseRoundMethod2`: reverse the result up to `fround+2`. A valid fault position must fault all the bytes of the reversed output with this method. This method is provided to detect is the fault is applied at fround+2 instead of fround. This method is not provided when `fround == wb.getRoundNumber()-1`

When `prepareFaultPosition` returns, 16 different fault positions must have been found according to `reverseRoundMethod` and `reverseRoundMethod2`.

### Selecting fault position during the attack (automatically)

DarkPhoenix integrates a second mechanism to identify the fault position. To use it, the base class `WhiteBoxedAESAuto` must be used, and the method `Attack.run` should be replaced by `Attack.runAuto`:

```python
from darkphoenixAES import WhiteBoxedAESAuto

class MyWhiteBoxedAES(WhiteBoxedAESAuto):

    # ... same as WhiteBoxedAES

    def changeFaultPosition(self, fround, fbytes):
        # TODO select a random fault position for (fround, fbytes)
        pass

    def applyFault(self, data, faults):
        for fround, fbytes, fxorval in faults:
            # TODO Apply the fault fxorval at the last selected position for (fround, fbytes)
```

The method `changeFaultPosition` selects a random fault position and associates (fround, fbytes) to this position. When a fault is asked with `applyFault` with the same (fround, fbytes), this position should be used. If DarkPhoenix detects that the position is not valid, `changeFaultPosition` will be called again until a valid position is found.

While DarkPhoenix is able to identify if the fault is mathematically valid, `changeFaultPosition` must verify that the fault position is viable (i.e. it does not crash the process) for any fault value.

### WhiteBoxedAES compatible with multiprocessing

When `Attack` is not called with `nprocess=0`, the computation of the two first steps will be performed in many `multiprocessing.Process` or in a `multiprocessing.Pool`. On Linux, this is equivalent to a fork (see [multiprocessing documentation](https://docs.python.org/3/library/multiprocessing.html#contexts-and-start-methods)).

When a new process is created during these steps, the new process has it own copy of `WhiteBoxedAES`. However, depending of the implementation of `WhiteBoxedAES`, some resources need to be recreated (file descriptor, subprocess, debugged process, ...). For this purpose, the method `newThread` will be called on the new copy of `WhiteBoxedAES` when the new thread start.

However, the first `WhiteBoxedAES` and any copy of it must return the same result for the same input with the same fault. If this not possible, you should disable multiprocessing with `nprocess=0`.

If using dynamic fault position, `prepareFaultPosition` and `changeFaultPosition` are always called on the first instance of `WhiteBoxedAES`. The fault position must be shared with any future copy of `WhiteBoxedAES`.

## About

### Authors and Contributors

Initial Authors and Contributors:

- Nicolas Surbayrole
- Philippe Teuwen

For next contributions, see the git project history.

### Copyright

[Quarkslab](https://www.quarkslab.com)

### License

DarkPhoenix is provided under the [Apache 2.0 license](LICENSE).

### Credits

Many thanks to Alessandro Amadori, author of [1], for having shared his simulation scripts, which greatly helped us verify our own implementation during its development.

## References

[1]
Amadori A., Michiels W., Roelse P. (2020)
A DFA Attack on White-Box Implementations of AES with External Encodings.
In: Paterson K., Stebila D. (eds) Selected Areas in Cryptography – SAC 2019. SAC 2019. Lecture Notes in Computer Science, vol 11959. Springer, Cham. https://doi.org/10.1007/978-3-030-38471-5_24
