## GhidraX64Dbg
Extension containing a Ghidra script to export annotations from Ghidra to an X32/X64 database.

## Potentially Better Project
Update: Check out https://github.com/bootleg/ret-sync/commits/master. Their offering appears to have far more features than the simple sync that this project accomplishes and supports a wider set of debuggers and RE programs.

## Easy Installation
1. From the releases tab download the zip file
2. Open Ghidra and select File -> Install Extensions
3. Install the extension
4. Open a binary in Ghidra
5. Open Window -> Script Manager
6. Select the X64DbgExport script and execute it
7. Note: If this does not work out of the box, change extension.properties to match your version of Ghidra (e.g. 9.1.2 -> 9.2)

## License
GSON is a dependency and follows the Apache license.
Everything I wrote in this repository follows the MIT license.
