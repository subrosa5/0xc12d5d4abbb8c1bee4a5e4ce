# Third-party components

The application source is MIT-licensed. Native builds bundle Python and third-party components; their own licenses and exceptions apply.

- Python / Tcl / Tk: runtime and desktop toolkit. https://docs.python.org/3/license.html and https://www.tcl-lang.org/software/tcltk/license.html
- PyCryptodome: AES-GCM, scrypt, Shamir, HPKE, ECC, ML-KEM and ML-DSA. https://www.pycryptodome.org/src/license
- PyInstaller: executable packaging and bootloader. https://pyinstaller.org/en/stable/license.html (including its distribution exception).
- PyInstaller hooks and packaging support: resolved build dependency versions are recorded in uv.lock.

These components are not assertions that the x12 application protocol has been audited or certified. Build archives include the available installed dependency license texts under third-party-licenses/.
