"""Voice in the Linux executable: PyInstaller packs libportaudio.so.2, but sounddevice looks PortAudio up with
ctypes.util.find_library("portaudio"), which never finds it there, so voice was off on every PC without
libportaudio2 installed. Simulates a frozen build on a PC with no PortAudio (a stub stands in for sounddevice,
so no sound card or package is needed) and checks that voice.py hands sounddevice the packed library."""
import sys, os, subprocess, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CHILD = r"""
import sys, ctypes.util
root, meipass, stubs, frozen = sys.argv[1:5]
sys.path[:0] = [stubs, root]
ctypes.util.find_library = lambda name: None if name == "portaudio" else "lib" + name   # no system PortAudio
if frozen == "1":
    sys.frozen, sys._MEIPASS = True, meipass
before = ctypes.util.find_library
import voice
print(repr(voice.sounddevice and voice.sounddevice.LIB), ctypes.util.find_library is before, voice.SOUND_ERR or "-")
"""

STUB = """from ctypes.util import find_library as _find_library     # what the real sounddevice does
LIB = _find_library("portaudio")
if LIB is None:
    raise OSError("PortAudio library not found")
"""

tmp = tempfile.mkdtemp()
meipass, stubs = os.path.join(tmp, "_MEI123"), os.path.join(tmp, "stubs")
os.makedirs(meipass); os.makedirs(stubs)
lib = os.path.join(meipass, "libportaudio.so.2")
open(lib, "wb").close()
open(os.path.join(stubs, "sounddevice.py"), "w").write(STUB)


def run(frozen):
    out = subprocess.run([sys.executable, "-c", CHILD, ROOT, meipass, stubs, frozen], cwd=tmp,
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


got = run("1")
assert got == f"{lib!r} True -", got
print("PASS frozen build: sounddevice gets the packed libportaudio.so.2; find_library is restored afterwards")

got = run("0")
assert got.startswith("None True PortAudio library not found"), got
print("PASS from source without PortAudio: voice is off and the window can say why")
print("ALL VOICE LIB TESTS PASSED")
