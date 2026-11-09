#!/usr/bin/python3
import os
import socket
import tempfile

MARKER = b"SENTINEL_LOOPBACK_OK"

def launch(executable, command=None, connection=None):
    child = os.fork()

    if child == 0:
        try:
            if connection is not None:
                connection.settimeout(None)
                for fd in (0, 1, 2):
                    os.dup2(connection.fileno(), fd)

            argv = [os.path.basename(executable)]
            if command is not None:
                argv += ["-c", command]

            os.execv(executable, argv)
        except OSError:
            os._exit(127)

    _, status = os.waitpid(child, 0)
    if status != 0:
        code = os.waitstatus_to_exitcode(status)
        raise RuntimeError(f"Test process exited with {code}")

with tempfile.TemporaryDirectory(prefix="sentinel-demo-") as directory:
    def alias(case, binary):
        folder = os.path.join(directory, case)
        os.mkdir(folder)
        path = os.path.join(folder, os.path.basename(binary))
        os.symlink(binary, path)
        return path

    normal = alias("normal", "/usr/bin/true")
    shell = alias("shell", "/bin/sh")
    network = alias("loopback", "/bin/sh")

    with open("/proc/self/comm") as stream:
        print("DEMO parent=" + stream.read().strip(), flush=True)

    print(
        f"CASE normal expected_file={normal!r}; expected=no alert",
        flush=True
    )
    launch(normal)

    print(
        f"CASE shell expected_file={shell!r}; expected=shell alert",
        flush=True
    )
    launch(shell, "exit 0")

    print(
        f"CASE loopback expected_file={network!r}; expected=shell alert",
        flush=True
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)

        with socket.create_connection(
                listener.getsockname(), timeout=3) as connection:
            launch(network, "printf SENTINEL_LOOPBACK_OK", connection)

        peer, _ = listener.accept()
        with peer:
            peer.settimeout(3)
            received = b""

            while len(received) < len(MARKER):
                chunk = peer.recv(len(MARKER) - len(received))
                if not chunk:
                    break
                received += chunk

        if received != MARKER:
            raise RuntimeError(f"Unexpected loopback output: {received!r}")

    print("LOOPBACK MARKER RECEIVED: OK", flush=True)

print("Demo cases finished; temporary files removed.", flush=True)
