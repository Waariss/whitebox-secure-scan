import subprocess


def run(request):
    command = ["/usr/bin/id"]
    return subprocess.run(command, shell=False, check=True, timeout=2)
