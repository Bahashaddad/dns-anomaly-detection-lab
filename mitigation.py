"""Reversible sandbox hosts-file experiment; never touches the OS hosts file."""

from pathlib import Path
from contextlib import contextmanager
from rules import normalize_domain


class SandboxHosts:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.path = self.directory / "hosts.preview"
        self.backup = self.directory / "hosts.preview.before"
        self.lock = self.directory / "hosts.preview.lock"

    @contextmanager
    def _acquire(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        if self.directory.is_symlink() or any(
            p.is_symlink() for p in (self.path, self.backup, self.lock)
        ):
            raise ValueError("Sandbox symlinks are not supported")
        handle = self.lock.open("x", encoding="utf-8")
        try:
            yield
        finally:
            handle.close()
            self.lock.unlink(missing_ok=True)

    def add(self, domain):
        domain = normalize_domain(domain)
        # Observation names may contain underscores; hosts mappings may not.
        if "_" in domain or any(
            label.startswith("-") or label.endswith("-") for label in domain.split(".")
        ):
            raise ValueError("Name is not suitable for a hosts mapping")
        with self._acquire():
            previous = (
                self.path.read_text(encoding="utf-8") if self.path.exists() else ""
            )
            if not self.backup.exists():
                with self.backup.open("x", encoding="utf-8") as handle:
                    handle.write(previous)
            names = {
                line.split()[1]
                for line in previous.splitlines()
                if len(line.split()) >= 2 and not line.lstrip().startswith("#")
            }
            if domain not in names:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(
                        ("" if not previous or previous.endswith("\n") else "\n")
                        + "127.0.0.1 "
                        + domain
                        + "\n"
                    )

    def restore(self):
        with self._acquire():
            if not self.backup.exists():
                raise FileNotFoundError("No sandbox backup exists")
            self.path.write_text(
                self.backup.read_text(encoding="utf-8"), encoding="utf-8"
            )
            self.backup.unlink()


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sandbox", type=Path, required=True)
    parser.add_argument("--restore", action="store_true", required=True)
    args = parser.parse_args()
    SandboxHosts(args.sandbox).restore()
    print("Sandbox preview restored. No operating-system hosts file was changed.")


if __name__ == "__main__":
    main()
