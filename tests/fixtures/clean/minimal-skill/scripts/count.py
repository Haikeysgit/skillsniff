"""Print the line, word and character counts of a text file."""

import sys


def count(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    return len(text.splitlines()), len(text.split()), len(text)


def main():
    if len(sys.argv) != 2:
        print("usage: count.py <path>")
        return 2
    lines, words, chars = count(sys.argv[1])
    print(f"lines: {lines}")
    print(f"words: {words}")
    print(f"characters: {chars}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
