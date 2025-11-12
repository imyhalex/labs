# Labs

A collection of small systems and C programming labs and exercises. These labs focus on low-level programming concepts (C, Makefiles, and shell tooling) and are intended for learning, experimentation, and assessment.

## Goals

- Teach foundational C programming and systems concepts.
- Provide short, focused exercises with clear build and test steps.
- Encourage reproducible builds using Makefiles and simple scripts.
- Maintain readable, testable, and small code examples suitable for learning and review.

## Repository layout (top-level)

- nyush/               — a mini shell implementation (source, Makefile, samples)
- nyuenc/              — a simple file encryption/encoding exercise
- nyufile/             — a FAT32 / disk-image file-manipulation lab
- nyuc/                — small utilities and argument-manipulation helpers
- other top-level files: Makefiles, archives, small metadata files
---

## Lab summaries

### nyush — mini shell
What it is
- A small POSIX-like shell implemented in C.
- Provides a hands-on exercise covering parsing, process creation and management, and I/O redirection.

Key files
- nyush/nyush.c — principal source file implementing the shell
- nyush/Makefile — build/test targets
- nyush/nyush    — compiled executable included in the repo
- nyush/sampledir1, sampledir2 — example directories for testing
- nyush/input.txt, nyush/output.txt — sample input/output files

How to build and run
- Build: cd nyush && make
- Run: ./nyush
- Typical use: run simple commands, use redirections and pipes (behavior implemented depends on the code in nyush.c).
- Tests: use the sample input/output and provided zip if present, or run automated tests if the Makefile includes a `test` target.

Notes
- The directory also contains a packaged zip of the lab and object files for reference.
- The autograder for this lab (nyush-autograder) contains inputs and reference outputs for automated evaluation.

---

### nyuenc — simple file encoder/encrypter
What it is
- An exercise that implements file encoding/encryption and related I/O patterns in C.
- Useful for practicing reading/writing binary files, command-line parsing, and buffer management.

Key files
- nyuenc/nyuenc.c — main source implementing the encoder/decoder
- nyuenc/Makefile
- nyuenc/file.txt, file1.txt — small plaintext test files
- nyuenc/file.enc, file2.enc — sample encoded outputs included for reference
- nyuenc/perf.data, nyuenc/strace.txt — data gathered during profiling/tracing (useful for performance/debug analysis)
- nyuenc/nyuenc — compiled executable and a zip package

How to build and run
- Build: cd nyuenc && make
- Run examples: typical usage is to encode or decode files from the command line (see nyuenc.c's help/usage text, or run `./nyuenc` with no args if the program prints usage).
- Tests: compare produced .enc/.txt outputs against the provided sample files, or use the autograder bundle for automated checks.

Notes
- The presence of perf and strace outputs suggests this lab was profiled; they are useful references for performance or system-call behavior discussions.

---

### nyufile — FAT32 / disk-image file tool
What it is
- A lab that interacts with a disk image (fat32.disk) to implement or exercise basic filesystem operations (listing files, reading file contents, etc).
- Great for practicing low-level file I/O, working with on-disk structures, and implementing parsing of filesystem metadata.

Key files
- nyufile/nyufile.c — main source for interacting with the FAT32 image
- nyufile/Makefile
- nyufile/fat32.disk — a FAT32 disk image used as test input
- nyufile/nyufile — compiled executable and a zip package

How to build and run
- Build: cd nyufile && make
- Run: typical commands will take the disk image as an argument (for example, `./nyufile fat32.disk <operation> <args>`); check the program's usage printed when run with no arguments.
- Tests: exercise operations against fat32.disk and compare results with expected outputs or use the autograder package.

Notes
- The disk image is present in the repository to make testing reproducible without external resources.

---

### nyuc — small utilities and argument-manipulation helpers
What it is
- A small collection of utilities for argument manipulation and helper functions used in other labs.
- Good focused practice on modular code, headers, and creating reusable components.

Key files
- nyuc/argmanip.c, nyuc/argmanip.h — argument manipulation helpers
- nyuc/nyuc.c — small utility program(s)
- nyuc/Makefile

How to build and run
- Build: cd nyuc && make
- Run: execute the produced binaries in `nyuc/` and inspect behavior, or include these helpers when building other labs that depend on them.

Notes
- This directory contains small building blocks that may be referenced from other labs or used for testing.

