# AFL++ Fuzzing for QC-MDPC Decoder

## Setup

```bash
# Build the fuzzer
cargo afl build --release -p arcb-fuzz --bin fuzz_decoder

# Run fuzzing (8 cores, 1 hour timeout per input)
cargo afl fuzz -i fuzz/corpus -o fuzz/output -t 1000 -- target/release/fuzz_decoder

# Or with multiple parallel instances
cargo afl fuzz -i fuzz/corpus -o fuzz/output -M fuzzer01 -t 1000 -- target/release/fuzz_decoder &
cargo afl fuzz -i fuzz/corpus -o fuzz/output -S fuzzer02 -t 1000 -- target/release/fuzz_decoder &
```

## What It Tests

1. **Stego unpack**: Feeds arbitrary digit streams to `stego::unpack()`.
   - Checks for panics, OOB reads, infinite loops.

2. **Decoder**: Feeds unpacked masks to `black_gray_decode()`.
   - Checks for infinite loops (decoder stuck).
   - Checks for crashes on pathological matrices.

3. **Full pipeline**: Feeds digits through `decapsulate()`.
   - Tests the complete decode + decrypt path.

## Expected Issues

Without girth filtering, the decoder may encounter:
- **Stuck decoder**: Some matrices cause the bit-flipping to oscillate.
  The MAX_ITER=500 limit prevents true infinite loops.
- **Slow decoding**: Some inputs may take many iterations.
  AFL++ timeout (default 1s) catches these.

## Output Interpretation

- `fuzz/output/fuzzer01/crashes/`: Inputs that caused crashes.
- `fuzz/output/fuzzer01/hangs/`: Inputs that exceeded timeout.
- `fuzz/output/fuzzer01/queue/`: Interesting inputs found.
