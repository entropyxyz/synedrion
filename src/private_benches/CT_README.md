## Constant-Time Benchmarks

This directory contains benchmarks designed to assess the constant-time behavior of `synedrion` code using the Dudect method ([https://eprint.iacr.org/2016/1123.pdf](https://eprint.iacr.org/2016/1123.pdf)). Dudect employs [Welch's t-test](https://en.wikipedia.org/wiki/Welch%27s_t-test) to statistically analyze execution time differences between "normal" and "special" input classes.

### Methodology

1. **Input Generation:** Two input classes are created: "normal" (random) and "special" (potentially triggering timing variations).
2. **Timing Measurement:** Execution time of the target code is measured for each input.
3. **Statistical Analysis:** Welch's t-test is applied to compare the execution time distributions of the two classes. The "max t" statistic is computed.

### Interpretation

A small absolute value of "max t" suggests that execution times for the two input classes are similar, indicating potential constant-time behavior.  A threshold of `|max t| >= 5` is often used to flag non-constant-time behavior. However, constant-time analysis can be complex, and a high "max t" value might not always indicate a practically exploitable timing leak.

### Running Benchmarks

Execute benchmarks using:

```bash
`cargo run --example dudect --release -F "private-benches dudect-bencher"`
```

For continuous testing until manual interruption, use:

```bash
`cargo run --example dudect --release -F "private-benches dudect-bencher"` -- --continuous <benchmark-name>
```

The benchmarks provide an estimate of the number of samples required to reach the `|max t| = 5` threshold. For truly constant-time code, this threshold should never be reached.
