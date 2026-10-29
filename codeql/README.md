# CodeQL Queries

This pack contains two C/C++ queries for bug patterns related to the two HAProxy QUIC issues.

- `IgnoredDecoderReturn.ql` finds ignored results from functions whose bodies establish a 0/1 failure contract and whose parameters permit indirect output updates. It does not use function names.
- `UncheckedUnsignedLengthSubtraction.ql` finds range-unproven subtraction that flows into a `size_t` argument or subtracts from a computed pointer offset. It does not depend on a specific callee or protocol.

Both queries are medium-precision review queries. They model general failure-contract and size or pointer safety bugs instead of the two exact HAProxy expressions.

## Run Tests

Use a CodeQL CLI bundle that includes the C/C++ extractor and libraries:

```sh
codeql pack install codeql
codeql pack install --additional-packs=codeql codeql/tests
codeql test run --additional-packs=codeql codeql/tests
```

## Analyze a Database

Create a C/C++ database for the target project, then run both queries:

```sh
codeql database analyze /path/to/database codeql/queries \
  --format=sarif-latest --output=codeql-results.sarif
```

Treat each unsigned-subtraction result as a request for contract review. Confirm whether a dominating check proves the required minimum length.
