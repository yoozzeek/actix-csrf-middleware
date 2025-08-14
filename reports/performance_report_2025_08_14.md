# Performance Report - actix-csrf-middleware v0.4.0

*Generated: 2025-08-14*

## Test Results Summary

✅ **All tests passing**: 62/62 test cases passed across all feature sets

- Unit tests: 2/2 passed
- Double Submit Cookie tests: 20/20 passed
- Synchronizer Token tests: 19/19 passed
- OWASP A01 Access Control tests: 6/6 passed
- OWASP A02 Crypto Failures tests: 7/7 passed
- OWASP A03 Injection tests: 8/8 passed

## Benchmark Results

### Token Generation Performance

#### CSRF Token Generation

- **Time**: ~60.1 ns per token
- **Performance**: Consistent with minimal variation (±2.1%)
- **Stability**: 96% of measurements within expected range

#### HMAC Token Operations

- **Generation**: ~61.5 ns per token
- **Validation (valid)**: ~989 ns per validation
- **Validation (invalid)**: ~1.0 µs per validation

### Token Comparison Performance

- **Matching tokens**: ~40.7 ns
- **Non-matching tokens**: ~39.6 ns

## HTTP and Memory Performance Analysis

### Double Submit Cookie Pattern

- **Request throughput**: **239,750 requests/second**
- **Total memory allocated**: 901 MB for 200,000 requests (100k GET + 100k POST)
- **Net memory usage**: Only 11.6 KB steady state
- **Memory efficiency**: 99.999% of allocated memory is properly deallocated
- **Test duration**: 834ms for 200,000 requests

### Synchronizer Token Pattern (with Sessions)

- **Request throughput**: **182,430 requests/second**
- **Total memory allocated**: 1.35 GB for 200,000 requests
- **Net memory usage**: Only 6.1 KB steady state
- **Memory efficiency**: 99.999% of allocated memory is properly deallocated
- **Test duration**: 1.1 seconds for 200,000 requests

### Pattern Comparison

| Metric                    | Double Submit Cookie | Synchronizer Token         | Winner        |
|---------------------------|----------------------|----------------------------|---------------|
| Throughput                | 239,750 req/sec      | 182,430 req/sec            | Double Submit |
| Memory Efficiency         | 99.999%              | 99.999%                    | Tie           |
| Net Memory Usage          | 11.6 KB              | 6.1 KB                     | Synchronizer  |
| Implementation Complexity | Lower                | Higher (requires sessions) | Double Submit |

*Apple M3 Max*