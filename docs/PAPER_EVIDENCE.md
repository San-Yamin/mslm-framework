# Evidence plan for the paper

This document distinguishes implemented evidence from claims requiring an external
experiment. It should be used to complete Sections VII-C and VII-D after execution.

## Section VII-C — MSLM defense effectiveness

Report, for every chain:

- fixed iteration count and random seed;
- attack variation method;
- expected first blocking layer;
- blocked trials and unexpected approvals;
- block rate with a binomial confidence interval;
- negative controls showing legitimate traffic is accepted;
- exact framework commit and generated `experiment.json`.

Suggested wording:

> In a controlled synthetic evaluation, each attack chain was executed N times.
> MSLM blocked X/N C1 attempts at L1, ... . These results demonstrate enforcement
> against the encoded threat scenarios; they do not establish effectiveness
> against unknown attacks or production mini-apps.

Do not write “100% prevention proven.” A finite test can show a 100% observed block
rate for defined trials, not universal prevention.

## Section VII-D — performance overhead

Report median, p95 and p99, not only the mean. Include:

- CPU and operating system;
- Python version;
- warm-up policy;
- number of iterations;
- whether network, TLS and database latency are included;
- baseline request measurement using the same harness;
- absolute latency and percentage overhead with confidence intervals.

The bundled benchmark is a local microbenchmark and excludes network, database and
TLS overhead. It must not be described as end-to-end payment throughput.

## Required external Juice Shop work

The current code does not prove that OWASP Juice Shop v20.0.0 was tested. To retain
that paper claim, preserve:

1. container image digest and configuration;
2. lawful isolated test environment;
3. attack scripts or Burp exports;
4. mapping from each Juice Shop behavior to V1–V6;
5. baseline and defended traces;
6. timestamps, exit status and sanitized logs;
7. statistical analysis script.

If those artifacts do not exist, change the paper to say that the Python harness
uses synthetic controlled scenarios inspired by the taxonomy.

## Corrections needed in the current manuscript

- Table III average CCRS is not 9.91. The four raw scores are approximately
  9.30, 8.67, 9.22 and 9.95, whose arithmetic mean is approximately 9.28.
- Section IV-B's formula yields “at least one succeeds” under independence; “by
  extension the chain succeeds” is not mathematically justified for sequential
  all-step chains.
- “More accurate” needs a ground-truth outcome and validation method. Until then,
  prefer “assigns higher cumulative severity than maximum CVSS.”
- The manuscript says C4 is capped at 9.8 “per Section IV.B,” but that section
  currently defines no cap. Define and justify the cap or report uncapped values.
- Replace blank test iterations and empty Sections VII-C/VII-D only with generated
  results from preserved runs.

