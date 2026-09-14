# Security policy

## Project status

MSLM v0.2.0 is a research prototype for controlled experiments. It is not a
production payment gateway and has not been independently validated for use in
live financial systems.

Production adaptation would require, at minimum, managed key storage (KMS or
HSM), a shared durable and atomic replay store, authenticated service-to-service
transport, operational monitoring, independent security review, and testing on
representative mini-app platforms.

## Reporting a vulnerability

Please do not publish an unpatched vulnerability or real financial-system data
in a public issue. Contact the maintainer privately through the email address
listed in the accompanying paper, including reproduction steps and expected
impact. Test only systems for which you have explicit authorization.
