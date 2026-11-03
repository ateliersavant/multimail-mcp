# Adversarial review tests

An independent agent reviewed the server adversarially and had to prove each finding with a failing test. These are those tests. Each one asserted the safe behaviour and failed on the code as it was; every one now passes, and they run with the rest of the suite as regression tests.

Each file's header comment describes the weakness as it was found, so the comments use the past state of the code. The fixes and their reasoning are summarised in [docs/security-review.md](../../docs/security-review.md).

Run them on their own:

```bash
npm run test:adversarial
```
