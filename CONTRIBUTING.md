# Contributing

Thank you for helping. This repository is a **one-way mirror**: the SDK is
developed alongside the Prosentriq control plane in a private repository, where
the two are tested together, and published here with each release.

- **Issues** are welcome here: bugs, questions and ideas.
- **Pull requests** are welcome too, but they aren't merged on GitHub. A
  maintainer applies your change to the private repository, credits you with a
  `Co-authored-by:` trailer, and it appears here with the next release. We'll
  close your pull request with a link to the release that contains it.

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), like the rest of this repository.

Before you open a pull request:

- Keep the SDK small: it runs on customer hosts and appliances, so new runtime
  dependencies need a strong reason.
- Don't break the event schema. Fields may be added; existing ones keep their
  meaning.
- Follow PEP 8.

Security problems: please don't open an issue. See the
[security policy](https://github.com/PROSENTRIQ/.github/blob/main/SECURITY.md).
