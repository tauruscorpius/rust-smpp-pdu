# rust-smpp-pdu

An [SMPP](https://smpp.org/) PDU parsing library for Rust.

Designed to be used with https://gitlab.com/andybalaam/rust-smpp - see there for
more information.

## Build

First, [install Rust](https://www.rust-lang.org/tools/install).

```bash
cargo test
```

## Publish

```bash
cargo update
vim CHANGELOG.md   # Set the version number
cargo publish
git tag $VERSION
git push --tags
```

## Code of conduct

We follow the [Rust code of conduct](https://www.rust-lang.org/conduct.html).

Currently the moderation team consists of Andy Balaam only.  We would welcome
more members: if you would like to join the moderation team, please contact
Andy Balaam.

Andy Balaam may be contacted by email on andybalaam at artificialworlds.net or
on mastodon on
[@andybalaam@mastodon.social](https://mastodon.social/web/accounts/7995).

## License

rust-smpp-pdu is distributed under the terms of both the [MIT
license](LICENSE-MIT) and the [Apache License (Version 2.0)](LICENSE-APACHE).

This project is developed in both my work and personal time, and released under
my personal copyright with the agreement of my employer.
