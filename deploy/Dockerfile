# The kernel image — one static binary, and nothing else in the runtime layer.
#
# ADR-0003 fixes the shape: a single static binary, `docker compose` stays two services, and every
# dependency is a line on a security questionnaire. That argument does not stop at the crate
# manifest. A runtime image with a package manager, a shell toolchain and a scripting language in it
# is a larger attack surface than the program it exists to run, so this one has the binary, a CA
# bundle, and a data directory.
#
# The build context is the repository root: the console's templates live in `console/` and askama
# compiles them into the binary (`kernel/stozher-kernel/askama.toml`), so both trees have to be
# present in the same relative positions the workspace expects.

# ---- build ---------------------------------------------------------------------------------
FROM rust:1.97-alpine AS build

# `musl-dev` is the C toolchain `ring` and the bundled SQLite need. Alpine is already musl, so the
# host target *is* the static target — no cross-compilation, no second linker to reason about.
RUN apk add --no-cache musl-dev

WORKDIR /src
COPY kernel/ kernel/
COPY console/ console/

WORKDIR /src/kernel
# `--locked` refuses to resolve a dependency the lockfile does not name. A release build that
# quietly picked up a different version of a crypto crate than the one the test suite ran against
# would defeat the point of having a lockfile in an audit product.
RUN cargo build --release --locked --bin stozher-kernel \
    && strip target/release/stozher-kernel

# ---- runtime -------------------------------------------------------------------------------
FROM alpine:3.22

# TLS trust roots, for the notification adapter's outbound webhook (ADR-0002's three channels).
# Nothing else is installed.
RUN apk add --no-cache ca-certificates \
    && mkdir -p /var/lib/stozher /etc/stozher

COPY --from=build /src/kernel/target/release/stozher-kernel /usr/local/bin/stozher-kernel

# The compose file pins `user:` to the operator's own uid so that a bind-mounted seed at mode 0600
# is readable by exactly one account on both sides of the boundary. `keys::require_owner_only`
# refuses to start on anything more permissive (§09 §8), which is the check that makes this matter.
WORKDIR /var/lib/stozher
VOLUME ["/var/lib/stozher"]
EXPOSE 8787

# `await-health` is the kernel's own client, so the health check needs no curl, no wget and no
# shell — one more tool that does not have to exist in the image.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=5 \
    CMD ["stozher-kernel", "await-health", "--url", "http://127.0.0.1:8787", "--timeout", "3"]

ENTRYPOINT ["stozher-kernel"]
CMD ["serve", "--config", "/etc/stozher/kernel-config.json"]
