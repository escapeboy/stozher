# The kernel image — one static binary, and nothing else in the runtime layer.
#
# ADR-0003 fixes the shape: a single static binary, `docker compose` stays two services, and every
# dependency is a line on a security questionnaire. That argument does not stop at the crate
# manifest. A runtime image with a package manager, a shell toolchain and a scripting language in it
# is a larger attack surface than the program it exists to run, so this one has the binary, a CA
# bundle, and a data directory — literally those, and nothing else.
#
# The runtime stage is `scratch`, and that is the sentence above being true rather than aspirational.
# It used to be `alpine`, which ships busybox and apk: `/sbin/apk` and eighty-odd binaries in `/bin`,
# every one of them a shell toolchain and a package manager sitting inside an image whose stated
# design was to have neither. The binary is statically linked against musl and needs no loader, no
# libc and no /etc/passwd, so nothing had to be given up to remove them.
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

# Asserted here rather than discovered at `docker run`, where the symptom would be a container that
# exits immediately with no output. `scratch` has no dynamic loader, so a binary that acquired one —
# a dependency that turned off `crt-static`, a build that picked up the gnu target — has to fail the
# build instead of the deployment.
RUN ldd target/release/stozher-kernel 2>&1 \
      | grep -qE 'Not a valid dynamic program|not a dynamic executable|statically linked' \
    || { echo "stozher-kernel is not statically linked; the scratch runtime stage cannot run it" >&2; exit 1; }

# The CA bundle is taken from the build stage rather than installed into the runtime one, which is
# the whole trick: `apk` runs here, in a layer that is thrown away, and never exists in the image
# that ships. `/etc/stozher` is made here for the same reason — `scratch` has no `mkdir` to run.
RUN apk add --no-cache ca-certificates && mkdir -p /empty/etc/stozher

# ---- runtime -------------------------------------------------------------------------------
FROM scratch

# TLS trust roots, for the notification adapter's outbound webhook (ADR-0002's three channels).
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# The mount point for `kernel-config.json`. Docker would create it at run time anyway; having it in
# the image means the container's filesystem is fully described by this file rather than half by the
# compose file.
COPY --from=build /empty/etc/stozher /etc/stozher

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
