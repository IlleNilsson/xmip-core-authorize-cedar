# xmip-core-authorize-cedar

Authorization by a Cedar policy set evaluated with the Cedar engine: the identity is the principal, the attempt's action and artifact the action and the resource, the facts the context; an explicit forbid is a denial, no matching policy no opinion. A technology of [xmip-core-authorize](https://github.com/IlleNilsson/xmip-core-authorize).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
