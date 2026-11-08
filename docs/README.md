# Documentation

This directory holds the architecture, design, and decision records for `paseo-permission-guardian`.

## Layout

```text
docs/
  README.md          # Documentation index and conventions (this file)
  DESIGN.md          # Living system design specification
  adr/
    README.md        # Architecture Decision Records index
    0000-template.md # Standard ADR template
    NNNN-*.md        # Numbered Architecture Decision Records
```

## Conventions

1. **Living design (`DESIGN.md`)**: Describes the current target architecture, module boundaries, contracts, and milestones. Update `DESIGN.md` when the design evolves; bump its version/status header accordingly.
2. **Architecture Decision Records (`docs/adr/`)**: Any significant architectural, security, API-contract, or trade-off decision **must** be recorded as an ADR before or alongside implementation.
   - ADRs are immutable once `Accepted`. To reverse or revise a decision, add a new ADR that sets `Supersedes: ADR-XXXX` and update the older ADR's status to `Superseded by ADR-YYYY`.
   - Use zero-padded 4-digit numbers (`0001`, `0002`, ...) and kebab-case titles.
   - Start from [0000-template.md](./adr/0000-template.md) and register every new ADR in [adr/README.md](./adr/README.md).
3. **Plugin listing overview (`OVERVIEW.md`)**: Kept at the repository root beside `paseo-plugin.json` per the Paseo plugin registry contract. It is user-facing and separate from internal engineering docs here.

## Key Documents

- [System Design (v0.2)](./DESIGN.md)
- [Architecture Decision Records](./adr/README.md)
