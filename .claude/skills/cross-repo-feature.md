# Cross-Repo Feature Implementation Guide

You are implementing a feature that affects multiple edictum repos. This repo (edictum-go) is a PORT — Python is the reference implementation.

## Step 1: Check the Reference

Before writing code, check the Python implementation:

```bash
# What does the Python version look like?
ls ../edictum/src/edictum/
# What tests exist?
ls ../edictum/tests/test_behavior/
```

## Step 2: Check Shared Fixtures

Verify behavioral fixtures exist for this feature:

```bash
ls ../edictum-schemas/fixtures/behavioral/
ls ../edictum-schemas/fixtures/adversarial/
```

If fixtures don't exist, **they must be created in edictum-schemas first** before porting. The fixtures are the parity spec — they define "correct behavior."

## Step 3: Implement the Port

1. Match the Python API surface (use Go naming conventions: exported funcs, PascalCase)
2. Write Go-native tests with `TestFeature` prefix
3. Write security tests with `TestSecurity` prefix
4. Verify shared fixtures pass
5. Run full suite: `go test ./... && go test -race ./...`
6. Create PR referencing the tracking issue

## Step 4: Fixture Runner

Run shared fixtures against your implementation:

```bash
go test -run "TestBehavioralFixtures" ./...
```

If the fixture runner doesn't exist yet, create it in `behavioral_fixtures_test.go`.

## Step 5: Cross-Repo Issues

If you find a bug that exists in multiple repos, file ONE issue in `edictum-ai/.github` with the `cross-repo` label.

## Checklist Before Merging

- [ ] Shared fixtures pass
- [ ] Python parity verified (same inputs → same outputs)
- [ ] Go-native tests written
- [ ] Security tests with `TestSecurity` prefix
- [ ] Race detector passes: `go test -race ./...`
- [ ] Terminology matches `.docs-style-guide.md`
- [ ] Tracking issue updated with PR link
