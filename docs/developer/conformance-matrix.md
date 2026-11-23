---
title: Conformance matrix
---

# Conformance matrix

This page maps every row of the [v3 feature checklist](chisel-v3-compatibility.md#fixture-seed-and-feature-to-test-checklist),
every intentional Vapor policy and every recorded ambiguity to the Vapor tests that
exercise it.

The mapping is enforced by `internal/conformance/matrix_test.go`, a test-only package
with no non-test files, so none of it reaches the `vaporize` binary. `go test` fails
when a named test does not exist, when an ID is repeated, when a status is unknown, or
when the checklist grows a row this matrix does not cover. A mapping nobody checks rots
in a month; this one cannot rot silently, and it costs the shipped binary nothing.

## On this page

- What a row status means
- Blockers
- Feature checklist rows
- Debian provider coverage
- Intentional Vapor policies
- Recorded ambiguities
- Other external authorities
- What this matrix does not claim

## What a row status means

| Status | Meaning |
| --- | --- |
| `covered` | Named Vapor tests exercise the behavior. This is Vapor evidence, not upstream evidence. |
| `blocked` | The behavior needs evidence that does not exist yet. The blocker is named, and the listed tests do not satisfy it. |
| `unsupported` | Vapor refuses the feature by name. The refusal is tested; the feature itself is out of scope and no compatibility is claimed. |
| `resolved` | An ambiguity with a recorded decision. The decision is a Vapor rule, and the tests cover it. |

No row is `covered` on the strength of fixture integrity, parser acceptance or reading
upstream source. Those are inputs to a test, never evidence of conformance.

## Blockers

Both blockers are stated here rather than hidden behind a status word.

- **Native-v3 execution (9.3.1).** No upstream binary or upstream test suite has been
  executed. Every `covered` row proves what Vapor does; none proves that Vapor matches
  upstream's output for the same input. That comparison needs separately authorized
  acquisition of the pinned upstream inputs and an offline replay, and it is the only
  evidence that can authorize a full-compatibility claim.
- **Store success (6.10.1).** Store-backed packages are parsed, validated and
  refused at selection with the store, kind and track named. Acquiring and extracting a
  store blob has no reviewed contract, so no store-success case exists and none may be
  inferred from the refusal tests.

## Feature checklist rows

The checklist has thirteen rows. IDs are stable: add a row when the checklist grows
rather than renumbering.

| ID | Checklist row | Status | Vapor tests |
| --- | --- | --- | --- |
| R01 | v3-only root, unknown/duplicate/extra docs, legacy fields rejected | covered | `TestParseCatalogue_Formats`, `TestParseCatalogue_StrictDocuments`, `TestParseCatalogue_RejectsInterpolation`, `TestParsePackagesDocumentErrors`, `TestParsePackagesRejectsInterpolation`, `TestStarter_PinnedSyntheticSelection` |
| R02 | Archive priority bounds/uniqueness/mixed omission, negative pins, no fallback, version ties, ordered suites and components | covered | `TestParseCatalogue_Priorities`, `TestParseCatalogue_ArchiveFields`, `TestSelectPackageOriginsArchiveRanking`, `TestSelectPackageOriginsPinnedArchiveAndNegativePriority`, `TestSelectPackageOriginsExactPinDoesNotSwitchArchive`, `TestBindArchivesRejections`, `TestBindArchivesDeterministicOrder` |
| R03 | Maintenance dates/defaults and warning-only EOL/unstable, warnings outside digests | covered | `TestParseCatalogue_Maintenance`, `TestProvider_ReleaseWarnings`, `TestMaintenance_Warnings` |
| R04 | Key ID/armor consistency versus independent full-fingerprint trust, selected Pro credentials only, tamper/size/freshness/cache replay | covered | `TestParseCatalogue_PublicKeys`, `TestVerifyRepositoriesInRelease`, `TestVerifyRepositoriesDetachedRelease`, `TestVerifyRepositoriesRejectsWrongSigner`, `TestVerifyRepositoriesRejectsTamperedEvidence`, `TestVerifyRepositoriesRejectsOversizedEvidence`, `TestVerifyRepositoriesReplaysExpiredSignature`, `TestVerifyRepositoriesReplaysOldExpiry`, `TestVerifyRepositoriesRedactsCachePath`, `TestSnapshotRejectsPrivateTrustKey`, `TestSnapshotRejectsPrivateAndInvalidCertificates`, `TestSelectedProSliceUsesAuthenticatedFetcher`, `TestSkipArchiveDefersUnselectedRestrictedSources`, `TestDefaultTrustRecordsAndStoresKeys`, `TestStoreReplacesPoisonedBlob`, `TestOpenRejectsMismatchedBlob` |
| R05 | Starter selection/closure, package-self omission, explicit-self/duplicates/missing refs/cycles, native arch filtering | covered | `TestSelectSlicesStarterClosure`, `TestSelectSlicesOmitsPackageSelfAndIsOrderIndependent`, `TestSelectSlicesErrors`, `TestSelectSlicesRejectsWholeOverlap`, `TestSelectSlicesRejectsTransitiveWholeOverlap`, `TestSelectSlicesArchitectureFilter`, `TestStarter_PinnedSyntheticSelection`, `TestSelectSlicedPackagesUsesNativeArchitecture` |
| R06 | Hints 40/41 bytes/nonprintable, scalar/list arch, nonmatching/invalid arch policies | covered | `TestParsePackagesHintsAndNames`, `TestParsePackagesEssentials`, `TestParseContentsErrors`, `TestApplyContent_ArchFilterSkipsDeclarations`, `TestApplyContent_GlobRespectsArchitecture`, `TestApplyContent_PreferenceIgnoresFilteredArchitecture` |
| R07 | Path kinds/empty text/clean keys, copied source/modes, explicit/implicit parents, hard links, missing matches | covered | `TestParseContentsKinds`, `TestParseContentsErrors`, `TestApplyContent_CopiesFiles`, `TestApplyContent_CopiesSymlinkWithoutFollowingIt`, `TestApplyContent_PreservesSourceHardLinks`, `TestApplyContent_CopiesSpecialBits`, `TestApplyContent_EmptyTextIsMeaningful`, `TestApplyContent_MakeDirectoryDefaults`, `TestApplyContent_ExplicitParentOverridesImplicit`, `TestApplyContent_RejectsFileAncestorOfDeclaration`, `TestApplyContent_DirectorySelectionIsNotRecursive`, `TestApplyContent_DoesNotMutateSource` |
| R08 | Glob ?/*/**, arch/until and forbidden options, cross-package conflict/preference chains/subset winners/cycles | covered | `TestApplyContent_GlobExpansion`, `TestApplyContent_GlobExpansionIsDeterministic`, `TestApplyContent_GlobIsNotShellGlob`, `TestApplyContent_GlobUnmatchedPatternFails`, `TestApplyContent_GlobAppliesUntilToEveryMatch`, `TestApplyContent_GlobAndExactDeclarationConflict`, `TestApplyContent_GlobAndExactDeclarationConflictOnMode`, `TestApplyContent_ConflictingProvidersWithoutPreferenceFail`, `TestApplyContent_PreferenceDecidesBetweenSelectedProviders`, `TestApplyContent_PreferenceChainWinsAcrossSelection`, `TestApplyContent_PreferenceCycleFails`, `TestApplyContent_PreferenceNeverAddsAPackage`, `TestApplyContent_PreferenceDoesNotCoverGlobOverlap`, `TestApplyContent_PreferenceDoesNotOverrideMetadataDisagreement`, `TestApplyContent_PreferenceIgnoresUnselectedProvider`, `TestApplyContent_PreferenceToPackageWithoutPathKeepsDeclaration`, `TestApplyContent_PreferenceWithoutSelectedProviderKeepsDeclaration`, `TestApplyContent_SamePackageSlicesStillConflict`, `TestApplyContent_SamePackageSharedDeclarationKeepsBothOrigins`, `TestValidatePackagesPreferences`, `TestValidatePackagesPathConflicts`, `TestGlobIntersects`, `TestGlobIntersectsAdversarial` |
| R09 | Mutation read/write/list, selected cross-slice reads, order, immutable/unlisted/hard-link rejection, shared temporary cleanup | covered | `TestContentReadReturnsSelectedContent`, `TestContentWriteReturnsOnlyChangedFiles`, `TestContentListIsSortedAndMarksDirectories`, `TestContentRejectsImmutableAndCreatedWrites`, `TestContentRejectsUnselectedPaths`, `TestContentRejectsHardlinkWrites`, `TestMutateAppliesScriptsInOrder`, `TestMutateLaterScriptSeesEarlierWork`, `TestMutatePreservesUnrelatedContent`, `TestMutateRejectsInvalidInput`, `TestRunScriptsKeepsSharedTemporaryPaths`, `TestRunScriptsRemovesTemporaryContentAfterMutation`, `TestRunScriptsRemovesEmptyTemporaryDirectories`, `TestRunScriptsRemovesNestedTemporaryDirectoriesDeepestFirst`, `TestRunScriptsFailureKeepsTemporaryContent` |
| R10 | Escape/cycle confinement, allocation/output/VFS/time/step exhaustion, rollback and deterministic execution | covered | `TestResolve_EscapesAndCycles`, `TestResolve_ExpansionIsBounded`, `TestResolve_FollowsLinks`, `TestResolve_RelativeDotDotTargetIsAppliedToTheLinksParent`, `TestRunScriptEnforcesStepBudget`, `TestRunScriptEnforcesMemoryBound`, `TestRunScriptEnforcesReadAndWriteBounds`, `TestRunScriptEnforcesWallClock`, `TestRunScriptEnforcesCPUBound`, `TestRunScriptEnforcesContentGrowthBound`, `TestRunScriptDeniesHostAccess`, `TestRunScriptIsolatesTheWorker`, `TestRunScriptRejectsOversizedScript`, `TestAdversarialCasesAreComplete`, `TestAdversarialCasesTripTheirBound`, `TestAdversarialCumulativeGrowthFailsTheBuild`, `TestAdversarialOversizedMessageFailsTheBuild`, `TestMutateFailureLeavesTreeUnchanged`, `TestMutateCancellationLeavesTreeUnchanged`, `TestMutateWorkerDeathLeavesTreeUnchanged`, `TestRunScriptsIsDeterministic`, `TestContentHasNoHostOrNetworkPrimitives` |
| R11 | Store prefix/track/kind/collisions and bin-slices discovery, selected unsupported acquisition fails explicitly | covered | `TestParseCatalogue_Stores`, `TestParsePackagesDiscovery`, `TestSelectPackageOriginsStoreSelection`, `TestCheckPackagesStoreBackedPackageOffline`, `TestBindArchivesRejections` |
| R12 | Manifest JSONWall/zstd/schema/count/order, original/final hashes, self registration, hard links, post-cleanup attribution | unsupported | `TestApplyContent_RejectsGenerate` |
| R13 | Native-v3 filesystem/manifest comparison, all ambiguities resolved, deterministic permutations and explicit policy deviations | blocked | none; needs an upstream run |

R12 is `unsupported` because Vapor does not generate manifests at all:
`generate: manifest` appears once in the pinned catalogue, is not in the starter
closure, and no Vapor consumer reads it. Selecting it fails by name instead of producing
an image that quietly lacks the file the slice asked for.

R13 is `blocked` because every other row compares Vapor with Vapor. Upstream filesystem
and manifest results for the same inputs have never been recorded.

## Intentional Vapor policies

Each row of the [policy table](chisel-v3-compatibility.md#intentional-vapor-policies-versus-upstream-behavior)
is a deliberate deviation. A deviation is acceptable only when it is tested and
documented as a deviation, never when it is an accident.

| ID | Policy | Status | Vapor tests |
| --- | --- | --- | --- |
| P01 | v3 only, strict unknown/duplicate fields, single document, no interpolation | covered | `TestParseCatalogue_Formats`, `TestParseCatalogue_StrictDocuments`, `TestParseCatalogue_RejectsInterpolation`, `TestParsePackagesRejectsInterpolation`, `TestStarter_PinnedSyntheticSelection` |
| P02 | External full fingerprints, size checked before decompression, cache reverified | covered | `TestParseCatalogue_PublicKeys`, `TestVerifyRepositoriesRejectsWrongSigner`, `TestVerifyRepositoriesRejectsOversizedEvidence`, `TestAuditRejectsSizeMismatch`, `TestAuditRejectsIncompleteCatalogueManifest`, `TestVerifyRepositoriesAuthenticatesPackageSelections`, `TestAuditPayloadsChecksCachedBytes`, `TestOpenRejectsMismatchedBlob`, `TestStoreRejectsMismatch`, `TestStoreReplacesPoisonedBlob` |
| P03 | Freshness enforced on new locks, evidence replayed without today's expiry | covered | `TestVerifyRepositoriesReplaysExpiredSignature`, `TestVerifyRepositoriesReplaysOldExpiry` |
| P04 | EOL and unstable catalogues warn rather than reject | covered | `TestParseCatalogue_Maintenance`, `TestProvider_ReleaseWarnings`, `TestMaintenance_Warnings` |
| P05 | Only selected inputs need credentials, secrets never enter outputs | covered | `TestSelectedProSliceUsesAuthenticatedFetcher`, `TestSkipArchiveDefersUnselectedRestrictedSources`, `TestProviderProTrust`, `TestPackagesFetchFailureIsRedacted`, `TestVerifyRepositoriesRedactsBlobErrors` |
| P06 | Lock acquires every input, build never fetches or re-resolves | covered | `TestAuditCountsVerifiedBytes`, `TestSnapshotCachesDeclaredInputsAndCatalogues`, `TestPackagesPublishesVerifiedArchives`, `TestArtifactsPublishesIntendedPlatforms` |
| P07 | Bounded mutation, no maintainer-script execution, no host access | covered | `TestRunScriptEnforcesStepBudget`, `TestRunScriptEnforcesMemoryBound`, `TestRunScriptEnforcesWallClock`, `TestRunScriptDeniesHostAccess`, `TestContentHasNoHostOrNetworkPrimitives`, `TestCheckSandboxPlatformFailsClosed`, `TestAdversarialCasesTripTheirBound` |
| P08 | Epoch timestamps, deterministic traversal, serialization and inode identity | covered | `TestApplyContent_IsDeterministic`, `TestApplyContent_GlobExpansionIsDeterministic`, `TestRunScriptsIsDeterministic`, `TestGenerate_ValidSpecAndDeterministicBytes`, `TestDefinitionDigestVector`, `TestTree_OrderingPermutations`, `TestTree_InodesAreStableAndShared` |

## Recorded ambiguities

Each [static observation](chisel-v3-compatibility.md#static-observations-needing-executable-decisions)
must end in a decision, not a silence. Three were resolved by choosing Vapor behavior;
three belonged to manifests and left with them.

| ID | Ambiguity | Status | Decision and evidence |
| --- | --- | --- | --- |
| A01 | Copied `mode` parsed but not forwarded to extraction | resolved | An omitted mode forwards the extracted mode; an explicit mode replaces the permission bits. `TestApplyContent_ExplicitModeOverridesCopy`, `TestApplyContent_GlobCopiesModesAndOwnership`, `TestApplyContent_CopiesSpecialBits`. Documented in [content selection](catalogue.md#applying-content). |
| A02 | Essential architecture typos not validated like path architecture values | resolved | Essential filters are copied as decoded, matching pinned v3, and are not narrowed to Vapor's target architectures. `TestParsePackagesEssentials`. |
| A03 | Manifest `arch` accepted but not filtered by `FindPaths` | unsupported | Manifests are not generated, so there is no `FindPaths` to disagree with. `TestApplyContent_RejectsGenerate`. |
| A04 | Exclusively temporary mutable file reaches a missing report entry | unsupported | Manifest reporting is not generated. Temporary removal is still exercised by `TestRunScriptsRemovesTemporaryContentAfterMutation`. |
| A05 | Synthesized shared temporary attribution differs from extracted | resolved | Temporary removal is decided by the selected path set, not by attribution. `TestApplyContent_SharedTemporaryPathIsRemovedOnce`, `TestApplyContent_SharedTemporaryPathSurvivesWhenRetained`, `TestRunScriptsKeepsSharedTemporaryPaths`. |
| A06 | Change-then-revert mutation leaves a stale final hash | unsupported | Final hashes are not produced: no manifest is generated. |

## Debian provider coverage

Debian is Vapor's own distribution support, not upstream Chisel compatibility, so it gets
its own table. No upstream Debian catalogue, store path or Pro equivalent is assumed:
upstream Chisel publishes Ubuntu catalogues only, and the rows above stay about that.

| ID | Behavior | Status | Vapor tests |
| --- | --- | --- | --- |
| D01 | Release selection: version numbers and codenames collapse to one canonical codename, moving aliases and unknown numbers are refused, untested releases warn and continue | covered | `TestNewAliases`, `TestNewRejects`, `TestNewUnknownCodename`, `TestReleaseWarnings`, `TestSelect_Debian`, `TestSelect_DebianRejectsMovingAlias`, `TestAssembleCanonicalizesDebianRelease` |
| D02 | Release identity: a signed `Codename` must match, `updates/<component>` resolves to the plain component, several signatures are read in packet order, and replay keeps the recorded signer | covered | `TestCheckReleaseIdentityRequiresCodename`, `TestCheckReleaseIdentityPrefixedComponents`, `TestVerifyReleaseDebianSuiteShapes`, `TestVerifyReleaseMultipleSignatures`, `TestVerifyRepositoriesUsesProviderMatching`, `TestVerifyRepositoriesRejectsOtherCodename`, `TestVerifyRepositoriesDefaultMatchingIsExact`, `TestVerifyRepositoriesKeepsRecordedSigner` |
| D03 | Trust: reviewed main and security key snapshots per release, pinned real `InRelease` samples, and no key that signs one archive accepted for the other | covered | `TestTrustSnapshots`, `TestTrustAndIdentity`, `TestPinnedReleaseSamples`, `TestPinnedReleaseRejectsOtherArchiveKeys`, `TestPinnedSecurityArchivesAreNotInterchangeable`, `TestPinnedReleaseFreshness`, `TestPinnedReleaseReplayKeepsRecordedSigner` |
| D04 | Archives: main serves the codename and its updates suite on one endpoint, security serves the security suite elsewhere, both are bound for a package-only image with their own keys, and a suite outside an archive is refused | covered | `TestArchitectureAndEndpoint`, `TestBindArchivesDebianKeepsMainImplicit`, `TestBindArchivesDebianRejectsForeignSuite`, `TestProvider_ArchivesScopeKeysToTheirOwnSuites` |
| D05 | `os-release` synthesis: the provider pins `ID`, `VERSION_ID` and `VERSION_CODENAME`, refuses a contradicting selected package, and an unknown codename keeps the released version | covered | `TestReleaseIdentity`, `TestReleaseIdentityUnknownCodename`, `TestRelease_DebianPinsIdentity`, `TestRelease_RejectsUbuntuCodenameOnDebian`, `TestRelease_RejectsConflictingDebianCodename`, `TestRelease_UnknownCodenameKeepsReleasedVersion` |
| D06 | Offline pipeline: one catalogue over the implicit main archive and a bound security archive locks and builds without network, freshness follows the declared policy, and an accepted lock outlives its metadata | covered | `TestDebianPipelineLocksAndBuildsOffline`, `TestDebianFreshnessPolicies`, `TestDebianLockBuildsAfterExpiry`, `TestDebianWholePackageWithoutCatalogue`, `TestDebianWholePackageWithImplicitArchive`, `TestDebianRejectsUndeclaredRepository`, `TestDebianSliceWithoutCatalogueIsRefused` |

D03 is the row that keeps two archives apart. Debian cross-signs: the main archives are
signed by both releases' keys, so a foreign key alone can verify them, while the security
archives are signed only by the security keys.

## Other external authorities

Chisel is not the only thing that defines Vapor's behavior. Debian version ordering is
defined by dpkg, archive decoding by dpkg-deb and tar, and the OCI and attestation
payloads by their published specifications. Those are **not** rows here: each is an
ordinary test with a real oracle, and a second status table would only restate the
first.

[External oracles](testing.md#external-oracles) records which tool defines what, the
rules for running one (opt-in, offline, pinned, never an input to a build) and the plan
to build oracle images with Vapor itself. No oracle comparison has been run yet.

## What this matrix does not claim

- It does not claim upstream compatibility. That needs the native-v3 comparison (9.3.1), and
  it is blocked.
- It does not claim Debian conformance to anything. The Debian rows record what Vapor
  does for Debian; no upstream Debian behaviour exists to compare against.
- It does not claim store support. R11 covers parsing, discovery and the explicit
  refusal; no store blob has ever been acquired or extracted.
- It does not claim that a `covered` row is complete. A row lists the tests that exist;
  adding behavior to a row means adding the test here too, and the matrix test fails if
  the checklist grows without a corresponding row.
