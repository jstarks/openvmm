//! Test entry point for the `vmm_tests` crate.

// Ensure all the tests get linked.
use vmm_tests as _;

fn main() {
    petri::test_main(|name, requirements| {
        requirements.resolve(
            petri_artifact_resolver_openvmm_known_paths::OpenvmmKnownPathsTestArtifactResolver::new(
                name,
            ),
        )
    })
}
