//! Anonymous Credentials (Tier 2)
//!
//! This module implements BBS+ anonymous credentials with device binding.
//!
//! # Features
//!
//! - **BBS+ Signatures**: Sign multiple messages with a single signature
//! - **Selective Disclosure**: Reveal only chosen attributes in a proof
//! - **Unlinkability**: Proofs cannot be linked to each other or issuance
//! - **Device Binding**: Credentials bound to hardware via BLS signature
//!
//! # Security Properties
//!
//! | Property | Description |
//! |----------|-------------|
//! | Unforgeability | Cannot create valid credential without issuer |
//! | Anonymity | Verifier cannot identify credential holder |
//! | Unlinkability | Same credential shown twice cannot be linked |
//! | Non-transferability | Credential cannot be used on different device |
//!
//! # Example
//!
//! ```ignore
//! // Issuer side
//! let issuer = Issuer::new(&mut rng);
//! let credential = issuer.issue(&attributes)?;
//!
//! // Holder side
//! let proof = credential.prove(
//!     &device_key,
//!     &issuer.public_key(),
//!     &[0, 2],  // Reveal attributes 0 and 2
//!     &challenge,
//!     &mut rng,
//! )?;
//!
//! // Verifier side
//! let disclosed = proof.verify(&issuer.public_key(), &device_pk, &challenge)?;
//! ```

pub mod bbs_plus;
pub mod device_binding;
pub mod schnorr;

pub use bbs_plus::{
    BBSSignature, Credential, CredentialProof, IssuerPublicKey, IssuerSecretKey,
};
pub use device_binding::{
    DeviceAttestation, DeviceBoundProof, DevicePublicKey, DeviceSecretKey, VerifiedAttributes,
};
pub use schnorr::{
    DLEQProof, PedersenCommitment, PedersenOpeningProof, SchnorrProofG1, SchnorrProofG2,
};
