#[cfg(all(feature = "pedm_client", target_os = "windows"))]
pub mod client;

#[cfg(all(feature = "pipe", target_os = "windows"))]
pub mod pipe;

#[cfg(feature = "policy")]
pub mod policy;

#[cfg(feature = "build")]
pub mod build;

#[cfg(all(feature = "desktop", target_os = "windows"))]
pub mod desktop;
