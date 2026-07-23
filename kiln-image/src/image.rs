//! An [`Image`]: an ordered stack of layer ids plus the runtime
//! configuration (env, default command, workdir, exposed ports) a
//! container started from it should get.
//!
//! Content-addressed like everything else in this crate: an image's id is
//! the hash of its own canonical JSON. This is what "bit-reproducible
//! build" cashes out to at this level - two builds that produce an
//! identical layer stack and config are, by construction, the *same*
//! image, with the same id, on any machine.

use crate::error::{Error, Result};
use crate::store::{Hash, Store};

/// Apply the same "official image" shorthand Docker Hub (and `docker
/// pull`) uses: a repository name with no `/` is short for `library/name`.
/// Shared between [`Image::resolve`]'s tag lookup and
/// [`crate::registry::Reference::parse`] so that `FROM busybox:latest` in
/// a Kilnfile resolves to the exact same tag [`crate::registry::pull`]
/// saved it under.
pub fn normalize_repository(name: &str) -> String {
    if name.contains('/') {
        name.to_string()
    } else {
        format!("library/{name}")
    }
}

/// Split `"name:tag"` into `(name, tag)`, defaulting `tag` to `"latest"`
/// when absent. Careful about a `host:port/name` prefix with no tag of its
/// own (e.g. `"localhost:5555/echo"`): a `:` whose right-hand side
/// contains `/` is a host:port separator, not a tag separator, so that
/// doesn't count as a tag. Shared by [`Image::resolve`],
/// [`crate::registry::Reference::parse`], and `kiln build`'s `-t` parsing
/// so all three agree on what a reference means.
pub fn split_name_tag(s: &str) -> (&str, &str) {
    match s.rsplit_once(':') {
        Some((name, tag)) if !tag.contains('/') => (name, tag),
        _ => (s, "latest"),
    }
}

/// Point `reference` (`name[:tag]`) at `id` - the `kiln tag` primitive,
/// shared by its CLI command and `kilnd`'s matching endpoint. This is the
/// missing step between "build/pull an image under its own name" and
/// "push it somewhere else": [`crate::registry::push`] (and
/// [`Image::resolve`] underneath it) only ever pushes an image under a
/// name it's *already* locally tagged as - there's no implicit "push
/// this same content under a different name" - so pushing to an explicit
/// host (`registry.example.com/you/app:latest`) needs this run first,
/// exactly like `docker tag` before `docker push` does.
pub fn tag_reference(store: &Store, id: &Hash, reference: &str) -> Result<()> {
    let (name, tag) = split_name_tag(reference);
    store.tag(&normalize_repository(name), tag, *id)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImageConfig {
    /// Ordered; a later entry with the same key overrides an earlier one,
    /// same as repeated `ENV` instructions in a Kilnfile.
    pub env: Vec<(String, String)>,
    /// Shell-form default command (`CMD`). Exec-form (`["a","b"]`) is not
    /// yet supported - see kilnfile.rs.
    pub cmd: Option<String>,
    pub workdir: String,
    pub exposed_ports: Vec<(u16, String)>,
}

impl ImageConfig {
    pub fn env_get(&self, key: &str) -> Option<&str> {
        self.env.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    pub fn env_set(&mut self, key: String, value: String) {
        self.env.push((key, value));
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Image {
    /// Base-to-top: `layers[0]` is the bottommost (e.g. the `FROM` base),
    /// `layers[last]` the most recently added.
    pub layers: Vec<Hash>,
    pub config: ImageConfig,
}

impl Image {
    pub fn id(&self) -> Hash {
        let json = serde_json::to_vec(self).expect("Image serialization cannot fail");
        Hash::of_bytes(&json)
    }

    pub fn save(&self, store: &Store) -> Result<Hash> {
        let id = self.id();
        let path = store.images_dir().join(format!("{id}.json"));
        if !path.is_file() {
            store.write_json(&path, self)?;
        }
        Ok(id)
    }

    pub fn load(store: &Store, id: &Hash) -> Result<Self> {
        let path = store.images_dir().join(format!("{id}.json"));
        if !path.is_file() {
            return Err(Error::ImageNotFound(id.to_string()));
        }
        store.read_json(&path)
    }

    /// Resolve a `name[:tag]` or bare content-hash reference to an image.
    /// `"scratch"` always resolves to the empty base image, matching
    /// Docker's convention for "no base layers".
    pub fn resolve(store: &Store, reference: &str) -> Result<Self> {
        if reference == "scratch" {
            return Ok(Image {
                layers: Vec::new(),
                config: ImageConfig::default(),
            });
        }
        if let Ok(hash) = Hash::from_hex(reference) {
            if store.images_dir().join(format!("{hash}.json")).is_file() {
                return Image::load(store, &hash);
            }
        }
        let (name, tag) = split_name_tag(reference);
        let id = store.resolve_tag(&normalize_repository(name), tag)?;
        Image::load(store, &id)
    }

    /// Overlayfs `lowerdir` order: highest priority (most recently added
    /// layer) first, which is the reverse of `layers`' base-to-top order.
    pub fn lower_dirs_order(&self) -> impl Iterator<Item = &Hash> {
        self.layers.iter().rev()
    }
}
