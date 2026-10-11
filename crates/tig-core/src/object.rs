//! The object model. See DESIGN.md "Objects".

use std::collections::{BTreeMap, BTreeSet};

use crate::encode::{Reader, Writer};
use crate::error::{Error, Result};
use crate::id::{ChangeId, ObjectId};
use crate::seal::SealedId;

const FORMAT_V1: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ObjectKind {
    Blob = 1,
    Tree = 2,
    Revision = 3,
    Operation = 4,
    View = 5,
}

impl ObjectKind {
    pub fn from_u8(b: u8) -> Result<Self> {
        Ok(match b {
            1 => ObjectKind::Blob,
            2 => ObjectKind::Tree,
            3 => ObjectKind::Revision,
            4 => ObjectKind::Operation,
            5 => ObjectKind::View,
            _ => return Err(Error::decode("object kind", format!("unknown kind {b}"))),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            ObjectKind::Blob => "blob",
            ObjectKind::Tree => "tree",
            ObjectKind::Revision => "revision",
            ObjectKind::Operation => "operation",
            ObjectKind::View => "view",
        }
    }
}

/// Computes the ID of an encoded object without building it.
pub fn hash_object(kind: ObjectKind, body: &[u8]) -> ObjectId {
    let mut h = blake3::Hasher::new_derive_key(crate::domain::OBJECT_ID);
    h.update(&[kind as u8]);
    h.update(body);
    ObjectId(*h.finalize().as_bytes())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Object {
    Blob(Vec<u8>),
    Tree(Tree),
    Revision(Revision),
    Operation(Operation),
    View(View),
}

impl Object {
    pub fn kind(&self) -> ObjectKind {
        match self {
            Object::Blob(_) => ObjectKind::Blob,
            Object::Tree(_) => ObjectKind::Tree,
            Object::Revision(_) => ObjectKind::Revision,
            Object::Operation(_) => ObjectKind::Operation,
            Object::View(_) => ObjectKind::View,
        }
    }

    /// The body bytes that get hashed and stored (without the kind byte).
    pub fn encode_body(&self) -> Vec<u8> {
        match self {
            Object::Blob(b) => b.clone(),
            Object::Tree(t) => t.encode(),
            Object::Revision(r) => r.encode(),
            Object::Operation(o) => o.encode(),
            Object::View(v) => v.encode(),
        }
    }

    pub fn decode(kind: ObjectKind, body: &[u8]) -> Result<Self> {
        Ok(match kind {
            ObjectKind::Blob => Object::Blob(body.to_vec()),
            ObjectKind::Tree => Object::Tree(Tree::decode(body)?),
            ObjectKind::Revision => Object::Revision(Revision::decode(body)?),
            ObjectKind::Operation => Object::Operation(Operation::decode(body)?),
            ObjectKind::View => Object::View(View::decode(body)?),
        })
    }

    pub fn id(&self) -> ObjectId {
        hash_object(self.kind(), &self.encode_body())
    }
}

fn check_version(r: &mut Reader<'_>, what: &'static str) -> Result<()> {
    let v = r.u8()?;
    if v != FORMAT_V1 {
        return Err(Error::decode(
            what,
            format!("unsupported format version {v}"),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tree

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EntryKind {
    File = 1,
    Executable = 2,
    Symlink = 3,
    Tree = 4,
    /// Placeholder for a private subtree in a public view. `id` is the sealed hash.
    Sealed = 5,
}

impl EntryKind {
    pub fn from_u8(b: u8) -> Result<Self> {
        Ok(match b {
            1 => EntryKind::File,
            2 => EntryKind::Executable,
            3 => EntryKind::Symlink,
            4 => EntryKind::Tree,
            5 => EntryKind::Sealed,
            _ => return Err(Error::decode("tree", format!("unknown entry kind {b}"))),
        })
    }

    /// True for entries whose id points at a blob.
    pub fn is_file_like(self) -> bool {
        matches!(
            self,
            EntryKind::File | EntryKind::Executable | EntryKind::Symlink
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
///
/// Fields are crate-private: outside tig-core, entries are built with
/// [`TreeEntry::new`] or [`TreeEntry::sealed`], so a plain object ID can never
/// be placed in a `Sealed` slot (see `seal.rs`).
pub struct TreeEntry {
    pub(crate) name: String,
    pub(crate) kind: EntryKind,
    pub(crate) id: ObjectId,
}

impl TreeEntry {
    /// A file, executable, symlink, or directory entry. Rejects `Sealed`:
    /// use [`TreeEntry::sealed`] with a [`SealedId`].
    pub fn new(name: impl Into<String>, kind: EntryKind, id: ObjectId) -> Result<Self> {
        let name = name.into();
        validate_name(&name)?;
        if kind == EntryKind::Sealed {
            return Err(Error::Invalid(format!(
                "{name:?}: a sealed entry needs a SealedId; a plain object ID would let anyone test guesses of private content"
            )));
        }
        Ok(TreeEntry { name, kind, id })
    }

    /// The public stand-in for a private file or folder.
    pub fn sealed(name: impl Into<String>, sealed: SealedId) -> Result<Self> {
        let name = name.into();
        validate_name(&name)?;
        Ok(TreeEntry { name, kind: EntryKind::Sealed, id: ObjectId(*sealed.as_bytes()) })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> EntryKind {
        self.kind
    }

    /// The object this entry points at. For `Sealed` entries these are the
    /// sealed ID's bytes, which name no object; use [`TreeEntry::sealed_id`].
    pub fn id(&self) -> ObjectId {
        self.id
    }

    pub fn sealed_id(&self) -> Option<SealedId> {
        (self.kind == EntryKind::Sealed).then(|| SealedId::from_stored(self.id.0))
    }
}

/// A directory. Entries are kept sorted bytewise by name with no duplicates;
/// `Tree::new` enforces this so two equal directories always hash the same.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tree {
    entries: Vec<TreeEntry>,
}

/// True if `name` would be treated as the `.tig` metadata directory by some
/// filesystem: any case, and with the zero-width characters that macOS HFS+
/// ignores removed (git guards `.git` the same way).
fn is_metadata_dir(name: &str) -> bool {
    const IGNORABLE: &[char] = &[
        '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
        '\u{202E}', '\u{206A}', '\u{206B}', '\u{206C}', '\u{206D}', '\u{206E}', '\u{206F}', '\u{FEFF}',
    ];
    let visible: String = name.chars().filter(|c| !IGNORABLE.contains(c)).collect();
    visible.eq_ignore_ascii_case(".tig")
}

/// Validates one path component.
///
/// Rejected everywhere (including when decoding stored trees): empty, `.`,
/// `..`, `/`, NUL, `\`, `:`, control characters, a trailing `.` or space,
/// and anything that aliases `.tig`. Names that are only dangerous on some
/// filesystems but legitimately exist in real repos (Windows device names
/// like `aux.c`, and `A` next to `a`) are checked by the filesystem working
/// copy before it writes, not here.
pub fn validate_name(name: &str) -> Result<()> {
    let bad = |reason| {
        Err(Error::InvalidPath {
            path: name.to_string(),
            reason,
        })
    };
    if name.is_empty() {
        return bad("empty name");
    }
    if name == "." || name == ".." {
        return bad("'.' and '..' are not allowed");
    }
    if name.contains('/') || name.contains('\0') {
        return bad("name contains '/' or NUL");
    }
    // Portable-name policy: names that mean something else on some OS are
    // refused everywhere, so a repo can never smuggle them onto a disk.
    // `\` is a separator on Windows, ':' opens an NTFS alternate data stream
    // or a drive prefix, and Windows silently strips trailing dots and spaces
    // (`.env.` and `.env ` would be written as `.env`).
    if name.contains('\\') || name.contains(':') {
        return bad("name contains '\\' or ':'");
    }
    if name.chars().any(|c| c.is_control()) {
        return bad("name contains a control character");
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return bad("name ends with '.' or ' ' (Windows would rename it)");
    }
    if is_metadata_dir(name) {
        return bad("'.tig' is reserved for repository metadata");
    }
    Ok(())
}

impl Tree {
    pub fn new(mut entries: Vec<TreeEntry>) -> Result<Self> {
        for e in &entries {
            validate_name(&e.name)?;
        }
        entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        if let Some(w) = entries.windows(2).find(|w| w[0].name == w[1].name) {
            return Err(Error::Invalid(format!(
                "duplicate tree entry {:?}",
                w[0].name
            )));
        }
        Ok(Tree { entries })
    }

    pub fn empty() -> Self {
        Tree::default()
    }

    pub fn entries(&self) -> &[TreeEntry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, name: &str) -> Option<&TreeEntry> {
        self.entries
            .binary_search_by(|e| e.name.as_bytes().cmp(name.as_bytes()))
            .ok()
            .map(|i| &self.entries[i])
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(FORMAT_V1);
        w.varint(self.entries.len() as u64);
        for e in &self.entries {
            w.u8(e.kind as u8);
            w.str(&e.name);
            w.id(&e.id);
        }
        w.finish()
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body, "tree");
        check_version(&mut r, "tree")?;
        let n = r.count(1 + 1 + 1 + 32)?;
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let kind = EntryKind::from_u8(r.u8()?)?;
            let name = r.str()?.to_string();
            let id = r.id()?;
            entries.push(TreeEntry { name, kind, id });
        }
        r.finish()?;
        // Decoding must accept only canonical trees; otherwise one directory
        // could have several IDs.
        let tree = Tree::new(entries.clone())?;
        if tree.entries != entries {
            return Err(Error::decode("tree", "entries not in canonical order"));
        }
        Ok(tree)
    }
}

// ---------------------------------------------------------------------------
// Revision

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub name: String,
    pub email: String,
    /// Milliseconds since the Unix epoch, UTC.
    pub timestamp_ms: i64,
    /// Local timezone offset in minutes, for display only.
    pub tz_offset_min: i32,
}

impl Signature {
    fn write(&self, w: &mut Writer) {
        w.str(&self.name);
        w.str(&self.email);
        w.ivarint(self.timestamp_ms);
        w.ivarint(self.tz_offset_min as i64);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let name = r.str()?.to_string();
        let email = r.str()?.to_string();
        let timestamp_ms = r.ivarint()?;
        let tz = r.ivarint()?;
        let tz_offset_min =
            i32::try_from(tz).map_err(|_| Error::decode("signature", "timezone out of range"))?;
        Ok(Signature {
            name,
            email,
            timestamp_ms,
            tz_offset_min,
        })
    }
}

/// One snapshot of a change. A change is the set of revisions sharing `change_id`;
/// the newest one is found through the view's heads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revision {
    pub tree: ObjectId,
    pub parents: Vec<ObjectId>,
    pub change_id: ChangeId,
    /// Earlier revisions of the same change that this one replaces.
    pub predecessors: Vec<ObjectId>,
    /// Who started the change and when. Preserved across rewrites.
    pub author: Signature,
    /// Who wrote this revision and when.
    pub committer: Signature,
    pub description: String,
}

impl Revision {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(FORMAT_V1);
        w.id(&self.tree);
        w.varint(self.parents.len() as u64);
        for p in &self.parents {
            w.id(p);
        }
        w.change_id(&self.change_id);
        w.varint(self.predecessors.len() as u64);
        for p in &self.predecessors {
            w.id(p);
        }
        self.author.write(&mut w);
        self.committer.write(&mut w);
        w.str(&self.description);
        w.finish()
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body, "revision");
        check_version(&mut r, "revision")?;
        let tree = r.id()?;
        let n = r.count(32)?;
        let parents = (0..n).map(|_| r.id()).collect::<Result<_>>()?;
        let change_id = r.change_id()?;
        let n = r.count(32)?;
        let predecessors = (0..n).map(|_| r.id()).collect::<Result<_>>()?;
        let author = Signature::read(&mut r)?;
        let committer = Signature::read(&mut r)?;
        let description = r.str()?.to_string();
        r.finish()?;
        Ok(Revision {
            tree,
            parents,
            change_id,
            predecessors,
            author,
            committer,
            description,
        })
    }
}

// ---------------------------------------------------------------------------
// Operation log

/// One entry in the operation log. Every repo mutation writes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    pub parents: Vec<ObjectId>,
    pub view: ObjectId,
    pub user: String,
    pub timestamp_ms: i64,
    pub description: String,
    /// Set when this operation is an undo: the operation it undid. Lets
    /// repeated `undo` keep stepping back instead of toggling.
    pub undo_of: Option<ObjectId>,
}

impl Operation {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(FORMAT_V1);
        w.varint(self.parents.len() as u64);
        for p in &self.parents {
            w.id(p);
        }
        w.id(&self.view);
        w.str(&self.user);
        w.ivarint(self.timestamp_ms);
        w.str(&self.description);
        match &self.undo_of {
            None => w.u8(0),
            Some(id) => {
                w.u8(1);
                w.id(id);
            }
        }
        w.finish()
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body, "operation");
        check_version(&mut r, "operation")?;
        let n = r.count(32)?;
        let parents = (0..n).map(|_| r.id()).collect::<Result<_>>()?;
        let view = r.id()?;
        let user = r.str()?.to_string();
        let timestamp_ms = r.ivarint()?;
        let description = r.str()?.to_string();
        let undo_of = match r.u8()? {
            0 => None,
            1 => Some(r.id()?),
            b => return Err(Error::decode("operation", format!("bad undo flag {b}"))),
        };
        r.finish()?;
        Ok(Operation {
            parents,
            view,
            user,
            timestamp_ms,
            description,
            undo_of,
        })
    }
}

/// The whole mutable state of a repo at one operation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct View {
    /// Workspace name -> its working revision.
    pub workspaces: BTreeMap<String, ObjectId>,
    /// Bookmark name -> revision.
    pub bookmarks: BTreeMap<String, ObjectId>,
    /// Visible revisions with no visible descendants. Revisions not reachable
    /// from heads (or workspaces/bookmarks) are hidden, never deleted.
    pub heads: BTreeSet<ObjectId>,
}

impl View {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(FORMAT_V1);
        w.varint(self.workspaces.len() as u64);
        for (name, id) in &self.workspaces {
            w.str(name);
            w.id(id);
        }
        w.varint(self.bookmarks.len() as u64);
        for (name, id) in &self.bookmarks {
            w.str(name);
            w.id(id);
        }
        w.varint(self.heads.len() as u64);
        for id in &self.heads {
            w.id(id);
        }
        w.finish()
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body, "view");
        check_version(&mut r, "view")?;
        let mut view = View::default();
        let n = r.count(33)?;
        for _ in 0..n {
            let name = r.str()?.to_string();
            let id = r.id()?;
            if view.workspaces.insert(name, id).is_some() {
                return Err(Error::decode("view", "duplicate workspace"));
            }
        }
        let n = r.count(33)?;
        for _ in 0..n {
            let name = r.str()?.to_string();
            let id = r.id()?;
            if view.bookmarks.insert(name, id).is_some() {
                return Err(Error::decode("view", "duplicate bookmark"));
            }
        }
        let n = r.count(32)?;
        for _ in 0..n {
            if !view.heads.insert(r.id()?) {
                return Err(Error::decode("view", "duplicate head"));
            }
        }
        r.finish()?;
        // BTreeMap re-sorts, so re-encoding catches out-of-order input.
        if view.encode() != body {
            return Err(Error::decode("view", "not in canonical order"));
        }
        Ok(view)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig() -> Signature {
        Signature {
            name: "a".into(),
            email: "a@x".into(),
            timestamp_ms: 1_700_000_000_000,
            tz_offset_min: -300,
        }
    }

    #[test]
    fn tree_is_canonical() {
        let id = ObjectId([1; 32]);
        let a = Tree::new(vec![
            TreeEntry {
                name: "b".into(),
                kind: EntryKind::File,
                id,
            },
            TreeEntry {
                name: "a".into(),
                kind: EntryKind::Tree,
                id,
            },
        ])
        .unwrap();
        let b = Tree::decode(&a.encode()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.entries()[0].name, "a");
        assert!(Tree::new(vec![
            TreeEntry {
                name: "a".into(),
                kind: EntryKind::File,
                id
            },
            TreeEntry {
                name: "a".into(),
                kind: EntryKind::File,
                id
            },
        ])
        .is_err());
        assert!(Tree::new(vec![TreeEntry {
            name: "x/y".into(),
            kind: EntryKind::File,
            id
        }])
        .is_err());
    }

    #[test]
    fn revision_roundtrip() {
        let r = Revision {
            tree: ObjectId([2; 32]),
            parents: vec![ObjectId([3; 32])],
            change_id: ChangeId([9; 16]),
            predecessors: vec![],
            author: sig(),
            committer: sig(),
            description: "hello\n".into(),
        };
        let obj = Object::Revision(r.clone());
        assert_eq!(
            Object::decode(ObjectKind::Revision, &obj.encode_body()).unwrap(),
            obj
        );
    }

    #[test]
    fn view_roundtrip() {
        let mut v = View::default();
        v.workspaces.insert("default".into(), ObjectId([1; 32]));
        v.bookmarks.insert("main".into(), ObjectId([2; 32]));
        v.heads.insert(ObjectId([1; 32]));
        assert_eq!(View::decode(&v.encode()).unwrap(), v);
    }

    /// Object IDs are part of the on-disk format. If this fails, an ID label
    /// or an encoding changed and every existing repo would break.
    #[test]
    fn object_ids_are_frozen() {
        assert_eq!(
            hash_object(ObjectKind::Blob, b"hello\n").to_hex(),
            "887c6633a8c3d0b715bac9b815307d47430c8a2d679dae9e84e9e7735eb4444e"
        );
        assert_eq!(Object::Tree(Tree::empty()).id().to_hex(), "43581fee33ae552ce24395c7610880617df277cef408a4988fe120e996bc2935");
    }

    #[test]
    fn sealed_entries_need_a_sealed_id() {
        use crate::seal::SealSalt;
        assert!(TreeEntry::new("x", EntryKind::Sealed, ObjectId([1; 32])).is_err());
        let sid = SealedId::compute(&SealSalt::from_bytes([3; 32]), EntryKind::File, &ObjectId([1; 32]));
        let e = TreeEntry::sealed("x", sid).unwrap();
        assert_eq!(e.sealed_id(), Some(sid));
        assert_eq!(TreeEntry::new("f", EntryKind::File, ObjectId([1; 32])).unwrap().sealed_id(), None);
    }

    #[test]
    fn kinds_hash_differently() {
        assert_ne!(
            hash_object(ObjectKind::Blob, b""),
            hash_object(ObjectKind::Tree, b"")
        );
    }
}
