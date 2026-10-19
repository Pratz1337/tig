//! Role isolation, two-step grants, rotation freeze, and env redaction.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;

use tig_core::store::{empty_tree_id, StoreExt};
use tig_core::treeops::{apply_edits, Leaf};
use tig_core::{MemoryStore, RepoPath};
use tig_private::env::{self, EnvError};
use tig_private::keys::{self, EpochKey, GroupEpoch, Identity};
use tig_private::project::{self, ProjectError};
use tig_private::roles::{self, Role, RoleError, TransitionBody};
use tig_private::keyring::Keyring;
use zeroize::Zeroizing;

fn remote() -> [u8; 16] {
    [9; 16]
}

fn role(rank: u32, permissions: u32, groups: &[&str]) -> Role {
    Role {
        rank,
        permissions,
        groups: groups.iter().map(|g| (*g).to_string()).collect(),
    }
}

#[test]
fn simple_keyring_stays_version_1() {
    let owner = Identity::generate().unwrap();
    let (keyring, _) = Keyring::create(remote(), &owner).unwrap();
    let bytes = keyring.encode().unwrap();
    assert_eq!(bytes[0], 1);
    let decoded = Keyring::decode(&bytes).unwrap();
    assert!(decoded.policy.is_empty());
    assert_eq!(decoded.encode().unwrap(), bytes);
    decoded.verify(&owner.public().signing, 0).unwrap();
}

#[test]
fn assigning_an_existing_role_cannot_delegate_permissions_the_manager_lacks() {
    let owner = Identity::generate().unwrap();
    let manager = Identity::generate().unwrap();
    let member = Identity::generate().unwrap();
    let (mut ring, _) = Keyring::create(remote(), &owner).unwrap();
    let sign = |body: TransitionBody, counter, actor: &Identity| body.sign(remote(), &owner.public().signing, counter, actor);
    let mut definitions = vec![sign(TransitionBody::SetRole {
        name: "lead".into(), role: role(10, roles::ASSIGN_ROLES, &[]),
    }, 2, &owner)];
    for (name, permissions) in [("rules", roles::EDIT_PRIVATE), ("manager", roles::MANAGE_ROLES),
        ("publisher", roles::PUBLISH), ("delegate", roles::ASSIGN_ROLES), ("reader", 0)] {
        definitions.push(sign(TransitionBody::SetRole {
            name: name.into(), role: role(1, permissions, &[]),
        }, 2, &owner));
    }
    ring.commit_policy(&owner, definitions, vec![]).unwrap();
    ring.commit_policy(&owner, vec![sign(TransitionBody::Assign {
        member: manager.public(), role: "lead".into(),
    }, 3, &owner)], vec![]).unwrap();
    let before = ring.encode().unwrap();
    for name in ["rules", "manager", "publisher"] {
        let error = ring.commit_policy(&manager, vec![sign(TransitionBody::Assign {
            member: member.public(), role: name.into(),
        }, 4, &manager)], vec![]).unwrap_err();
        assert!(error.to_string().contains("permission"), "{error}");
        assert_eq!(ring.encode().unwrap(), before);
    }
    ring.commit_policy(&manager, vec!["delegate", "reader"].into_iter().map(|name| sign(TransitionBody::Assign {
        member: member.public(), role: name.into(),
    }, 4, &manager)).collect(), vec![]).unwrap();
    assert_eq!(ring.policy_snapshot().unwrap().permissions(&member.public()), roles::ASSIGN_ROLES);
    ring.commit_policy(&owner, vec![sign(TransitionBody::Assign {
        member: member.public(), role: "publisher".into(),
    }, 5, &owner)], vec![]).unwrap();
    assert!(ring.policy_snapshot().unwrap().has(&member.public(), roles::PUBLISH));
}

#[test]
fn owner_commits_reader_wraps_and_env_denies_removed_reader() {
    let owner = Identity::generate().unwrap();
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let dave = Identity::generate().unwrap();
    let (mut keyring, _) = Keyring::create(remote(), &owner).unwrap();
    let root_signing = keyring.owner.signing;
    let remote_id = keyring.remote;

    let sign_all = |counter: u64, actor: &Identity, bodies: Vec<TransitionBody>| {
        bodies
            .into_iter()
            .map(|body| body.sign(remote_id, &root_signing, counter, actor))
            .collect::<Vec<_>>()
    };

    keyring
        .commit_policy(
            &owner,
            sign_all(
                2,
                &owner,
                vec![
                    TransitionBody::SetRole {
                        name: "billing".into(),
                        role: role(1, 0, &["billing"]),
                    },
                    TransitionBody::SetRole {
                        name: "lead".into(),
                        role: role(10, roles::ASSIGN_ROLES | roles::MANAGE_ROLES, &[]),
                    },
                    TransitionBody::SetRole {
                        name: "publisher".into(),
                        role: role(2, roles::PUBLISH, &["billing"]),
                    },
                ],
            ),
            vec![],
        )
        .unwrap();
    keyring
        .commit_policy(
            &owner,
            sign_all(
                3,
                &owner,
                vec![
                    TransitionBody::Assign {
                        member: alice.public(),
                        role: "billing".into(),
                    },
                    TransitionBody::Assign {
                        member: dave.public(),
                        role: "billing".into(),
                    },
                    TransitionBody::Assign {
                        member: dave.public(),
                        role: "publisher".into(),
                    },
                    TransitionBody::Assign {
                        member: bob.public(),
                        role: "lead".into(),
                    },
                ],
            ),
            vec![],
        )
        .unwrap();

    let raise = TransitionBody::Assign {
        member: bob.public(),
        role: "publisher".into(),
    }
    .sign(remote(), &keyring.owner.signing, 4, &bob);
    let err = keyring.commit_policy(&owner, vec![raise], vec![]).unwrap_err();
    assert!(err.to_string().contains("raise"), "{err}");

    let too_much = TransitionBody::SetRole {
        name: "auditor".into(),
        role: role(1, roles::PUBLISH, &["billing"]),
    }
    .sign(remote(), &keyring.owner.signing, 4, &bob);
    let err = keyring
        .commit_policy(&owner, vec![too_much], vec![])
        .unwrap_err();
    assert!(err.to_string().contains("permission"), "{err}");

    let bob_advance = TransitionBody::AdvanceEpoch {
        group: "billing".into(),
        epoch: 1,
    }
    .sign(remote(), &keyring.owner.signing, 4, &bob);
    let err = keyring
        .commit_policy(&owner, vec![bob_advance], vec![])
        .unwrap_err()
        .to_string();
    assert!(err.contains("only a reader"), "{err}");

    let ctx = GroupEpoch {
        remote: remote(),
        group: "billing".into(),
        epoch: 1,
    };
    let epoch_key = EpochKey::generate(ctx).unwrap();
    let alice_grant = keys::grant(&epoch_key, &alice.public(), &alice).unwrap();
    let dave_grant = keys::grant(&epoch_key, &dave.public(), &alice).unwrap();
    let signed = sign_all(
        4,
        &alice,
        vec![
            TransitionBody::AdvanceEpoch {
                group: "billing".into(),
                epoch: 1,
            },
            TransitionBody::AuthorizeGrant {
                group: "billing".into(),
                epoch: 1,
                recipient: alice.public(),
                grant_signature: alice_grant.signature,
            },
            TransitionBody::AuthorizeGrant {
                group: "billing".into(),
                epoch: 1,
                recipient: dave.public(),
                grant_signature: dave_grant.signature,
            },
        ],
    );
    keyring
        .commit_policy(&owner, signed, vec![alice_grant, dave_grant])
        .unwrap();

    let bytes = keyring.encode().unwrap();
    assert_eq!(bytes[0], 2);
    keyring = Keyring::decode(&bytes).unwrap();
    assert_eq!(keyring.owner, owner.public());
    let verified = keyring.verify(&owner.public().signing, 0).unwrap();
    let opened = verified.key_for("billing", 1, &dave).unwrap();
    assert_eq!(opened.to_bytes(), epoch_key.to_bytes());
    assert!(verified.reads_now(&alice.public(), "billing"));
    assert!(!verified.reads_now(&bob.public(), "billing"));
    assert!(!verified.group_frozen("billing"));
    assert!(matches!(
        verified
            .snapshot()
            .may_publish_group(&bob.public(), &keyring.grants, "billing", Some(1)),
        Err(RoleError::Denied(_))
    ));

    let drop_alice = TransitionBody::Unassign {
        member: alice.public(),
        role: "billing".into(),
    }
    .sign(remote(), &keyring.owner.signing, 5, &bob);
    keyring.commit_policy(&owner, vec![drop_alice], vec![]).unwrap();
    let verified = keyring.verify(&owner.public().signing, 0).unwrap();
    assert!(verified.group_frozen("billing"));
    assert!(!verified.reads_now(&alice.public(), "billing"));
    assert!(verified.key_for("billing", 1, &alice).is_ok());
    assert!(matches!(
        verified
            .snapshot()
            .may_publish_group(&dave.public(), &keyring.grants, "billing", Some(1)),
        Err(RoleError::Frozen { .. })
    ));

    let secret = Zeroizing::new("super-secret-value".to_string());
    let mut secrets = BTreeMap::new();
    secrets.insert("TOKEN".into(), secret.clone());
    let denied = env::run(OsString::from("sh").as_os_str(), &[], &secrets, false).unwrap_err();
    assert!(!denied.to_string().contains(secret.as_str()));
    assert!(matches!(denied, EnvError::Denied));

    let ctx2 = GroupEpoch {
        remote: remote(),
        group: "billing".into(),
        epoch: 2,
    };
    let next_key = EpochKey::generate(ctx2).unwrap();
    let dave_next = keys::grant(&next_key, &dave.public(), &dave).unwrap();
    let signed = vec![
        TransitionBody::AdvanceEpoch {
            group: "billing".into(),
            epoch: 2,
        }
        .sign(remote(), &keyring.owner.signing, 6, &dave),
        TransitionBody::AuthorizeGrant {
            group: "billing".into(),
            epoch: 2,
            recipient: dave.public(),
            grant_signature: dave_next.signature,
        }
        .sign(remote(), &keyring.owner.signing, 6, &dave),
    ];
    keyring
        .commit_policy(&owner, signed, vec![dave_next])
        .unwrap();
    let verified = keyring.verify(&owner.public().signing, 0).unwrap();
    assert!(!verified.group_frozen("billing"));
    assert!(verified.key_for("billing", 2, &alice).is_err());
    assert!(verified.key_for("billing", 1, &alice).is_ok());
    assert_eq!(
        verified.key_for("billing", 2, &dave).unwrap().to_bytes(),
        next_key.to_bytes()
    );
    assert!(verified.granted_epochs(&alice).iter().any(|(g, e)| g == "billing" && *e == 1));
    assert!(!verified.granted_epochs(&alice).iter().any(|(g, e)| g == "billing" && *e == 2));
    verified
        .snapshot()
        .may_publish_group(&dave.public(), &keyring.grants, "billing", Some(2))
        .unwrap();

    let successor = Identity::generate().unwrap();
    let transfer = TransitionBody::Transfer {
        owner: successor.public(),
    }
    .sign(remote(), &keyring.owner.signing, 7, &owner);
    keyring
        .commit_policy(&successor, vec![transfer], vec![])
        .unwrap();
    assert_eq!(keyring.owner, owner.public());
    let verified = keyring.verify(&owner.public().signing, 0).unwrap();
    assert_eq!(verified.snapshot().current_owner, successor.public());
    assert!(keyring.verify(&successor.public().signing, 0).is_err());
}

#[test]
fn dotenv_is_literal_and_unreadable_sources_fail() {
    let parsed = env::parse_dotenv(
        "a.env",
        b"export TOKEN=$(launch)\nQUOTED=\"${TOKEN}\"\n# comment\nPLAIN=ok\n",
    )
    .unwrap();
    assert_eq!(parsed["TOKEN"].as_str(), "$(launch)");
    assert_eq!(parsed["QUOTED"].as_str(), "${TOKEN}");
    assert_eq!(parsed["PLAIN"].as_str(), "ok");
    assert!(matches!(
        env::load_source("sealed.env", Ok(Vec::new()), true).unwrap_err(),
        EnvError::Sealed { .. }
    ));
    assert!(matches!(
        env::load_source(
            "gone.env",
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "gone")),
            false,
        )
        .unwrap_err(),
        EnvError::Unreadable { .. }
    ));


}

#[test]
fn grouped_projection_uses_the_role_key() {
    let store = MemoryStore::new();
    let root = apply_edits(
        &store,
        &empty_tree_id(),
        &BTreeMap::from([
            (
                RepoPath::new(".private").unwrap(),
                Some(Leaf::file(store.put_blob(b"billing/** @billing\n").unwrap())),
            ),
            (
                RepoPath::new("billing/plan").unwrap(),
                Some(Leaf::file(store.put_blob(b"secret-plan").unwrap())),
            ),
        ]),
    )
    .unwrap();
    let private_key = EpochKey::generate(GroupEpoch {
        remote: remote(),
        group: "private".into(),
        epoch: 1,
    })
    .unwrap();
    assert!(matches!(
        project::project_tree(&store, &root, &private_key),
        Err(ProjectError::RolesNotSupported(_))
    ));
    let billing_key = EpochKey::generate(GroupEpoch {
        remote: remote(),
        group: "billing".into(),
        epoch: 1,
    })
    .unwrap();
    let mut keys = BTreeMap::new();
    keys.insert("billing".into(), &private_key);
    assert!(project::project_grouped(&store, &root, &keys).is_err());
    keys.insert("billing".into(), &billing_key);
    let projected = project::project_grouped(&store, &root, &keys).unwrap();
    assert_eq!(projected.sealed.len(), 1);
    assert_eq!(projected.sealed[0].readers, BTreeSet::from(["billing".into()]));
    let sealed = projected.sealed[0].leaf;
    let expect = billing_key.seal(&projected.sealed[0].path, sealed.kind(), &sealed.id());
    let public = tig_core::treeops::lookup(
        &store,
        &projected.public_tree,
        &projected.sealed[0].path,
    )
    .unwrap()
    .unwrap();
    assert_eq!(public.sealed_id(), Some(expect));
}

#[test]
fn commit_keyring_lands_policy_on_a_directory_remote() {
    let dir = tempfile::tempdir().unwrap();
    let remote = tig_private::remote::DirRemote::create(dir.path(), remote()).unwrap();
    let owner = Identity::generate().unwrap();
    let (keyring, _) = Keyring::create(remote.remote_id(), &owner).unwrap();
    let empty = tig_private::remote::HeadVersion::of(None, None);
    assert!(matches!(
        remote
            .commit_head(&empty, Some(&keyring.encode().unwrap()), None)
            .unwrap(),
        tig_private::remote::CommitOutcome::Committed(_)
    ));
    let mut state = tig_private::publish::PublishState::new();
    state.remote_id = remote.remote_id();
    state.owner_signing = Some(owner.public().signing);
    let local = tempfile::tempdir().unwrap();
    tig_private::access::commit_keyring(&remote, local.path(), &mut state, |current| {
        let body = TransitionBody::SetRole {
            name: "billing".into(),
            role: role(1, 0, &["billing"]),
        }
        .sign(
            current.remote,
            &current.owner.signing,
            current.head.counter + 1,
            &owner,
        );
        let mut next = current.clone();
        next.commit_policy(&owner, vec![body], vec![])?;
        Ok((next, None))
    })
    .unwrap();
    let stored = Keyring::decode(&remote.read_head().unwrap().keyring.unwrap()).unwrap();
    assert_eq!(stored.encode().unwrap()[0], 2);
    assert!(stored.policy_snapshot().unwrap().roles.contains_key("billing"));
    assert!(state.counter >= stored.head.counter);
}

#[test]
fn removing_last_visibility_role_keeps_old_holders_revoked_and_group_frozen() {
    let owner = Identity::generate().unwrap();
    let alice = Identity::generate().unwrap();
    let (mut keyring, keys) = Keyring::create(remote(), &owner).unwrap();
    keyring.grant(&keys, &owner, &alice.public()).unwrap();
    let counter = keyring.head.counter + 1;
    let define = TransitionBody::SetRole {
        name: "reader".into(), role: role(1, 0, &["private"]),
    }.sign(remote(), &keyring.owner.signing, counter, &owner);
    keyring.commit_policy(&owner, vec![define], vec![]).unwrap();
    let counter = keyring.head.counter + 1;
    let assign = TransitionBody::Assign { member: alice.public(), role: "reader".into() }
        .sign(remote(), &keyring.owner.signing, counter, &owner);
    keyring.commit_policy(&owner, vec![assign], vec![]).unwrap();
    assert!(keyring.verify(&owner.public().signing, 0).unwrap().reads_now(&alice.public(), "private"));
    let counter = keyring.head.counter + 1;
    let remove = TransitionBody::RemoveRole { name: "reader".into() }
        .sign(remote(), &keyring.owner.signing, counter, &owner);
    keyring.commit_policy(&owner, vec![remove], vec![]).unwrap();
    let verified = keyring.verify(&owner.public().signing, 0).unwrap();
    assert!(!verified.reads_now(&alice.public(), "private"));
    assert!(verified.group_frozen("private"));
    assert!(verified.key_for("private", 1, &alice).is_ok());
}

#[test]
fn manager_can_commit_authorized_roles_but_former_owner_cannot_forge_transfer_head() {
    let owner = Identity::generate().unwrap();
    let manager = Identity::generate().unwrap();
    let successor = Identity::generate().unwrap();
    let (mut keyring, keys) = Keyring::create(remote(), &owner).unwrap();
    let sign = |body: TransitionBody, counter, actor: &Identity| body.sign(remote(), &owner.public().signing, counter, actor);
    keyring.commit_policy(&owner, vec![sign(TransitionBody::SetRole {
        name: "lead".into(), role: role(10, roles::MANAGE_ROLES, &[]),
    }, 2, &owner)], vec![]).unwrap();
    keyring.commit_policy(&owner, vec![sign(TransitionBody::Assign {
        member: manager.public(), role: "lead".into(),
    }, 3, &owner)], vec![]).unwrap();
    keyring.commit_policy(&manager, vec![sign(TransitionBody::SetRole {
        name: "auditor".into(), role: role(1, 0, &["billing"]),
    }, 4, &manager)], vec![]).unwrap();
    keyring.verify(&owner.public().signing, 0).unwrap();
    keyring.commit_policy(&successor, vec![sign(TransitionBody::Transfer {
        owner: successor.public(),
    }, 5, &owner)], vec![]).unwrap();
    keyring.verify(&owner.public().signing, 0).unwrap();
    let forged = keys::grant(&keys.keys[&("private".into(), 1)], &owner.public(), &owner).unwrap();
    keyring.policy.baseline.insert(forged.signature);
    keyring.grants.push(forged);
    let mut message = keyring.head.signing_bytes();
    message.extend(keyring.policy.digest(remote(), &owner.public().signing));
    keyring.head.signature = owner.sign(&message);
    assert!(keyring.verify(&owner.public().signing, 0).is_err());
}

#[test]
fn union_group_visibility_is_any_named_reader_and_removal_stays_explicit() {
    let owner = Identity::generate().unwrap();
    let alice = Identity::generate().unwrap();
    let (mut keyring, _) = Keyring::create(remote(), &owner).unwrap();
    keyring.commit_policy(&owner, vec![TransitionBody::SetRole {
        name: "billing".into(), role: role(1, 0, &["billing"]),
    }.sign(remote(), &owner.public().signing, 2, &owner)], vec![]).unwrap();
    keyring.commit_policy(&owner, vec![TransitionBody::Assign {
        member: alice.public(), role: "billing".into(),
    }.sign(remote(), &owner.public().signing, 3, &owner)], vec![]).unwrap();
    let snapshot = keyring.policy_snapshot().unwrap();
    assert!(snapshot.may_read(&alice.public(), "billing+security", &BTreeSet::new()));
    assert!(!snapshot.may_read(&alice.public(), "security", &BTreeSet::new()));
}

#[test]
fn assigned_visibility_without_key_custody_cannot_rotate_an_existing_group() {
    let owner = Identity::generate().unwrap();
    let waiting = Identity::generate().unwrap();
    let (mut keyring, _) = Keyring::create(remote(), &owner).unwrap();
    let sign = |body: TransitionBody, counter, actor: &Identity| body.sign(remote(), &owner.public().signing, counter, actor);
    keyring.commit_policy(&owner, vec![sign(TransitionBody::SetRole {
        name: "reader".into(), role: role(1, 0, &["private"]),
    }, 2, &owner)], vec![]).unwrap();
    keyring.commit_policy(&owner, vec![sign(TransitionBody::Assign {
        member: waiting.public(), role: "reader".into(),
    }, 3, &owner)], vec![]).unwrap();
    let before = keyring.clone();
    let error = keyring.commit_policy(&waiting, vec![sign(TransitionBody::AdvanceEpoch {
        group: "private".into(), epoch: 2,
    }, 4, &waiting)], vec![]).unwrap_err();
    assert!(error.to_string().contains("key holder"), "{error}");
    assert_eq!(keyring, before);
}

#[test]
fn accepted_transfer_checkpoint_rejects_former_owner_higher_counter_fork() {
    let owner = Identity::generate().unwrap();
    let successor = Identity::generate().unwrap();
    let (mut accepted, _) = Keyring::create(remote(), &owner).unwrap();
    accepted.commit_policy(&successor, vec![TransitionBody::Transfer { owner: successor.public() }
        .sign(remote(), &owner.public().signing, 2, &owner)], vec![]).unwrap();
    let checkpoint = accepted.policy_checkpoint().unwrap();
    let (mut fork, _) = Keyring::create(remote(), &owner).unwrap();
    for counter in 2..=4 {
        fork.commit_policy(&owner, vec![TransitionBody::SetRole {
            name: format!("alternate{counter}"), role: role(1, 0, &[]),
        }.sign(remote(), &owner.public().signing, counter, &owner)], vec![]).unwrap();
    }
    fork.verify(&owner.public().signing, accepted.head.counter).unwrap();
    assert!(fork.verify_policy_checkpoint(Some(&checkpoint)).is_err());
    accepted.verify_policy_checkpoint(Some(&checkpoint)).unwrap();
    accepted.commit_policy(&successor, vec![TransitionBody::SetRole {
        name: "legitimate".into(), role: role(1, 0, &[]),
    }.sign(remote(), &owner.public().signing, 3, &successor)], vec![]).unwrap();
    accepted.verify_policy_checkpoint(Some(&checkpoint)).unwrap();
}

#[test]
fn fetch_publish_and_access_refuse_a_higher_counter_fork_after_transfer() {
    use tig_core::repo::{root_revision, root_revision_id};
    use tig_core::Object;
    use tig_private::fetch::{fetch, FetchState};
    use tig_private::manifest::Manifest;
    use tig_private::publish::{publish, PublishOptions, PublishState};
    use tig_private::remote::DirRemote;
    let owner = Identity::generate().unwrap();
    let successor = Identity::generate().unwrap();
    let (mut accepted, _) = Keyring::create(remote(), &owner).unwrap();
    accepted.commit_policy(&successor, vec![TransitionBody::Transfer { owner: successor.public() }
        .sign(remote(), &owner.public().signing, 2, &owner)], vec![]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let target = DirRemote::create(dir.path(), remote()).unwrap();
    let good_manifest = Manifest::signed(remote(), 1,
        BTreeMap::from([("main".into(), root_revision_id())]), BTreeMap::new(), &successor).unwrap();
    target.commit_head(&target.read_head().unwrap().version(), Some(&accepted.encode().unwrap()), Some(&good_manifest.encode().unwrap())).unwrap();
    let store = MemoryStore::new();
    let mut fetched = FetchState::new();
    fetch(&target, &store, None, &mut fetched, &PublishState::new()).unwrap();
    assert_eq!(FetchState::decode(&fetched.encode().unwrap()).unwrap(), fetched);
    let before_fetch = fetched.clone();
    let (mut fork, keys) = Keyring::create(remote(), &owner).unwrap();
    for counter in 2..=4 {
        fork.commit_policy(&owner, vec![TransitionBody::SetRole {
            name: format!("fork{counter}"), role: role(1, 0, &[]),
        }.sign(remote(), &owner.public().signing, counter, &owner)], vec![]).unwrap();
    }
    let forged_manifest = Manifest::signed(remote(), 2,
        BTreeMap::from([("main".into(), root_revision_id())]), BTreeMap::new(), &owner).unwrap();
    target.commit_head(&target.read_head().unwrap().version(), Some(&fork.encode().unwrap()), Some(&forged_manifest.encode().unwrap())).unwrap();
    let error = fetch(&target, &store, None, &mut fetched, &PublishState::new()).unwrap_err();
    assert!(error.to_string().contains("accepted role policy"), "{error}");
    assert_eq!(fetched, before_fetch);
    let mut published = PublishState::new();
    published.remote_id = remote();
    published.owner_signing = Some(owner.public().signing);
    published.counter = accepted.head.counter;
    published.policy_checkpoint = accepted.policy_checkpoint();
    let before_publish = published.clone();
    store.put(&Object::Revision(root_revision())).unwrap();
    let error = publish(&store, &target, &owner, Some(&keys), &mut published,
        &FetchState::new(), "other", root_revision_id(), &PublishOptions::default()).unwrap_err();
    assert!(error.to_string().contains("accepted role policy"), "{error}");
    assert_eq!(published, before_publish);
    let local = tempfile::tempdir().unwrap();
    let error = tig_private::access::commit_keyring(&target, local.path(), &mut published,
        |_| panic!("forked policy must be refused before the update is built")).unwrap_err();
    assert!(error.to_string().contains("accepted role policy"), "{error}");
    assert_eq!(published, before_publish);
    assert!(target.public_store().get_raw(&root_revision_id()).unwrap().is_none());
}

#[test]
fn managing_a_lower_assigned_role_cannot_add_read_access_to_yourself() {
    let owner = Identity::generate().unwrap();
    let manager = Identity::generate().unwrap();
    let (mut ring, _) = Keyring::create(remote(), &owner).unwrap();
    let sign = |body: TransitionBody, counter, actor: &Identity| body.sign(remote(), &owner.public().signing, counter, actor);
    ring.commit_policy(&owner, vec![
        sign(TransitionBody::SetRole { name: "lead".into(), role: role(10, roles::MANAGE_ROLES, &[]) }, 2, &owner),
        sign(TransitionBody::SetRole { name: "audit".into(), role: role(1, 0, &[]) }, 2, &owner),
    ], vec![]).unwrap();
    ring.commit_policy(&owner, vec![
        sign(TransitionBody::Assign { member: manager.public(), role: "lead".into() }, 3, &owner),
        sign(TransitionBody::Assign { member: manager.public(), role: "audit".into() }, 3, &owner),
    ], vec![]).unwrap();
    let before = ring.clone();
    let error = ring.commit_policy(&manager, vec![sign(TransitionBody::SetRole {
        name: "audit".into(), role: role(1, 0, &["billing"]),
    }, 4, &manager)], vec![]).unwrap_err();
    assert!(error.to_string().contains("own assigned role"), "{error}");
    assert_eq!(ring, before);
}

#[test]
fn parentless_rules_creation_requires_edit_private_before_uploads() {
    use tig_core::repo::{root_revision, root_revision_id};
    use tig_core::Object;
    use tig_private::fetch::FetchState;
    use tig_private::publish::{publish, PublishOptions, PublishState};
    use tig_private::remote::DirRemote;
    let owner = Identity::generate().unwrap();
    let publisher = Identity::generate().unwrap();
    let (mut ring, _) = Keyring::create(remote(), &owner).unwrap();
    ring.commit_policy(&owner, vec![TransitionBody::SetRole {
        name: "publisher".into(), role: role(1, roles::PUBLISH, &[]),
    }.sign(remote(), &owner.public().signing, 2, &owner)], vec![]).unwrap();
    ring.commit_policy(&owner, vec![TransitionBody::Assign {
        member: publisher.public(), role: "publisher".into(),
    }.sign(remote(), &owner.public().signing, 3, &owner)], vec![]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let target = DirRemote::create(dir.path(), remote()).unwrap();
    target.commit_head(&target.read_head().unwrap().version(), Some(&ring.encode().unwrap()), None).unwrap();
    let before_head = target.read_head().unwrap().version();
    let store = MemoryStore::new();
    let public = store.put_blob(b"public content").unwrap();
    let tree = apply_edits(&store, &empty_tree_id(), &BTreeMap::from([
        (RepoPath::new("readme").unwrap(), Some(Leaf::file(public))),
        (RepoPath::new(".private").unwrap(), Some(Leaf::file(store.put_blob(b"*.secret\n").unwrap()))),
    ])).unwrap();
    let mut revision = root_revision();
    revision.tree = tree;
    revision.change_id = tig_core::ChangeId([229; 16]);
    assert!(revision.parents.is_empty());
    let id = store.put(&Object::Revision(revision.clone())).unwrap();
    let mut state = PublishState::new();
    state.remote_id = remote();
    state.owner_signing = Some(owner.public().signing);
    let before = state.clone();
    let error = publish(&store, &target, &publisher, None, &mut state,
        &FetchState::new(), "main", id, &PublishOptions::default()).unwrap_err();
    assert!(error.to_string().contains("EDIT_PRIVATE"), "{error}");
    assert_eq!(state, before);
    assert_eq!(target.read_head().unwrap().version(), before_head);
    assert!(!target.public_store().has(&id).unwrap());
    assert!(!target.public_store().has(&public).unwrap());
    assert!(!target.public_store().has(&root_revision_id()).unwrap());
    // Parentless public history remains supported when it creates no rules.
    revision.tree = apply_edits(&store, &empty_tree_id(), &BTreeMap::from([
        (RepoPath::new("readme").unwrap(), Some(Leaf::file(public))),
    ])).unwrap();
    revision.change_id = tig_core::ChangeId([230; 16]);
    let allowed = store.put(&Object::Revision(revision)).unwrap();
    publish(&store, &target, &publisher, None, &mut state,
        &FetchState::new(), "main", allowed, &PublishOptions::default()).unwrap();
    assert!(target.public_store().has(&allowed).unwrap());
}

#[test]
fn policy_update_cannot_leave_a_manifest_signed_by_a_revoked_publisher() {
    use tig_core::repo::root_revision_id;
    use tig_private::manifest::Manifest;
    use tig_private::publish::PublishState;
    use tig_private::remote::DirRemote;
    let owner = Identity::generate().unwrap();
    let publisher = Identity::generate().unwrap();
    let manager = Identity::generate().unwrap();
    let (mut ring, _) = Keyring::create(remote(), &owner).unwrap();
    let sign = |body: TransitionBody, counter, actor: &Identity| body.sign(remote(), &owner.public().signing, counter, actor);
    ring.commit_policy(&owner, vec![
        sign(TransitionBody::SetRole { name: "publisher".into(), role: role(1, roles::PUBLISH, &[]) }, 2, &owner),
        sign(TransitionBody::SetRole { name: "lead".into(), role: role(10, roles::ASSIGN_ROLES, &[]) }, 2, &owner),
    ], vec![]).unwrap();
    ring.commit_policy(&owner, vec![
        sign(TransitionBody::Assign { member: publisher.public(), role: "publisher".into() }, 3, &owner),
        sign(TransitionBody::Assign { member: manager.public(), role: "lead".into() }, 3, &owner),
    ], vec![]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let target = DirRemote::create(dir.path(), remote()).unwrap();
    let manifest = Manifest::signed(remote(), 1, BTreeMap::from([("main".into(), root_revision_id())]), BTreeMap::new(), &publisher).unwrap();
    target.commit_head(&target.read_head().unwrap().version(), Some(&ring.encode().unwrap()), Some(&manifest.encode().unwrap())).unwrap();
    let before_head = target.read_head().unwrap().version();
    let mut state = PublishState::new();
    state.remote_id = remote();
    state.owner_signing = Some(owner.public().signing);
    state.counter = ring.head.counter;
    state.manifest_seq = 1;
    state.policy_checkpoint = ring.policy_checkpoint();
    let before = state.clone();
    let local = tempfile::tempdir().unwrap();
    let error = tig_private::access::commit_keyring(&target, local.path(), &mut state, |current| {
        let mut next = current.clone();
        let transition = TransitionBody::Unassign { member: publisher.public(), role: "publisher".into() }
            .sign(remote(), &owner.public().signing, current.head.counter + 1, &manager);
        next.commit_policy(&manager, vec![transition], vec![])?;
        Ok((next, None))
    }).unwrap_err();
    assert!(error.to_string().contains("authorized publisher"), "{error}");
    assert_eq!(target.read_head().unwrap().version(), before_head);
    assert_eq!(state, before);
    assert!(!local.path().join("pending-keyring").exists());
}
