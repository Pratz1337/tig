# Roles and command environments

Roles separate read visibility, key custody, and management. The current owner has management permissions but does not automatically receive a group's secret. A role assignment permits reading; a key grant makes its ciphertext readable. The high-level grant command performs both in one conditional head update. Public role policy, identity tokens, group names, and role names are not secrets.

Start with an initialized repository and an already published remote named `origin`. On another client, fetch or clone first so it has the owner's trust pin. Obtain each person's public token with `tig identity`.

## Define and assign roles

```text
tig role create billing --rank 1
tig role grant billing READER_TOKEN
tig role list
```

The remote defaults to `origin`. The existing explicit form, such as `tig role origin list`, also works. `create` gives a new role its own read group and initializes the creator-owner's key custody. `grant` assigns the role and wraps its key together. Directory and HTTP remotes commit these consecutive signed policy batches in one conditional head update; the server verifies each batch and rejects skipped counters.

`set` creates or replaces a role. Its `--groups` and `--permissions` arguments accept comma-separated names. Larger numeric ranks are higher. A manager can change or assign only roles strictly below their own highest rank, cannot give permissions they lack, and cannot assign themselves a higher role. The current owner is exempt from the rank limit.

The effective permissions are `edit-private`, `manage-roles`, `assign-roles`, and `publish`. For example:

```text
tig role create lead --rank 10 --permissions manage-roles,assign-roles
tig role grant lead MANAGER_TOKEN
```

A manager without a group's read role cannot obtain its key merely by managing it. A current key holder completes pending grants. For a new group, its first authorized reader can create the initial epoch while granting it. Existing groups require existing epoch-key custody for grants and rotation.

Publishing a new `@billing` tag as the owner also creates that read role and initializes its key automatically. Adding tags is sufficient to switch from simple mode; no migration command is needed. The role policy and published bookmark land in the same conditional head update. Existing simple-mode members retain their private-group access, publish permission, and rule-edit permission through a built-in rank-0 `private` role. New read-role recipients receive no unrelated private-group keys or publish permission. A tag does not change existing roles' ranks or permissions.

Put role rules in `.private`, for example:

```text
.env.billing @billing
internal/billing/** @billing
```

Untagged rules retain the `private` group. Each historical revision uses its own rules. Publishing a `.private` change requires `edit-private`, and a publisher cannot assign private content to a group they cannot read. Existing independent private files stay private when a sealed security change is later revealed.

## Remove access and rotate

```text
tig role revoke billing READER_TOKEN
```

`revoke` removes the assignment, rotates affected group keys, and wraps them for the remaining readers in one conditional update. A separate read role can still authorize a member for a shared group. A revoked reader retains old epochs but cannot open new ciphertext.

The advanced `set`, `assign`, `unassign`, `pending`, and `rotate` operations remain available. `set` creates or replaces explicit permission/group definitions. A low-level `unassign` freezes publication until a reader rotates; the high-level `revoke` performs both steps atomically. Existing groups require key custody before grants or rotation; a manager who cannot read them cannot obtain their keys by managing roles.

In role mode, publication can use a verified epoch grant when no local owner key is saved. A saved local key must still match its signed commitment; simple mode continues to require the original owner's local private-group key.

If removing publish permission invalidates the current manifest's signer, the command re-signs its unchanged contents with the acting authorized publisher. A manager without publish permission must have an authorized publisher make that role change instead.

Revocation cannot erase plaintext, old keys, or history someone already received. Fetch can still open historical epochs for which that person has a valid grant. New epochs exclude removed readers. If no remaining reader has the old key, restore authorized custody before rotating; management permission alone cannot manufacture it.

## Transfer ownership

The old owner signs a proposal naming the successor and next policy counter. The proposal also records the observed remote head:

```text
tig role origin transfer SUCCESSOR_TOKEN transfer.proposal
```

Give that proposal file to the successor. On their own client, using their own identity, they run:

```text
tig role origin accept-transfer transfer.proposal
```

Acceptance signs the new keyring head and re-signs existing public reveal certificates. It does not export either person's private identity or raw epoch keys. The CLI checks the recorded head before accepting; if it changed, make a fresh proposal. Concurrent public updates can still be preserved by the conditional commit. The signed authorization binds the successor and policy counter, rather than the recorded head bytes. The root owner pin remains the trust anchor; the former owner's key no longer confers owner authority. Secret access still follows read assignments and key grants, so arrange needed reader custody separately.

## Run a command with role secrets

With `.env.billing` classified as `@billing` and available in the working revision:

```text
tig env origin --role billing -- PROGRAM ARGUMENTS
tig env origin --role billing --file internal/billing/service.env -- PROGRAM ARGUMENTS
```

The default file is `.env.<role>`. Here `--role` selects the read group named in `.private`; a custom role definition can authorize several such groups. The selected source must be classified private for that group. Missing, sealed, unreadable, invalid, and unauthorized sources fail before the child starts. Authorization checks the live verified remote policy even if the file and an old key remain cached locally.

Role commands and `tig env` persist each verified policy counter and signed policy prefix before acting, including a denied environment request. Later commands reject an older head or a different accepted prefix. This local observation floor survives stale fetch/publish cache saves and serializes competing observers. It cannot detect an older genuine policy on first contact or revoke plaintext already held by another process.

Dotenv parsing is literal: optional `export ` and matching outer quotes are supported; `$`, command substitutions, and escapes are not evaluated. The command and its arguments are passed directly to the child without an inserted shell. The child inherits standard input/output/error and its exit status is propagated; it can print or otherwise disclose secrets it receives. tig itself does not print parsed values or include invalid line contents in errors.
