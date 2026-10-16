# Roles and command environments

Roles separate read visibility, key custody, and management. The current owner has management permissions but does not automatically receive a group's secret. A role assignment permits reading; a separate key grant makes its ciphertext readable. Public role policy, identity tokens, group names, and role names are not secrets.

Start with an initialized repository and an already published remote named `origin`. On another client, fetch or clone first so it has the owner's trust pin. Obtain each person's public token with `tig identity`.

## Define and assign roles

```text
tig role origin set billing --rank 1 --groups billing
tig role origin assign billing OWNER_TOKEN
tig role origin grant billing OWNER_TOKEN
tig role origin assign billing READER_TOKEN
tig role origin grant billing READER_TOKEN
tig role origin list
tig role origin pending
```

`set` creates or replaces a role. Its `--groups` and `--permissions` arguments accept comma-separated names. Larger numeric ranks are higher. A manager can change or assign only roles strictly below their own highest rank, cannot give permissions they lack, and cannot assign themselves a higher role. The current owner is exempt from the rank limit.

The effective permissions are `edit-private`, `manage-roles`, `assign-roles`, and `publish`. For example:

```text
tig role origin set lead --rank 10 --permissions manage-roles,assign-roles
tig role origin assign lead MANAGER_TOKEN
```

A manager without a group's read role cannot obtain its key merely by managing it. A current key holder completes pending grants. For a new group, its first authorized reader can create the initial epoch while granting it. Existing groups require existing epoch-key custody for grants and rotation.

Committing the first role policy switches the remote from simple mode to explicit permissions. Former simple-mode members retain their historical grants, but need an explicitly assigned `publish` permission to publish again. Permission to publish does not itself grant private-group visibility. Before a nonowner custodian wraps or rotates the existing untagged `private` group in role mode, explicitly define a reader role with `--groups private` and assign it to that custodian. Keeping an old simple-mode grant permits historical reads but does not make that person a signed role-policy actor.

Put role rules in `.private`, for example:

```text
.env.billing @billing
internal/billing/** @billing
```

Untagged rules retain the `private` group. Each historical revision uses its own rules. Publishing a `.private` change requires `edit-private`, and a publisher cannot assign private content to a group they cannot read. Existing independent private files stay private when a sealed security change is later revealed.

## Remove access and rotate

```text
tig role origin unassign billing READER_TOKEN
tig role origin pending
tig role origin rotate billing
```

A remaining authorized key holder runs `rotate`. Removing the last applicable read role freezes new publication to that group until rotation. Deleting its role with `tig role origin delete billing` also removes its assignments; it does not make historical grant holders readable again.

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

The default file is `.env.<role>`. The selected source must be classified private for that role. Missing, sealed, unreadable, invalid, and unauthorized sources fail before the child starts. Authorization checks the live verified remote policy even if the file and an old key remain cached locally.

Dotenv parsing is literal: optional `export ` and matching outer quotes are supported; `$`, command substitutions, and escapes are not evaluated. The command and its arguments are passed directly to the child without an inserted shell. The child inherits standard input/output/error and its exit status is propagated; it can print or otherwise disclose secrets it receives. tig itself does not print parsed values or include invalid line contents in errors.
