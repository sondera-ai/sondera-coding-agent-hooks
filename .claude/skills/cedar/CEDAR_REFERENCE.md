# Cedar Language Reference

Comprehensive Cedar policy and schema syntax reference. Distilled from the
[official Cedar documentation](https://docs.cedarpolicy.com/).

## Contents

- [Core Concepts](#core-concepts)
- [Policy Syntax](#policy-syntax)
- [Schema Syntax](#schema-syntax)
- [Data Types](#data-types)
- [Operators](#operators)
- [Entity References](#entity-references)
- [Templates](#templates)
- [Validation](#validation)
- [Authorization Patterns](#authorization-patterns)
- [Best Practices](#best-practices)

---

## Core Concepts

Cedar is a policy-as-code language for authorization. Every authorization decision answers: **Can this principal perform
this action on this resource?**

| Term           | Definition                                                           |
|----------------|----------------------------------------------------------------------|
| **Principal**  | Who is making the request (user, role, service)                      |
| **Action**     | What operation is being performed                                    |
| **Resource**   | What the action targets                                              |
| **Context**    | Additional request metadata (IP, time, etc.)                         |
| **Entity**     | A typed object with an ID, attributes, and optional parent hierarchy |
| **Policy**     | A `permit` or `forbid` rule with scope + conditions                  |
| **Policy Set** | Collection of all policies evaluated together                        |
| **Schema**     | Type definitions for entities, actions, and context                  |

**Key principle**: An explicit `forbid` always overrides any number of `permit` policies. If no policy matches, the
default decision is **deny**.

---

## Policy Syntax

### Basic Structure

```cedar
@annotation("value")
effect (
    principal_constraint,
    action_constraint,
    resource_constraint
)
when { condition }
unless { condition };
```

### Effect

- `permit` — allows the request if scope and conditions match
- `forbid` — denies the request if scope and conditions match (overrides permits)

### Scope Constraints

#### Principal

```cedar
principal                                      // any principal
principal == User::"alice"                     // exact match
principal in Group::"admins"                   // hierarchy membership
principal is User                              // type check
principal is User in Group::"admins"           // type + membership
```

#### Action

```cedar
action                                         // any action
action == Action::"view"                       // exact match
action in [Action::"read", Action::"list"]     // set membership
action in Action::"readActions"                // action group
```

#### Resource

```cedar
resource                                       // any resource
resource == Photo::"vacation.jpg"              // exact match
resource in Album::"trips"                     // hierarchy membership
resource is Photo                              // type check
resource is Photo in Album::"trips"            // type + membership
```

### Conditions

#### `when` — policy matches only if expression is `true`

```cedar
when {
    principal.department == "Engineering" &&
    principal.jobLevel >= 5
}
```

#### `unless` — policy matches only if expression is `false`

```cedar
unless {
    principal == resource.owner
}

unless {
    context.authentication.usedMFA
}
```

### Annotations

Metadata with no effect on evaluation. Available to external systems.

```cedar
@id("policy-001")
@description("Allow admins full access")
@advice("Contact security team for exceptions")
permit (principal in Group::"admins", action, resource);
```

### Complete Examples

```cedar
// Simple: Alice can view a specific photo
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"vacation.jpg"
);

// ABAC: owners can edit their own resources
permit (
    principal,
    action == Action::"edit",
    resource
)
when {
    resource.owner == principal
};

// Forbid with exception: block private resources unless owner
forbid (
    principal,
    action,
    resource
)
when {
    resource.private
}
unless {
    principal == resource.owner
};

// Multiple actions with attribute conditions
permit (
    principal in Team::"Finance",
    action in [Action::"reviewBudget", Action::"approveBudget"],
    resource
)
when {
    resource.value < 25000
};
```

---

## Schema Syntax

Cedar schemas define entity types, actions, and shared types in `.cedarschema` files.

### Namespace

```cedar
namespace MyApp {
    entity User;
    // ... all declarations within namespace
}
```

### Entity Types

```cedar
// Basic entity
entity User;

// With attributes
entity User = {
    name: String,
    email: String,
    jobLevel: Long,
};

// With optional attributes (use ? suffix)
entity User = {
    name: String,
    delegate?: User,
};

// With hierarchy (membership)
entity User in [Group];

// With attributes + hierarchy
entity User in [Group] = {
    name: String,
    blocked: Set<User>,
};

// With tags (dynamic key-value pairs)
entity User = {
    name: String,
} tags String;

// Enumerated entity (restricts valid EIDs)
entity Group enum ["admins", "editors", "viewers"];

// Multiple entities sharing a definition
entity UserA, UserB, UserC;

// Nested record attributes
entity List = {
    owner: User,
    flags: {
        organizations?: Set<Org>,
        tags: Set<String>,
    },
};
```

### Action Declarations

```cedar
// Full action with appliesTo
action "ViewDocument" in [ReadActions] appliesTo {
    principal: [User, Public],
    resource: Document,
    context: {
        network: ipaddr,
        browser: String,
    },
};

// Action with structured context
action "uploadPhoto" appliesTo {
    principal: User,
    resource: Album,
    context: {
        "authenticated": Bool,
        "photo": {
            "file_size": Long,
            "file_type": String,
        },
    },
};

// Action group (no appliesTo, used for grouping)
action "readActions" in [Action::"allActions"];
```

### Common Types

Reusable type aliases to reduce duplication:

```cedar
type EmailAddress = String;

type AuthContext = {
    authenticated: Bool,
    mfaUsed: Bool,
    ipAddress: ipaddr,
};

// Used in actions:
action "login" appliesTo {
    principal: User,
    resource: Application,
    context: AuthContext,
};
```

### Attribute Types Summary

| Type       | Syntax       | Example                  |
|------------|--------------|--------------------------|
| Boolean    | `Bool`       | `active: Bool`           |
| Integer    | `Long`       | `age: Long`              |
| String     | `String`     | `name: String`           |
| Set        | `Set<T>`     | `tags: Set<String>`      |
| Record     | `{ ... }`    | `addr: { city: String }` |
| Entity ref | `EntityType` | `owner: User`            |
| IP address | `ipaddr`     | `source: ipaddr`         |
| Decimal    | `decimal`    | `price: decimal`         |
| Optional   | `T?`         | `nickname?: String`      |

---

## Data Types

### Primitives

| Type     | Literal         | Range/Notes                                 |
|----------|-----------------|---------------------------------------------|
| `Bool`   | `true`, `false` |                                             |
| `Long`   | `-1`, `42`      | -9223372036854775808 to 9223372036854775807 |
| `String` | `"hello"`       | Sequence of characters                      |

### Collections

**Set** — unordered collection, brackets syntax:

```cedar
[2, 4, "hello"]
[-1]
[]                    // empty (valid in entities, not in policies during validation)
```

**Record** — key-value pairs:

```cedar
{"key": "value", id: "another"}
{"foo": 2, bar: [3, 4], ham: "eggs", "hello": true}
```

### Entity References

```cedar
User::"alice"
Action::"ReadFile"
PhotoFlash::User::"alice"              // with namespace
User::"a1b2c3d4-e5f6-a1b2-c3d4-EXAMPLE11111"  // UUID recommended for production
```

### Extension Types

**datetime** — instant with millisecond precision:

```cedar
datetime("2024-10-15")
datetime("2024-10-15T11:35:00Z")
datetime("2024-10-15T11:35:00.000+0100")
```

**decimal** — up to 4 decimal places:

```cedar
decimal("12345.1234")
// Range: -922337203685477.5808 to 922337203685477.5807
```

**duration** — time span:

```cedar
duration("2h30m")
duration("-1d12h")
duration("1h30m45s")
```

**ipaddr** — IPv4/IPv6 with optional CIDR:

```cedar
ip("192.168.1.100")
ip("10.50.0.0/24")
ip("1:2:3:4::/48")
```

---

## Operators

### Arithmetic (Long only)

| Op  | Example | Notes                    |
|-----|---------|--------------------------|
| `+` | `a + b` | Overflow produces errors |
| `-` | `a - b` | Also unary negation `-a` |
| `*` | `a * b` | No division operator     |

### Comparison

| Op                | Types                    | Example                        |
|-------------------|--------------------------|--------------------------------|
| `==`              | All                      | `principal == User::"alice"`   |
| `!=`              | All                      | `a != b` (only in when/unless) |
| `<` `<=` `>` `>=` | Long, datetime, duration | `principal.age >= 18`          |

Decimal uses method syntax: `.lessThan()`, `.greaterThan()`, `.lessThanOrEqual()`, `.greaterThanOrEqual()`

### Logical

| Op                 | Example              | Notes                                  |
|--------------------|----------------------|----------------------------------------|
| `&&`               | `a && b`             | Short-circuit: stops if first is false |
| `\|\|`             | `a \|\| b`           | Short-circuit: stops if first is true  |
| `!`                | `!a`                 | Boolean negation                       |
| `if...then...else` | `if a then b else c` | Conditional expression                 |

### String

**`like`** — pattern matching with `*` wildcard:

```cedar
context.path like "*.py"                        // ends with .py
context.command like "*rm -rf *"                // contains rm -rf
principal.email like "*@example.com"            // ends with domain
```

**Important**: `like` is an **infix operator**, not a method call. `*` matches zero or more characters.

For multi-extension matching, chain with `||`:

```cedar
context.path like "*.js" || context.path like "*.ts"
```

### Hierarchy & Membership

| Op    | Example                        | Notes                        |
|-------|--------------------------------|------------------------------|
| `in`  | `principal in Group::"admins"` | Reflexive and transitive     |
| `is`  | `principal is User`            | Entity type check            |
| `has` | `resource has "location"`      | Attribute existence check    |
| `.`   | `resource.owner`               | Attribute access             |
| `[]`  | `resource["owner"]`            | Alternative attribute access |

### Set Operations

```cedar
set.contains(element)                           // single element membership
set.containsAll(otherSet)                       // subset check
set.containsAny(otherSet)                       // intersection check
set.isEmpty()                                   // empty check
```

### IP Address Functions

```cedar
ip("192.168.1.1").isIpv4()                     // true
ip("::1").isIpv6()                             // true
ip("127.0.0.1").isLoopback()                   // true
ip("224.0.0.1").isMulticast()                  // true
ip("192.168.1.100").isInRange(ip("192.168.1.0/24"))  // true
```

### Datetime Functions

```cedar
context.time.offset(duration("2h30m"))         // add duration
context.time.durationSince(datetime("2024-01-01"))  // difference
context.time.toDate()                          // extract date
context.time.toTime()                          // extract time as duration
duration("2h30m").toMinutes()                  // 150
```

### Tag Operations

```cedar
entity.hasTag("tag_name")                      // check tag existence
entity.getTag("tag_name")                      // retrieve tag value
```

---

## Entity References

### Syntax

```cedar
Type::"identifier"                             // basic
Namespace::Type::"identifier"                  // namespaced
Namespace::SubNS::Type::"identifier"           // nested namespace
```

### In Policies

```cedar
// Equality
principal == User::"alice"

// Hierarchy membership (reflexive — an entity is `in` itself)
principal in Group::"admins"

// Attribute access
resource.owner
principal.department

// Attribute existence check (required before accessing optional attrs)
resource has "location" && resource.location == "US"
```

---

## Templates

Templates enable dynamic policy creation with placeholders.

Only `?principal` and `?resource` placeholders are supported, and only on the right side of `==` or `in`:

```cedar
permit (
    principal in ?principal,
    action in [Action::"view", Action::"comment"],
    resource in ?resource
)
unless {
    resource.tag == "private"
};
```

Templates are linked at runtime by substituting concrete entity values:

```
?principal → UserGroup::"friendsAndFamily"
?resource  → Album::"vacationTrip"
```

**Placeholder restrictions**: Only in scope (not conditions). Only with `==` or `in`. Cannot use standalone `is` with placeholders.

---

## Validation

Cedar validation checks policies against a schema **before deployment**.

### What Validation Catches

- Unrecognized entity types (typos like `Uzer` instead of `User`)
- Misspelled actions or invalid principal/resource combinations
- References to undefined attributes
- Unsafe access to optional attributes without `has` guards
- Type mismatches (comparing string against number)
- Invalid entity identifiers for enumerated types

### What Validation Cannot Catch

1. **Integer overflow** — adding large Long values beyond 64-bit capacity
2. **Missing entities** — references to entities not in the store at evaluation time
3. **Invalid extension values** — malformed constructor arguments in non-strict mode

### Strict Mode (Default)

Forbids passing non-literal strings to extension constructors:

```cedar
// Strict mode REJECTS this (principal.IPAddr could be malformed):
ip(principal.IPAddr).isInRange(ip("10.0.0.0/8"))

// Strict mode ACCEPTS this (literal string, validated at compile time):
ip("10.0.0.1").isInRange(ip("10.0.0.0/8"))
```

Cedar's validation is formally proven: if policies validate against a schema, they are guaranteed not to produce type
errors for conforming requests.

---

## Authorization Patterns

### Pattern 1: Membership / RBAC

Access based on role or group membership. Policies are static; group assignments are managed externally.

```cedar
// Role-based access
permit (
    principal in Role::"ContractManager",
    action in [Action::"reviewContract", Action::"executeContract"],
    resource
);

// Role with attribute constraints (prevents role explosion)
permit (
    principal in Role::"ComplianceOfficer",
    action in [Action::"approveAudit"],
    resource is Audit
)
when {
    principal has complianceOfficerCountries &&
    resource.country in principal.complianceOfficerCountries
};
```

### Pattern 2: Relationship / ReBAC

Access derived from relationships between principals and resources.

```cedar
// Owner access
permit (
    principal is User,
    action in Action::"ownerActions",
    resource is List
)
when {
    principal in resource.owners
};

// Contributors with group support and negative constraint
permit (
    principal is User,
    action in Action::"contributorActions",
    resource is List
)
when {
    (resource has contributingUsers &&
     principal in resource.contributingUsers) ||
    (resource has contributingTeams &&
     principal in resource.contributingTeams)
}
unless {
    principal has isTerminated && principal.isTerminated
};
```

### Pattern 3: Discretionary

Ad-hoc grants to specific principals. Always use `principal ==` (not `in`).

```cedar
// Service-to-service
permit (
    principal == Service::"Service-1343",
    action == Action::"ServiceRequest",
    resource == Service::"Service-7465"
);

// Template-based discretionary (runtime policies)
permit (
    principal == ?principal,
    action in Action::"SharedAccess",
    resource == ?resource
)
when {
    resource.status == "OPEN"
};
```

### Pattern 4: Mixed Model

Combine patterns in a single policy store:

```cedar
// RBAC: admin role
permit (
    principal in Role::"Admin",
    action in Action::"adminActions",
    resource is List
);

// ReBAC: public access
permit (
    principal in UserGroup::"rootUserGroup",
    action in [Action::"viewList"],
    resource is List
)
when {
    resource has isPublic && resource.isPublic
};

// Discretionary: daemon access
permit (
    principal == daemon::"housekeeping",
    action in Action::"housekeepingActions",
    resource is List
);
```

---

## Best Practices

### Policy Design

1. **Use business actions, not API verbs** — design actions around user workflows (`CreateSupportCase`) not HTTP
   methods (`POST`).
2. **Populate the policy scope** — use principal/action/resource constraints in scope rather than checking them in
   `when` conditions.
3. **Keep principal/action/resource out of context** — context is for request metadata (IP, time), not identity or
   authorization information.
4. **Don't mix patterns in a single policy** — each policy should follow one pattern (RBAC, ReBAC, or discretionary).

### Schema Design

1. **One principal type with groups** — create a single `User` entity type and use `Group` entities for role
   differentiation.
2. **Every resource in a container** — resources should belong to a parent container for hierarchy-based access.
3. **Use attributes over entity proliferation** — add attributes to prevent creating many similar entity types.
4. **Avoid mutable identifiers** — don't use values that can change (like email) as entity IDs.

### Security

1. **Explicit deny wins** — a single matching `forbid` overrides all `permit` policies.
2. **Default deny** — if no policy matches, access is denied. Use a baseline `permit (principal, action, resource)` only
   when you want default-allow with targeted forbids.
3. **Guard optional attributes** — always check `has` before accessing optional attributes to prevent validation errors.
4. **Use `like` carefully** — wildcards match broadly. `context.command like "*rm*"` matches `rm` but also `format`,
   `firmware`, etc.
