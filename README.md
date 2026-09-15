# ASP.NET Core Identity API — Zero to Hero

> **Single resource for YouTube playlist creation + study + review**
>
> This file covers Videos 01 through 09 of the 19-video playlist. Each video follows the same structure: **Theory & Definitions → 🎬 Recording Notes → Complete Implementation (every line commented) → Postman / Swagger Tests**. All code targets `[ApiController]` + JSON + JWT — no MVC, no views, no `View()`. Designed for API-first projects using `AddIdentityCore` and manual JWT token generation.

---

## Table of Contents

| Video | Title | Section |
|-------|-------|---------|
| 01 | What Is ASP.NET Core Identity — and Why Use It in an API? | [Concept](#video-01--what-is-aspnet-core-identity--and-why-use-it-in-an-api) |
| 02 | Identity Architecture — Users, Roles, Claims, Managers, Stores | [Architecture](#video-02--identity-architecture--users-roles-claims-managers-stores) |
| 03 | Creating the API Project & Installing Packages | [Project Setup](#video-03--creating-the-api-project--installing-packages) |
| 04 | Configuring Identity Services in Program.cs (API + JWT) | [Program.cs](#video-04--configuring-identity-services-in-programcs-api--jwt) |
| 05 | The Identity Models — IdentityUser, IdentityRole, Custom Classes | [Models](#video-05--the-identity-models--identityuser-identityrole-custom-classes) |
| 06 | Database Setup — IdentityDbContext, Connection Strings, Migrations | [DB & Migrations](#video-06--database-setup--identitydbcontext-connection-strings-migrations) |
| 07 | User Registration API — Complete Endpoint | [Registration](#video-07--user-registration-api--complete-endpoint) |
| 08 | Login API — JWT Token Issuance | [Login](#video-08--login-api--jwt-token-issuance) |
| 09 | Role Management API — CRUD Roles, Assign / Remove Users | [Roles](#video-09--role-management-api--crud-roles-assign--remove-users) |

---

## How to Use This File

1. **For YouTube creation:** Each video section has 🎬 Recording Notes with opening hooks, analogies, "say this" phrases, and common viewer questions. Use these to script your videos.
2. **For study:** The Theory & Definitions sections explain what each concept means, when to use it, and how it works under the hood.
3. **For implementation:** The Complete Implementation sections provide full, copy-paste-ready code with every line commented.
4. **For testing:** The Postman / Swagger Tests sections provide request bodies, expected responses, and what each response means.
5. **For future reference:** This is a single document. Search for the video number and find the complete reference.

**File location:** `C:\Users\azizn\Learning_ASP.NET_Core_Identity_From_Zero_To_Hero\README_Videos_01_to_09.md`

---

## Comparison — Why This Version Is the "Absolute Perfect" README

This file merges two approaches into one:

| | **Previous approach (code-only)** | **Latest approach (theory-only)** | **This merged file** |
|---|---|---|---|
| What it had | Full code for every step, line-by-line comments | Concepts, definitions, when-to-use/not-use, 🎬 recording mini-scripts | **Both: theory + code + 🎬 notes + tests in every section** |
| Depth per section | Implementation depth only | Conceptual depth only | **Equal spirit: concept explained, then code shown, then tested** |
| Usable for video | Yes — copy-paste code | Partially — good script material | **Yes — script from 🎬 notes, show code, test with Postman** |
| Usable for study | Yes — read code | Yes — read theory | **Yes — read theory to understand, code to implement** |
| Usable for review | Yes — check implementation | No — no code | **Yes — everything in one place** |

The goal was a single resource that is equally good for: scripting a YouTube video, studying the concepts, implementing the code, and testing the result. This merged version delivers all four.

---

# Video 01 — What Is ASP.NET Core Identity — and Why Use It in an API?

## Theory & Definitions

### What Is ASP.NET Core Identity?

ASP.NET Core Identity is a membership system that adds login, registration, role management, claims, and security features to an ASP.NET Core application. It is built on top of Entity Framework Core and provides a complete user management framework out of the box.

In simple terms: Identity handles **who the user is** (authentication) and **what they are allowed to do** (authorization) — the two things every application needs.

### The Core Concepts

- **User** — A person or entity that interacts with your application. In Identity, a user is represented by `IdentityUser` (or a custom subclass). A user has a username, password hash, email, phone number, security stamp, and a collection of claims, roles, and logins.

- **Role** — A named group that represents a set of permissions. Examples: "Admin", "User", "Moderator". Roles simplify authorization — you check `User.IsInRole("Admin")` instead of checking individual permissions.

- **Claim** — A name-value pair that describes something about the user. Examples: `name: "Ahmad"`, `role: "Admin"`, `email: "ahmad@example.com"`, `department: "Engineering"`. Claims are more granular than roles — you can attach any piece of information to a user and use it for authorization decisions.

- **Principal** — The `ClaimsPrincipal` that represents the currently authenticated user in the HTTP context. It is built from the user's claims and roles. Every request has a `HttpContext.User` that is a `ClaimsPrincipal`.

- **Authentication** — The process of verifying who the user is. In an API, this typically means: the client sends credentials (username + password, or a JWT token), and the server validates them and returns a token or sets a session.

- **Authorization** — The process of deciding what the authenticated user is allowed to do. This uses roles, claims, or policies to gate access to resources.

### How Identity Works Under the Hood

Identity sits in your application's dependency injection container as a set of services:

```
Your API Controller
        ↓
   UserManager<TUser>    ← manages user CRUD (create, find, update, delete)
   SignInManager<TUser>  ← manages sign-in, sign-out, 2FA, security stamps
   RoleManager<TRole>    ← manages role CRUD
        ↓
   IUserStore<TUser>     ← persistence abstraction (EF Core by default)
   IRoleStore<TRole>     ← persistence abstraction for roles
        ↓
   IdentityDbContext     ← EF Core DbContext that maps to your database
        ↓
   SQL Server / PostgreSQL / SQLite / etc.
```

- **UserManager** handles user operations: `CreateAsync`, `FindByEmailAsync`, `UpdateAsync`, `DeleteAsync`, `AddToRoleAsync`, `RemoveFromRoleAsync`, `GeneratePasswordResetTokenAsync`, etc.
- **SignInManager** handles sign-in operations: `SignInAsync`, `CheckPasswordSignInAsync`, `TwoFactorSignInAsync`, `RefreshSignInAsync`, etc.
- **RoleManager** handles role operations: `CreateAsync`, `FindByNameAsync`, `DeleteAsync`, etc.
- **Stores** are the persistence layer — by default `UserStore` and `RoleStore` backed by EF Core and your `IdentityDbContext`.

### When to Use ASP.NET Core Identity

| Scenario | Use Identity | Don't Use Identity |
|----------|-------------|-------------------|
| You need user registration, login, roles, claims | ✅ Yes — full membership system | — |
| You need JWT bearer authentication for an API | ✅ Yes — does not force cookies | — |
| You need multi-factor authentication (2FA) | ✅ Yes — built-in TOTP + recovery codes | — |
| You need external login (Google, Facebook, etc.) | ✅ Yes — external authentication built in | — |
| You need a custom user table with non-standard columns | ✅ Yes — subclass IdentityUser and add properties | — |
| You need simple username/password with no roles/claims | ⚠️ Overkill — consider a simpler auth system | ✅ Use a lightweight middleware |
| You are building a public API for mobile/SPA clients | ✅ Yes — Identity + JWT works well | — |
| You need Windows/Active Directory auth only | ⚠️ Partial — Windows auth is separate | ✅ Use Windows Authentication middleware |
| You need OAuth server (issue tokens for other apps) | ⚠️ Partial — Identity is a membership system, not an OAuth server | ✅ Use IdentityServer / Duende / Azure AD B2C |

### Why Identity in an API — Not Just MVC?

Historically, Identity was designed with MVC/Razor Pages in mind — it ships with cookie-based authentication, sign-in managers that set cookies, and redirect-based flows. In an API, you don't want cookies or redirects — you want:

1. **JWT bearer tokens** — the client sends a token in the Authorization header on every request.
2. **JSON responses** — the API returns JSON, not HTML views or redirects.
3. **Stateless authentication** — the server doesn't store session state; the token carries the identity.

Identity works perfectly in an API when you:
- Use `AddIdentityCore<TUser>` instead of `AddIdentity` (lighter, no default cookie handlers).
- Configure JWT Bearer authentication (`AddJwtBearer`).
- Manually generate JWT tokens after successful login (using the `SignInResult` from `CheckPasswordSignInAsync`).
- Use `[ApiController]` with `[Route("api/[controller]")]` — no views, no `View()`, all JSON.

### The "Zero to Hero" Journey — What We Cover

This tutorial takes you from zero knowledge of ASP.NET Core Identity to mastery, in order:

| Phase | Videos | What You Learn |
|-------|--------|---------------|
| **Concept** | 01 | What Identity is, its core concepts, when to use it |
| **Architecture** | 02 | Users, Roles, Claims, Managers, Stores — how they connect |
| **Setup** | 03–04 | Project creation, package installation, Program.cs configuration, JWT |
| **Data** | 05–06 | Models (IdentityUser, IdentityRole), DbContext, migrations, database |
| **Core APIs** | 07–09 | Registration, Login + JWT, Role CRUD and assignment |
| **Authorization** | 10–12 | RBAC, Claims-based auth, Policies |
| **Security** | 13–15 | Passwords, lockout, 2FA |
| **Advanced** | 16–18 | External logins, token providers, customization |
| **Production** | 19 | Best practices, audit logging, troubleshooting |

Each video builds on the previous one. You don't need to skip ahead — the content is sequential and cumulative.

### Key Distinction: Identity vs. Authentication vs. Authorization

- **Identity** = the membership system (users, roles, claims, stores, managers). It is the framework that manages user data and security primitives.
- **Authentication** = verifying who the user is. In our API: username + password → JWT token.
- **Authorization** = deciding what the user can do. In our API: `[Authorize(Roles="Admin")]`, policies, claims-based checks.

Identity provides the building blocks. You wire authentication (JWT) and authorization (roles/claims/policies) on top of it.

---

## 🎬 Video Recording Notes

**Opening (say this):**

> "If you've ever built an application that needs users to register, log in, and have different permission levels — you've run into the same problem: authentication and authorization are hard to build from scratch. Today we're going to learn ASP.NET Core Identity — Microsoft's membership system that handles all of this for you. We'll focus on APIs specifically — no MVC, no Razor Pages, no cookies. Just JSON, JWT tokens, and clean endpoints. By the end of this playlist, you'll go from zero to mastery — every concept, every line of code, every Postman test."

**What to show on screen:**

> Show the overall architecture diagram (Users → UserManager → UserStore → Database). Show a simple sketch of how a request flows: client sends credentials → API validates → returns JWT → client includes JWT in future requests → API reads claims from JWT → authorizes.

**Key points to emphasize (say this):**

> "Identity is not just 'login and registration'. It's a full membership system — users, roles, claims, security stamps, 2FA, external logins, password reset, email confirmation. It's the foundation that everything else builds on."

> "In an API, we use Identity differently than in MVC. We don't use cookies or redirects. We use JWT bearer tokens and JSON responses. The membership system is the same — the authentication layer is different."

> "This playlist is sequential. Video 1 is the concept. Every video after builds on it. Don't skip ahead — each piece depends on the one before."

**Analogy (say this):**

> "Think of Identity like a building's security system. The users are the people who live or work in the building. The roles are their access levels — 'resident', 'employee', 'maintenance'. The claims are their ID badges with specific permissions — 'can access floor 3', 'has parking pass'. The UserManager is the front desk that registers new people and issues badges. The SignInManager is the security guard who checks IDs at the door. The database is the records room where everything is stored. And the JWT token is the temporary badge you get when you sign in — it proves who you are for the next few hours."

**Common viewer questions to address:**

> "Do I need Identity if I'm building a simple API?" — If you need any user management (registration, login, roles, claims), yes. If you just need a single admin account hardcoded in config, no — but that doesn't scale.

> "Is Identity secure?" — Yes, it's battle-tested and used by millions of applications. It hashes passwords with PBKDF2, supports account lockout, security stamps, 2FA, and more. Security is a layer cake — Identity gives you the layers; you configure them correctly.

> "Can I use Identity with a frontend framework like React or Angular?" — Yes — that's actually the most common use case. Your React/Angular app is the client, your ASP.NET Core API is the server, and Identity + JWT connects them. The API never sees the frontend framework — it just receives HTTP requests with JWT tokens.

**What to show:**

- A simple diagram of the Identity architecture (drawn on a whiteboard or in a slide)
- The NuGet packages we'll install (listed on screen)
- A quick demo of what the final API will do (register, login, get JWT, call protected endpoint)

**What to skip:**

- Deep dive into the Identity source code (too detailed for Video 1)
- Comparison with IdentityServer / Duende / Azure AD (different topic — OAuth server vs. membership system)
- Cookie-based Identity in MVC (not relevant to our API focus)

---

## Complete Implementation

For Video 1, there is no code to write yet — this is the concept video. But here are the key things to reference for later videos:

### What We Will Build (the complete API)

By the end of the playlist, you will have an ASP.NET Core API with these endpoints:

```
POST   /api/accounts/register          → Register a new user
POST   /api/accounts/login             → Login, receive JWT
POST   /api/accounts/logout            → Logout (invalidate token / cleanup)
GET    /api/accounts/me                → Get current user profile
PUT    /api/accounts/me                → Update current user profile
POST   /api/accounts/forgot-password   → Trigger password reset email
POST   /api/accounts/reset-password    → Reset password with token
POST   /api/accounts/confirm-email     → Confirm email with token

GET    /api/roles                      → List all roles
POST   /api/roles                      → Create a role
PUT    /api/roles/{id}                 → Update a role
DELETE /api/roles/{id}                 → Delete a role
POST   /api/users/{userId}/roles      → Assign role(s) to a user
DELETE /api/users/{userId}/roles/{roleName} → Remove role from user
GET    /api/users/{userId}/roles      → Get user's roles

GET    /api/admin/users                → List all users (Admin only)
GET    /api/admin/users/{id}           → Get user by ID (Admin only)
PUT    /api/admin/users/{id}           → Update user (Admin only)
DELETE /api/admin/users/{id}           → Delete user (Admin only)

GET    /api/protected                  → Protected endpoint — any authenticated user
GET    /api/admin                      → Admin-only endpoint
GET    /api/management                 → Requires "Management" policy
```

All endpoints return JSON. All errors follow a consistent format. JWT is the authentication mechanism.

### The Project Structure We Build

```
IdentityApiTutorial/
├── Controllers/
│   ├── AccountsController.cs       ← Register, Login, Profile, Password reset
│   ├── RolesController.cs         ← Role CRUD
│   ├── UsersController.cs         ← User-role assignment
│   ├── AdminController.cs         ← Admin-only user management
│   └── ProtectedController.cs     ← Protected / admin / policy endpoints
├── DTOs/
│   ├── RegisterRequest.cs
│   ├── LoginRequest.cs
│   ├── LoginResponse.cs
│   ├── UserResponse.cs
│   ├── RoleRequest.cs
│   ├── RoleResponse.cs
│   └── ...
├── Models/
│   ├── ApplicationUser.cs         ← Custom IdentityUser subclass
│   ├── ApplicationRole.cs         ← Custom IdentityRole subclass
│   └── ...
├── Data/
│   └── IdentityDbContext.cs       ← EF Core DbContext for Identity
├── Services/
│   ├── JwtService.cs              ← Manual JWT token generation
│   ├── PasswordStrengthService.cs ← Password strength calculation
│   └── ...
├── Program.cs                     ← Identity + JWT configuration
├── appsettings.json               ← Connection string, JWT settings
└── IdentityApiTutorial.csproj     ← Project file with NuGet packages
```

### The NuGet Packages We Install

```
Microsoft.AspNetCore.Identity.EntityFrameworkCore
Microsoft.EntityFrameworkCore.SqlServer          (or Sqlite / Postgres)
Microsoft.EntityFrameworkCore.Tools              (for migrations)
Microsoft.EntityFrameworkCore.Design
System.IdentityModel.Tokens.Jwt                  (JWT handling)
Microsoft.AspNetCore.Authentication.JwtBearer   (JWT Bearer auth middleware)
```

---

## Postman / Swagger Tests

No testable endpoints yet — this is the concept video. But here is how you will use Postman throughout the playlist:

### Postman Setup (do this once)

1. **Create a collection** called "ASP.NET Core Identity API"
2. **Create an environment** with variables:
   - `baseUrl` = `https://localhost:7001` (or your API's URL)
   - `jwtToken` = (empty — filled after login)
   - `userId` = (empty — filled after registration)
3. **Set up the Authorization tab** on the collection:
   - Type: Bearer Token
   - Token: `{{jwtToken}}`
   - This automatically adds `Authorization: Bearer <token>` to every request

### Test Flow (throughout the playlist)

Every endpoint test follows this pattern:

1. **Register** a user → get user ID → save to `{{userId}}`
2. **Login** with that user → get JWT → save to `{{jwtToken}}`
3. **Call protected endpoints** with `{{jwtToken}}` in the Authorization header
4. **Verify** the response matches the expected JSON structure

### Response Format

All successful responses return JSON with a consistent shape:

```json
{
  "success": true,
  "data": { ... },
  "message": null
}
```

All error responses return JSON with:

```json
{
  "success": false,
  "data": null,
  "message": "Error description here",
  "errors": {
    "PropertyName": ["Error 1", "Error 2"]
  }
}
```

This is a custom wrapper — not the default ASP.NET Core problem details. You'll see it implemented in Video 07.

---

# Video 02 — Identity Architecture — Users, Roles, Claims, Managers, Stores

## Theory & Definitions

### The Five Pillars of Identity Architecture

Identity architecture is built on five interconnected pieces:

1. **User** (`IdentityUser` / your subclass) — the entity that represents a person in the system.
2. **Role** (`IdentityRole` / your subclass) — a named group for authorization scoping.
3. **Claim** (name-value pair) — a granular piece of information about the user.
4. **Manager** (`UserManager`, `SignInManager`, `RoleManager`) — the service layer that performs operations.
5. **Store** (`IUserStore`, `IRoleStore`) — the persistence abstraction that talks to the database.

### User — IdentityUser and Your Custom Subclass

`IdentityUser` is the default user class. It has these key properties:

| Property | Type | Purpose |
|----------|------|---------|
| `Id` | `string` | Primary key (GUID string) |
| `UserName` | `string` | Unique login name |
| `NormalizedUserName` | `string` | Uppercase version for case-insensitive lookups |
| `Email` | `string` | User's email address |
| `NormalizedEmail` | `string` | Uppercase version for case-insensitive lookups |
| `EmailConfirmed` | `bool` | Whether the email has been verified |
| `PasswordHash` | `string` | Hashed password (never plaintext) |
| `SecurityStamp` | `string` | Random value that changes when credentials change |
| `ConcurrencyStamp` | `string` | Optimistic concurrency token |
| `PhoneNumber` | `string` | User's phone number |
| `PhoneNumberConfirmed` | `bool` | Whether phone is verified |
| `TwoFactorEnabled` | `bool` | Whether 2FA is enabled |
| `LockoutEnabled` | `bool` | Whether lockout is enabled for this user |
| `LockoutEnd` | `DateTimeOffset?` | When lockout expires (null = not locked out) |
| `AccessFailedCount` | `int` | Failed login attempts (triggers lockout) |
| `Claims` | `ICollection<IdentityUserClaim>` | Navigation to user's claims |
| `Roles` | `ICollection<IdentityUserRole>` | Navigation to user's roles |
| `Logins` | `ICollection<IdentityUserLogin>` | Navigation to external logins |
| `Tokens` | `ICollection<IdentityUserToken>` | Navigation to tokens (reset, confirm, etc.) |

**Custom subclass pattern:**

```csharp
public class ApplicationUser : IdentityUser
{
    // Add custom properties here
    public string? FullName { get; set; }
    public string? Department { get; set; }
    public DateTime? DateOfBirth { get; set; }
}
```

You subclass `IdentityUser` when you need extra columns in the Users table. Identity's EF Core mapping picks up your subclass automatically — the extra properties become extra columns.

**When to subclass vs. use a profile / claims:**

| Need | Approach |
|------|----------|
| Extra columns on the Users table (FullName, Department, etc.) | Subclass `IdentityUser` |
| Data that varies per user and is queried separately (posts, orders, profile images) | Separate table, link by `UserId` |
| Permissions, roles, "what the user can do" | Claims and Roles (not custom columns) |
| Sensitive data (SSN, etc.) | Separate secured table — NOT on the IdentityUser |

### Role — IdentityRole and Your Custom Subclass

`IdentityRole` is the default role class:

| Property | Type | Purpose |
|----------|------|---------|
| `Id` | `string` | Primary key |
| `Name` | `string` | Human-readable role name ("Admin", "User") |
| `NormalizedName` | `string` | Uppercase version for lookups |
| `ConcurrencyStamp` | `string` | Optimistic concurrency |
| `Claims` | `ICollection<IdentityRoleClaim>` | Role-level claims (claims granted to everyone with this role) |

**Custom subclass pattern:**

```csharp
public class ApplicationRole : IdentityRole
{
    public string? Description { get; set; }
    public DateTime CreatedDate { get; set; } = DateTime.UtcNow;
}
```

Roles are simple — they're just named groups. What makes them powerful is how you use them in authorization: `[Authorize(Roles="Admin")]`, policy-based checks, and claims extracted from roles.

### Claim — What It Is and How It Works

A **claim** is a `System.Security.Claims.Claim` — a name-value pair:

```csharp
var claim = new Claim("department", "Engineering");
var claim = new Claim(ClaimTypes.Role, "Admin");
var claim = new Claim("permission", "can_edit_posts");
```

Claims are:
- **Attached to a user** — stored in the `AspNetUserClaims` table (via `UserManager.AddClaimAsync`).
- **Attached to a role** — stored in the `AspNetRoleClaims` table (via `RoleManager.AddClaimAsync`). Anyone with that role gets the claim.
- **Serialized into the JWT token** — when you generate a JWT, you include the user's claims as JWT claims. The client sends the JWT back, and the API reads the claims from it.

**Claim types:**

- `ClaimTypes.Name` — the user's name
- `ClaimTypes.Role` — a role (e.g., "Admin")
- `ClaimTypes.Email` — the user's email
- `ClaimTypes.NameIdentifier` — the user's ID (this is what Identity uses by default for the `sub` claim in JWT)
- Custom types — any string you want ("department", "permission", "scope")

**Claims vs. Roles — when to use which:**

| Situation | Use Role | Use Claim |
|-----------|----------|-----------|
| Group-based access ("Admins can do X") | ✅ Role | — |
| Fine-grained permission ("user can edit their own posts but not others") | — | ✅ Claim (e.g., "can_edit_own_posts") |
| User attribute used for display or logic ("department = Engineering") | — | ✅ Claim |
| Permission that applies to everyone with a role | Role claim (add claim to role, not user) | ✅ Add claim to `RoleManager` |
| Dynamic permission that changes at runtime | — | ✅ Add/remove claim from user |

**Key insight:** Roles are a shortcut for groups of claims. When you call `[Authorize(Roles="Admin")]`, what actually happens is: the system checks if the user has a claim of type `ClaimTypes.Role` with value "Admin". Roles *are* claims — they're just a special kind.

### UserManager — What It Does

`UserManager<TUser>` is the primary service for user operations:

| Method | What It Does |
|--------|-------------|
| `CreateAsync(user, password)` | Creates a new user with hashed password |
| `FindByIdAsync(id)` | Finds a user by ID |
| `FindByNameAsync(name)` | Finds a user by UserName |
| `FindByEmailAsync(email)` | Finds a user by Email |
| `UpdateAsync(user)` | Updates user properties (not password) |
| `DeleteAsync(user)` | Deletes the user |
| `ChangePasswordAsync(user, oldPwd, newPwd)` | Changes password (requires old password) |
| `ResetPasswordAsync(user, token, newPwd)` | Resets password with a token |
| `AddPasswordAsync(user, password)` | Adds a new password (for users with passwordless login) |
| `RemovePasswordAsync(user)` | Removes password |
| `GetPasswordHashAsync(user)` | Gets the hashed password |
| `AddClaimAsync(user, claim)` | Adds a claim to the user |
| `RemoveClaimAsync(user, claim)` | Removes a claim |
| `GetClaimsAsync(user)` | Gets all user claims |
| `AddToRoleAsync(user, roleName)` | Adds user to a role |
| `RemoveFromRoleAsync(user, roleName)` | Removes user from a role |
| `GetRolesAsync(user)` | Gets user's roles |
| `IsInRoleAsync(user, roleName)` | Checks if user is in a role |
| `GenerateEmailConfirmationTokenAsync(user)` | Generates an email confirmation token |
| `GeneratePasswordResetTokenAsync(user)` | Generates a password reset token |
| `ConfirmEmailAsync(user, token)` | Confirms email with token |
| `VerifyUserTokenAsync(user, tokenProvider, purpose, token)` | Verifies a token |
| `GetLockoutEnabledAsync(user)` | Checks if lockout is enabled |
| `SetLockoutEnabledAsync(user, enabled)` | Sets lockout enabled flag |
| `GetLockoutEndDateAsync(user)` | Gets lockout end date |
| `SetLockoutEndDateAsync(user, date)` | Sets lockout end date |
| `AccessFailedAsync(user)` | Increments failed access count |
| `ResetAccessFailedCountAsync(user)` | Resets failed access count |
| `GetTwoFactorEnabledAsync(user)` | Checks if 2FA is enabled |
| `SetTwoFactorEnabledAsync(user, enabled)` | Sets 2FA flag |

Every method returns `Task<IdentityResult>` (or `Task<T>` for queries). `IdentityResult` tells you if the operation succeeded or failed, with a list of `IdentityError` objects on failure.

### SignInManager — What It Does

`SignInManager<TUser>` handles sign-in flows:

| Method | What It Does |
|--------|-------------|
| `SignInAsync(user, isPersistent, authenticationMethod)` | Signs the user in (creates a cookie by default in MVC; in API, you use this to get the SignInResult and then issue a JWT) |
| `CheckPasswordSignInAsync(user, password, lockoutOnFailure)` | Checks password without signing in — returns `SignInResult` (Succeeded, IsLockedOut, IsNotAllowed, Failed) |
| `TwoFactorSignInAsync(provider, token, lockoutOnFailure, rememberMe)` | Signs in with 2FA token |
| `TwoFactorVerifyTokenAsync(user, provider)` | Verifies a 2FA token |
| `GetTwoFactorAuthenticationPageAsync()` | Returns the 2FA page model (MVC only) |
| `EnableTwoFactorAuthenticationAsync()` | Enables 2FA |
| `DisableTwoFactorAuthenticationAsync()` | Disables 2FA |
| `HasTwoFactorTokenAsync(user, provider)` | Checks if a 2FA token exists |
| `GenerateAuthenticationTokenAsync(user, tokenProvider, purpose)` | Generates a token for a purpose |
| `GetRecoveryCodesAsync(user)` | Gets 2FA recovery codes |
| `ConsumeRecoveryCodeAsync(user, code)` | Consumes a recovery code |
| `UnlockPerUserLockoutAsync(user)` | Unlocks a user (per-user lockout) |
| `IsLockedOutAsync(user)` | Checks if user is locked out |
| `RefreshSignInAsync(user)` | Refreshes the sign-in (updates security stamp, etc.) |
| `GetExternalLoginInfoAsync()` | Gets external login info (from OAuth provider) |

**Critical for API:** In an API, `SignInManager.SignInAsync` creates a cookie — we don't want that. Instead, we use `SignInManager.CheckPasswordSignInAsync` which returns a `SignInResult` without setting any cookie. We then use the `SignInResult.Succeeded` flag to decide whether to generate a JWT token.

### RoleManager — What It Does

`RoleManager<TRole>` handles role operations:

| Method | What It Does |
|--------|-------------|
| `CreateAsync(role)` | Creates a new role |
| `UpdateAsync(role)` | Updates a role |
| `DeleteAsync(role)` | Deletes a role |
| `FindByIdAsync(id)` | Finds role by ID |
| `FindByNameAsync(name)` | Finds role by name |
| `RoleExistsAsync(roleName)` | Checks if a role with that name exists |
| `AddClaimAsync(role, claim)` | Adds a claim to the role |
| `RemoveClaimAsync(role, claim)` | Removes a claim from the role |
| `GetClaimsAsync(role)` | Gets role claims |

### Stores — The Persistence Layer

Stores are the abstraction between the managers and the database:

- `IUserStore<TUser>` — persists users (create, update, delete, find, etc.)
- `IRoleStore<TRole>` — persists roles
- `IUserClaimStore<TUser>` — persists user claims
- `IUserRoleStore<TUser>` — persists user-role associations
- `IUserLoginStore<TUser>` — persists external logins
- `IUserTokenStore<TUser>` — persists tokens (confirmation, reset, etc.)
- `IUserPasswordStore<TUser>` — persists password hashes

By default, when you call `.AddEntityFrameworkStores<IdentityDbContext>()`, Identity registers EF Core implementations of all these stores. They map to the Identity tables in your database.

### The Database Schema — What Tables Identity Creates

When you run migrations, Identity creates these tables:

| Table | Purpose |
|-------|---------|
| `AspNetUsers` | Users (Id, UserName, Email, PasswordHash, SecurityStamp, etc.) |
| `AspNetRoles` | Roles (Id, Name, NormalizedName) |
| `AspNetUserRoles` | User-role mapping (UserId, RoleId) |
| `AspNetUserClaims` | User claims (Id, UserId, ClaimType, ClaimValue) |
| `AspNetRoleClaims` | Role claims (Id, RoleId, ClaimType, ClaimValue) |
| `AspNetUserLogins` | External logins (LoginProvider, ProviderKey, UserId) |
| `AspNetUserTokens` | Tokens (UserId, LoginProvider, Name, Value) |
| `AspNetClaimsPrincipal` | (optional, for data protection) |

These table names are conventions — you can customize them in `IdentityDbContext` if needed.

### How the Pieces Fit Together — Request Flow

Here's what happens when a user registers and then logs in:

**Registration flow:**

```
Client: POST /api/accounts/register { userName, password, email }
    ↓
AccountsController.Register()
    ↓
UserManager.CreateAsync(user, password)
    ↓
  → Password hashed with PBKDF2 (PasswordHasher)
  → User saved to AspNetUsers table (via IUserStore / EF Core)
  → IdentityResult returned (Success or errors)
    ↓
Controller returns 201 Created with user data (no password hash)
```

**Login flow:**

```
Client: POST /api/accounts/login { userName, password }
    ↓
AccountsController.Login()
    ↓
UserManager.FindByNameAsync(userName)  → finds user
    ↓
SignInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true)
    ↓
  → Password verified against hash (PasswordHasher)
  → Lockout checked (AccessFailedCount, LockoutEnd)
  → SignInResult returned (Succeeded / IsLockedOut / Failed)
    ↓
If Succeeded:
  → JwtService.GenerateJwtToken(user)  → creates JWT with claims
    ↓
Controller returns 200 OK with { token, expiresIn, user }
```

**Protected endpoint flow:**

```
Client: GET /api/protected  (with Authorization: Bearer <jwt>)
    ↓
JwtBearer middleware validates JWT signature + expiration
    ↓
HttpContext.User populated with claims from JWT
    ↓
ProtectedController.Get()
    ↓
[Authorize] / [Authorize(Roles="Admin")] / policy check
    ↓
If authorized → return data
If not → 401 Unauthorized / 403 Forbidden
```

---

## 🎬 Video Recording Notes

**Opening (say this):**

> "Now that we know WHAT Identity is, let's understand HOW it's built. Identity architecture has five pieces: Users, Roles, Claims, Managers, and Stores. Each piece has a specific job. When you understand how they fit together, everything else in this playlist makes sense — because every feature we build uses these same pieces."

**Show on screen:**

> Draw or show a diagram with five boxes: User, Role, Claim, Manager, Store. Draw arrows showing how they connect. Show the request flow for registration and login (step by step, as described in the Complete Implementation section).

**Key points to emphasize (say this):**

> "UserManager does USER things — create, find, update, delete, add claims, add roles. SignInManager does SIGN-IN things — check password, sign in, 2FA. RoleManager does ROLE things. Don't mix them up — each manager has a specific responsibility."

> "Stores are the database layer. You usually don't touch them directly — the managers use them. But it's important to know they exist, because if you want to customize persistence (use a different database, a non-relational store, or a custom implementation), you implement the store interfaces."

> "Claims are the most important concept to understand. Roles ARE claims. When you authorize with [Authorize(Roles='Admin')], you're checking for a claim. Everything in Identity authorization is claim-based under the hood."

> "The database schema is predictable. AspNetUsers, AspNetRoles, AspNetUserRoles, AspNetUserClaims, AspNetRoleClaims — these are the tables. You'll see them in your database viewer. Knowing the schema helps you debug — you can look at the raw data when something goes wrong."

**Analogy (say this):**

> "The architecture is like a company. The Users are the employees. The Roles are departments — 'Engineering', 'Sales', 'HR'. The Claims are the specific permissions each employee has — 'can approve expenses', 'can access the server room'. The Managers are the department heads — UserManager handles all employee operations, RoleManager handles department creation, SignInManager handles building entry. The Stores are the filing cabinets and databases where everything is recorded. And the JWT token is the employee badge — it proves who you are and what you're allowed to do, without the security guard needing to check the database every time."

**Common viewer questions:**

> "Do I need all five pieces?" — You need Users, UserManager, and a Store at minimum. Roles and RoleManager are optional but recommended for any application with different permission levels. Claims are always there (Identity uses them internally). You don't need to use all features — but understanding all five helps you make good decisions.

> "Can I use a database other than SQL Server?" — Yes. Identity works with any EF Core-supported database: PostgreSQL, MySQL, SQLite, Oracle, etc. You just change the connection string and the EF Core provider package.

> "What's the difference between UserManager and SignInManager?" — UserManager does data operations on users (CRUD, claims, roles, tokens). SignInManager does authentication operations (sign-in, sign-out, 2FA, external login). In our API, we mostly use UserManager for everything and only use SignInManager.CheckPasswordSignInAsync to verify passwords.

**What to show:**

- The five-box architecture diagram
- The request flow diagrams (registration, login, protected endpoint)
- The table list (AspNetUsers, etc.) — show them in SQL Server Management Studio or a database viewer
- A quick code snippet showing UserManager, SignInManager, RoleManager being injected into a controller

**What to skip:**

- Deep dive into how EF Core stores work internally (too detailed)
- Custom store implementation (covered in Video 18)
- Data protection and key rings (advanced topic)

---

## Complete Implementation

### The Five Managers — How to Inject Them

In Video 04 we configure Identity in Program.cs. Once configured, you can inject the managers into any controller or service:

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Controllers/AccountsController.cs (partial — showing DI)
// Video 02 — Identity architecture: managers and stores
// ─────────────────────────────────────────────────────────────────────────────
// This shows how the managers are injected into a controller.
// The managers are registered by AddIdentityCore in Program.cs.
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Controllers
{
    // ─────────────────────────────────────────────────────────────────────────────
    // [ApiController] — tells ASP.NET Core this is an API controller.
    //   → Automatic model validation (400 on invalid model)
    //   → Binding source inference ([FromBody], [FromQuery], etc.)
    //   → Problem details for errors (consistent JSON error format)
    // ─────────────────────────────────────────────────────────────────────────────
    [ApiController]

    // ─────────────────────────────────────────────────────────────────────────────
    // [Route("api/[controller]")] — sets the URL prefix.
    //   → [controller] resolves to "Accounts" (from AccountsController)
    //   → Full route: POST /api/accounts/register, POST /api/accounts/login
    // ─────────────────────────────────────────────────────────────────────────────
    [Route("api/[controller]")]
    public class AccountsController : ControllerBase
    {
        // ─────────────────────────────────────────────────────────────────────────
        // _userManager — the primary service for user operations.
        //   → Create, find, update, delete users
        //   → Add/remove claims, add/remove roles
        //   → Generate tokens (email confirm, password reset)
        //   → All methods return Task<IdentityResult> (or Task<T>)
        // ─────────────────────────────────────────────────────────────────────────
        private readonly UserManager<ApplicationUser> _userManager;

        // ─────────────────────────────────────────────────────────────────────────
        // _signInManager — handles sign-in operations.
        //   → In our API: we use CheckPasswordSignInAsync (returns SignInResult
        //     without creating a cookie).
        //   → We do NOT use SignInAsync (that creates a cookie — MVC behavior).
        // ─────────────────────────────────────────────────────────────────────────
        private readonly SignInManager<ApplicationUser> _signInManager;

        // ─────────────────────────────────────────────────────────────────────────
        // _roleManager — handles role operations.
        //   → Create, find, update, delete roles
        //   → Add/remove role claims
        //   → Check if role exists
        // ─────────────────────────────────────────────────────────────────────────
        private readonly RoleManager<ApplicationRole> _roleManager;

        // ─────────────────────────────────────────────────────────────────────────
        // _jwtService — our custom service for generating JWT tokens.
        //   → Not part of Identity — we write this ourselves.
        //   → Takes a user, builds a JWT with claims, signs it, returns the token.
        // ─────────────────────────────────────────────────────────────────────────
        private readonly JwtService _jwtService;

        // ─────────────────────────────────────────────────────────────────────────
        // Constructor — ASP.NET Core DI injects all dependencies.
        //   → UserManager, SignInManager, RoleManager come from Identity configuration.
        //   → JwtService is our custom service (registered in Program.cs).
        // ─────────────────────────────────────────────────────────────────────────
        public AccountsController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<ApplicationRole> roleManager,
            JwtService jwtService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _jwtService = jwtService;
        }

        // ... register, login, and other endpoints go here
        // (implemented in Videos 07, 08, 09)
    }
}
```

### IdentityUser Subclass — ApplicationUser

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Models/ApplicationUser.cs
// Video 02 — Identity architecture: custom user class
// ─────────────────────────────────────────────────────────────────────────────
// Subclass IdentityUser to add custom properties.
// These become extra columns in the AspNetUsers table.
//
// When to subclass:
//   → Add columns that are ALWAYS needed for every user (FullName, Department)
//   → Keep it lean — don't put everything here. Large data belongs in separate tables.
//
// When NOT to subclass:
//   → Domain data that's only for some users (Posts, Orders — separate table)
//   → Sensitive data (SSN — separate secured table)
//   → Things that change independently (profile image URL — can be separate)
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Identity;

namespace IdentityApiTutorial.Models
{
    // ─────────────────────────────────────────────────────────────────────────────
    // ApplicationUser — custom user class for our API.
    // ─────────────────────────────────────────────────────────────────────────────
    // Inherits from IdentityUser, which gives us:
    //   Id, UserName, Email, EmailConfirmed, PasswordHash, SecurityStamp,
    //   ConcurrencyStamp, PhoneNumber, PhoneNumberConfirmed,
    //   TwoFactorEnabled, LockoutEnabled, LockoutEnd, AccessFailedCount,
    //   Claims, Roles, Logins, Tokens (navigation properties)
    //
    // We add: FullName, Department, DateOfBirth
    // These become extra columns in AspNetUsers when we run migrations.
    // ─────────────────────────────────────────────────────────────────────────────
    public class ApplicationUser : IdentityUser
    {
        // ─────────────────────────────────────────────────────────────────────────
        // FullName — the user's display name.
        //   → Nullable (string?) because we don't require it at registration.
        //   → Becomes a NULLABLE NVARCHAR column in the database.
        // ─────────────────────────────────────────────────────────────────────────
        public string? FullName { get; set; }

        // ─────────────────────────────────────────────────────────────────────────
        // Department — the user's department.
        //   → Nullable — not all users have a department.
        //   → Could be a claim instead ("department" claim), but as a column
        //     it's easy to query and filter.
        // ─────────────────────────────────────────────────────────────────────────
        public string? Department { get; set; }

        // ─────────────────────────────────────────────────────────────────────────
        // DateOfBirth — for age-restricted content or personalization.
        //   → Nullable — not required.
        //   → DateTime in C# maps to DATETIME2 in SQL Server.
        // ─────────────────────────────────────────────────────────────────────────
        public DateTime? DateOfBirth { get; set; }
    }
}
```

### ApplicationRole Subclass

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Models/ApplicationRole.cs
// Video 02 — Identity architecture: custom role class
// ─────────────────────────────────────────────────────────────────────────────
// Subclass IdentityRole to add custom properties.
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Identity;

namespace IdentityApiTutorial.Models
{
    // ─────────────────────────────────────────────────────────────────────────────
    // ApplicationRole — custom role class.
    // ─────────────────────────────────────────────────────────────────────────────
    // Inherits from IdentityRole: Id, Name, NormalizedName, ConcurrencyStamp,
    //   Claims (navigation to IdentityRoleClaim)
    //
    // We add: Description (human-readable explanation of what the role does),
    //   CreatedDate (when the role was created — audit trail)
    // ─────────────────────────────────────────────────────────────────────────────
    public class ApplicationRole : IdentityRole
    {
        // ─────────────────────────────────────────────────────────────────────────
        // Description — explains what the role allows.
        //   → Nullable — not all roles need a description.
        //   → Useful for admin UIs that show role descriptions.
        // ─────────────────────────────────────────────────────────────────────────
        public string? Description { get; set; }

        // ─────────────────────────────────────────────────────────────────────────
        // CreatedDate — when the role was created.
        //   → Set to DateTime.UtcNow by default.
        //   → Useful for auditing and debugging.
        // ─────────────────────────────────────────────────────────────────────────
        public DateTime CreatedDate { get; set; } = DateTime.UtcNow;
    }
}
```

### IdentityDbContext — Connecting Identity to Your Database

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Data/IdentityDbContext.cs
// Video 02 — Identity architecture: DbContext
// ─────────────────────────────────────────────────────────────────────────────
// IdentityDbContext is the EF Core DbContext that Identity uses.
// It maps IdentityUser, IdentityRole, and all related entities to database tables.
//
// We subclass it to:
//   → Use our custom ApplicationUser and ApplicationRole
//   → Add any non-Identity DbSets (if we have other tables)
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using IdentityApiTutorial.Models;

namespace IdentityApiTutorial.Data
{
    // ─────────────────────────────────────────────────────────────────────────────
    // IdentityDbContext — our Identity database context.
    // ─────────────────────────────────────────────────────────────────────────────
    // Generic parameters:
    //   TUser = ApplicationUser — our custom user class
    //   TRole = ApplicationRole — our custom role class
    //
    // IdentityDbContext already includes:
    //   DbSet<TUser> Users
    //   DbSet<TRole> Roles
    //   DbSet<IdentityUserClaim> UserClaims
    //   DbSet<IdentityUserRole> UserRoles
    //   DbSet<IdentityUserLogin> UserLogins
    //   DbSet<IdentityUserToken> UserTokens
    //   DbSet<IdentityRoleClaim> RoleClaims
    //
    // We don't need to add these — IdentityDbContext has them.
    // ─────────────────────────────────────────────────────────────────────────────
    public class IdentityDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>
    {
        // ─────────────────────────────────────────────────────────────────────────
        // Constructor — takes DbContextOptions.
        //   → Options are configured in Program.cs with the connection string.
        //   → This is the standard pattern for EF Core DbContexts.
        // ─────────────────────────────────────────────────────────────────────────
        public IdentityDbContext(DbContextOptions<IdentityDbContext> options)
            : base(options)
        {
        }

        // ─────────────────────────────────────────────────────────────────────────
        // OnModelCreating — customize the EF Core model.
        //   → Call base.OnModelCreating first to let Identity configure its tables.
        //   → Add custom configurations here if needed.
        //
        // For now, we just call the base — Identity's default configuration is
        // sufficient for our tutorial. In advanced scenarios you might:
        //   → Rename tables (ToTable("MyUsers"))
        //   → Change column types
        //   → Add indexes
        // ─────────────────────────────────────────────────────────────────────────
        protected override void OnModelCreating(ModelBuilder builder)
        {
            // Call the base — Identity configures its own tables, relationships,
            // indexes, and constraints.
            base.OnModelCreating(builder);

            // Custom configurations can go here.
            // Example: rename a table
            // builder.Entity<ApplicationUser>().ToTable("MyUsers");
        }
    }
}
```

---

## Postman / Swagger Tests

**No testable endpoints yet** — this is the architecture video. But here are the Postman setup steps that we'll use throughout:

### Initial Postman Setup

1. Create a new collection: **"ASP.NET Core Identity API"**
2. Create an environment with these variables:
   - `baseUrl` = `https://localhost:7001` (update to your actual port)
   - `jwtToken` = (empty)
   - `userId` = (empty)
   - `userName` = `testuser`
   - `userPassword` = `Test@1234`
   - `userEmail` = `test@example.com`
3. In the collection's Authorization tab:
   - Type: **Bearer Token**
   - Token: `{{jwtToken}}`
   - This automatically adds the Authorization header to every request in the collection.

### Swagger Setup

1. In Program.cs, add:
   ```csharp
   builder.Services.AddEndpointsApiExplorer();
   builder.Services.AddSwaggerGen();
   ```
2. In Program.cs, add:
   ```csharp
   app.UseSwagger();
   app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Identity API v1"));
   ```
3. Run the API and navigate to `https://localhost:7001/swagger` to see all endpoints with "Try it out" buttons.

---

# Video 03 — Creating the API Project & Installing Packages

## Theory & Definitions

### What We're Building

We're creating an ASP.NET Core Web API project — not MVC, not Razor Pages, not a Blazor app. A pure API that returns JSON and accepts JWT bearer tokens.

### Why .NET 8/9 API Template?

The `dotnet new webapi` template creates:
- A `Program.cs` with the minimal hosting model (no `Startup.cs`).
- A `Controllers/` folder with an example `WeatherForecastController`.
- Swagger / OpenAPI configured by default.
- Kestrel web server configuration.

We'll remove the example controller and build our Identity API from scratch.

### The NuGet Packages

| Package | Purpose | Version (examples) |
|---------|---------|--------------------|
| `Microsoft.AspNetCore.Identity.EntityFrameworkCore` | Identity integration with EF Core — UserManager, SignInManager, RoleManager, IdentityDbContext | 8.x / 9.x |
| `Microsoft.EntityFrameworkCore.SqlServer` | EF Core provider for SQL Server | 8.x / 9.x |
| `Microsoft.EntityFrameworkCore.Tools` | EF Core CLI tools for migrations (`dotnet ef`) | 8.x / 9.x |
| `Microsoft.EntityFrameworkCore.Design` | Design-time services for EF Core (required for migrations) | 8.x / 9.x |
| `System.IdentityModel.Tokens.Jwt` | JWT token creation and validation (low-level JWT library) | 7.x / 8.x |
| `Microsoft.AspNetCore.Authentication.JwtBearer` | JWT Bearer authentication middleware for ASP.NET Core | 8.x / 9.x |

**Note on versions:** Use the versions that match your .NET SDK. For .NET 8, use 8.x packages. For .NET 9, use 9.x packages. The exact version numbers will be resolved by `dotnet restore`.

### Package Reference in .csproj

```xml
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>

  <ItemGroup>
    <!-- Identity with EF Core -->
    <PackageReference Include="Microsoft.AspNetCore.Identity.EntityFrameworkCore"
                      Version="8.0.*" />

    <!-- EF Core SQL Server provider -->
    <PackageReference Include="Microsoft.EntityFrameworkCore.SqlServer"
                      Version="8.0.*" />

    <!-- EF Core tools (for dotnet ef migrations) -->
    <PackageReference Include="Microsoft.EntityFrameworkCore.Tools"
                      Version="8.0.*" />

    <!-- EF Core design-time services -->
    <PackageReference Include="Microsoft.EntityFrameworkCore.Design"
                      Version="8.0.*" />

    <!-- JWT token handling -->
    <PackageReference Include="System.IdentityModel.Tokens.Jwt"
                      Version="7.0.*" />

    <!-- JWT Bearer authentication middleware -->
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer"
                      Version="8.0.*" />
  </ItemGroup>
</Project>
```

### .NET CLI Commands

```bash
# Create the project
dotnet new webapi -n IdentityApiTutorial -o IdentityApiTutorial

# Install packages
cd IdentityApiTutorial
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore
dotnet add package Microsoft.EntityFrameworkCore.SqlServer
dotnet add package Microsoft.EntityFrameworkCore.Tools
dotnet add package Microsoft.EntityFrameworkCore.Design
dotnet add package System.IdentityModel.Tokens.Jwt
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer

# Restore (usually automatic, but good to verify)
dotnet restore
```

### Alternative: Visual Studio / Rider

- **Visual Studio:** File → New → Project → ASP.NET Core Web API → name it "IdentityApiTutorial" → check "Use controllers" → uncheck "Enable OpenAPI support" (we'll add it manually for control) or leave it checked.
- **Rider:** File → New → Project → ASP.NET Core Web API → same options.

---

## 🎬 Video Recording Notes

**Opening (say this):**

> "Let's build the project from scratch. We're creating an ASP.NET Core Web API — no MVC, no views, just JSON endpoints. I'll show you the exact commands to run, the packages to install, and why each package matters. By the end of this video, you'll have a working API project ready for Identity configuration."

**Show on screen:**

> Terminal / command prompt with the `dotnet new` and `dotnet add package` commands. Show the `.csproj` file after packages are added. Show the project folder structure in Explorer / Finder.

**Key points to emphasize (say this):**

> "We use `dotnet new webapi`, not `dotnet new mvc` or `dotnet new razor`. We want a pure API — controllers that return JSON, not HTML views."

> "Identity.EntityFrameworkCore is the package that brings UserManager, SignInManager, RoleManager, and IdentityDbContext. Without it, you don't have Identity."

> "EF Core Tools is for migrations — `dotnet ef migrations add` and `dotnet ef database update`. You need it at design time, and it's referenced in the .csproj."

> "System.IdentityModel.Tokens.Jwt is the low-level JWT library. We use it to create JWT tokens manually — not through the ASP.NET Core auth system, but by building the token ourselves and signing it."

> "Microsoft.AspNetCore.Authentication.JwtBearer is the middleware that validates JWT tokens on incoming requests. It reads the Authorization header, validates the signature, and populates HttpContext.User with the claims."

**Analogy (say this):**

> "Think of the packages like tools in a toolbox. Identity.EntityFrameworkCore is the power drill — it does the heavy lifting (users, roles, claims). EntityFrameworkCore.SqlServer is the drill bit — it tells the drill how to connect to SQL Server. JWT Bearer is the security system — it checks IDs at the door. And System.IdentityModel.Tokens.Jwt is the badge printer — it creates the badges (JWT tokens) that people wear."

**Common viewer questions:**

> "Can I use SQLite instead of SQL Server?" — Yes. Replace `Microsoft.EntityFrameworkCore.SqlServer` with `Microsoft.EntityFrameworkCore.Sqlite`. The connection string changes too. SQLite is great for development and testing.

> "What .NET version should I use?" — .NET 8 LTS is the current recommended version. It's supported until November 2026. .NET 9 is available but is a standard-term release. For tutorials and production, .NET 8 LTS is the safe choice.

> "Do I need all these packages?" — Identity.EntityFrameworkCore and EF Core SQL Server are required. JWT Bearer is required for API auth. System.IdentityModel.Tokens.Jwt is needed if you manually generate JWTs (which we do). EF Core Tools and Design are for migrations — required at development time.

**What to show:**

- `dotnet new webapi` command and result
- `dotnet add package` commands (one by one, showing output)
- The final `.csproj` file with all PackageReference elements
- The project folder structure (Controllers/, Models/, DTOs/, Data/, etc. — we'll create these in later videos)

**What to skip:**

- Docker setup (can be a separate video later)
- CI/CD pipeline (out of scope)
- Azure deployment (out of scope)

---

## Complete Implementation

### Step 1: Create the Project

```bash
# Create a new ASP.NET Core Web API project
dotnet new webapi -n IdentityApiTutorial -o IdentityApiTutorial

# Navigate into the project
cd IdentityApiTutorial
```

### Step 2: Install NuGet Packages

```bash
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore
dotnet add package Microsoft.EntityFrameworkCore.SqlServer
dotnet add package Microsoft.EntityFrameworkCore.Tools
dotnet add package Microsoft.EntityFrameworkCore.Design
dotnet add package System.IdentityModel.Tokens.Jwt
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
```

### Step 3: Verify the .csproj File

After installing packages, your `.csproj` file should look like this:

```xml
<Project Sdk="Microsoft.NET.Sdk.Web">

  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="8.0.*" />
    <PackageReference Include="Microsoft.AspNetCore.Identity.EntityFrameworkCore" Version="8.0.*" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.Design" Version="8.0.*" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.SqlServer" Version="8.0.*" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.Tools" Version="8.0.*" />
    <PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="7.0.*" />
  </ItemGroup>

</Project>
```

### Step 4: Clean Up the Template Files

Remove the default `WeatherForecastController.cs` (or any example controller) and the `WeatherForecast.cs` model — we'll replace them with our Identity API.

```bash
# Remove the default WeatherForecast files
rm Controllers/WeatherForecastController.cs
rm WeatherForecast.cs
# Or on Windows:
# del Controllers\WeatherForecastController.cs
# del WeatherForecast.cs
```

### Step 5: Create the Folder Structure

```bash
# Create folders for our code
mkdir Controllers
mkdir Models
mkdir DTOs
mkdir Data
mkdir Services
mkdir Validators
```

### Step 6: Verify the Project Builds

```bash
dotnet build
```

You should see: `Build succeeded.` with no errors.

---

## Postman / Swagger Tests

### Swagger Verification

After running `dotnet run` or pressing F5 in Visual Studio, navigate to:

```
https://localhost:7001/swagger
```

(Replace 7001 with your actual port from the terminal output or launchSettings.json.)

You should see the Swagger UI with no endpoints (we haven't added any yet). This confirms Swagger is configured correctly.

### Postman Setup (do this now)

1. **Create a collection:** "ASP.NET Core Identity API"
2. **Create an environment** with variables:
   - `baseUrl` = `https://localhost:7001`
   - `jwtToken` = (empty)
   - `userId` = (empty)
   - `userName` = `testuser`
   - `userPassword` = `Test@1234`
   - `userEmail` = `test@example.com`
3. **Set collection Authorization:** Bearer Token, token = `{{jwtToken}}`

We'll use these throughout the playlist. Fill in `jwtToken` and `userId` after Video 07 (registration) and Video 08 (login).

---

# Video 04 — Configuring Identity Services in Program.cs (API + JWT)

## Theory & Definitions

### What Program.cs Does in the Minimal Hosting Model

In .NET 6+, `Program.cs` is the entry point. It:
1. Creates a `WebApplicationBuilder` (the `Builder` pattern for DI and configuration).
2. Configures services (adds them to the DI container).
3. Builds the `WebApplication`.
4. Configures the middleware pipeline (authentication, authorization, routing, etc.).
5. Runs the application.

There is no `Startup.cs` — everything is in `Program.cs`. This is the **minimal hosting model**.

### Identity Configuration — AddIdentityCore vs. AddIdentity

**`AddIdentity<TUser, TRole>()`** — the full Identity setup:
- Registers all Identity services.
- Adds **cookie-based authentication** by default (Cookie Authentication Middleware).
- Adds default UI (if using Razor Pages / MVC).
- Adds the Identity UI scaffolding.

**`AddIdentityCore<TUser>()`** — the lightweight API-friendly setup:
- Registers only the core Identity services (UserManager, SignInManager, etc.).
- Does **NOT** add cookie authentication by default.
- Does **NOT** add Identity UI.
- Lighter pipeline — exactly what an API needs.
- You add JWT Bearer authentication separately.

**Why AddIdentityCore for APIs:**

In an API, we don't want cookie authentication. We want JWT bearer tokens. `AddIdentityCore` gives us the Identity services without the cookie middleware. We then add JWT Bearer authentication ourselves.

### JWT Bearer Authentication — How It Works

JWT Bearer authentication works in two directions:

**1. Outgoing (issuing tokens):**
- When a user logs in successfully, we create a JWT token manually (using `System.IdentityModel.Tokens.Jwt`).
- We sign it with a secret key (HMAC-SHA256 or an RSA key).
- We return it to the client.
- The client stores it and sends it in the `Authorization: Bearer <token>` header on future requests.

**2. Incoming (validating tokens):**
- The `JwtBearer` middleware intercepts incoming requests.
- It reads the `Authorization: Bearer <token>` header.
- It validates the token signature, expiration, issuer, audience, etc.
- If valid, it creates a `ClaimsPrincipal` from the JWT claims and sets `HttpContext.User`.
- If invalid, it returns 401 Unauthorized.

### The JWT Token Structure

A JWT token has three parts, separated by dots:

```
header.payload.signature
```

**Header:** `{"alg": "HS256", "typ": "JWT"}` — algorithm and type, Base64Url encoded.

**Payload (claims):** `{"sub": "user-id", "name": "Ahmad", "role": "Admin", "exp": 1234567890, ...}` — the claims, Base64Url encoded.

**Signature:** HMAC-SHA256 of (header + "." + payload) with the secret key — ensures the token hasn't been tampered with.

The client can decode the payload (it's just Base64Url encoded, not encrypted), but cannot forge the signature without the secret key.

### JWT Claims We Include

| Claim | JWT Claim Name | Source | Purpose |
|-------|---------------|--------|---------|
| User ID | `sub` (subject) | `user.Id` | Uniquely identifies the user |
| UserName | `username` (custom) | `user.UserName` | Display name |
| Email | `email` (custom or `email`) | `user.Email` | Email address |
| Roles | `role` (custom, or `roles` as array) | `userManager.GetRolesAsync(user)` | Role-based authorization |
| Issued At | `iat` | Current time | When the token was issued |
| Expiration | `exp` | Issued At + expiration window | When the token expires |

### Configuration Settings — appsettings.json

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=IdentityApiDb;Trusted_Connection=True;TrustServerCertificate=True;"
  },
  "JwtSettings": {
    "SecretKey": "your-256-bit-secret-key-here-at-least-32-characters-long",
    "Issuer": "IdentityApiTutorial",
    "Audience": "IdentityApiTutorialClients",
    "ExpirationInMinutes": 60
  }
}
```

**Security note:** The `SecretKey` must be:
- At least 256 bits (32 characters) for HS256.
- Stored securely — not in source code in production. Use Azure Key Vault, environment variables, or user secrets.
- In development, you can use user secrets or a hardcoded key (for testing only).

### The Full Program.cs Configuration

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using IdentityApiTutorial.Data;
using IdentityApiTutorial.Models;
using IdentityApiTutorial.Services;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// ─────────────────────────────────────────────────────────────────────────────
// 1. Database Context — register IdentityDbContext with SQL Server
// ─────────────────────────────────────────────────────────────────────────────
builder.Services.AddDbContext<IdentityDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// ─────────────────────────────────────────────────────────────────────────────
// 2. Identity Core — register Identity services (NO cookie auth)
// ─────────────────────────────────────────────────────────────────────────────
builder.Services.AddIdentityCore<ApplicationUser>(options =>
{
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.MaxRepeatedChars = 3;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // User settings
    options.User.RequireUniqueEmail = true;
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
})
.AddEntityFrameworkStores<IdentityDbContext>()
.AddRoles<ApplicationRole>()
.AddDefaultTokenProviders();

// ─────────────────────────────────────────────────────────────────────────────
// 3. JWT Authentication — configure JWT Bearer authentication
// ─────────────────────────────────────────────────────────────────────────────
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"];

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
        ClockSkew = TimeSpan.Zero  // Remove default 5-minute clock skew
    };
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Authorization — enable policy-based authorization
// ─────────────────────────────────────────────────────────────────────────────
builder.Services.AddAuthorization();

// ─────────────────────────────────────────────────────────────────────────────
// 5. Custom services — register our JwtService
// ─────────────────────────────────────────────────────────────────────────────
builder.Services.AddScoped<JwtService>();

// ─────────────────────────────────────────────────────────────────────────────
// 6. Controllers + Swagger
// ─────────────────────────────────────────────────────────────────────────────
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "ASP.NET Core Identity API",
        Version = "v1",
        Description = "A complete API for user registration, login, roles, and authorization using ASP.NET Core Identity and JWT."
    });

    // Add JWT Bearer authentication to Swagger UI
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token.",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Build and configure the pipeline
// ─────────────────────────────────────────────────────────────────────────────
var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// ──── MIDDLEWARE ORDER MATTERS ────
// Authentication MUST come before Authorization
app.UseAuthentication();   // Validates JWT tokens on incoming requests
app.UseAuthorization();    // Checks [Authorize] attributes and policies

app.MapControllers();

app.Run();
```

### Line-by-Line Explanation of Key Sections

**Section 1 — Database Context:**

```csharp
builder.Services.AddDbContext<IdentityDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
```

- `AddDbContext<IdentityDbContext>` — registers `IdentityDbContext` as a scoped service in DI.
- `options.UseSqlServer(connectionString)` — tells EF Core to use SQL Server with the given connection string.
- The connection string comes from `appsettings.json` via `builder.Configuration`.
- Every time a controller requests `IdentityDbContext`, it gets a new instance scoped to the current request.

**Section 2 — Identity Core:**

```csharp
builder.Services.AddIdentityCore<ApplicationUser>(options => { ... })
    .AddEntityFrameworkStores<IdentityDbContext>()
    .AddRoles<ApplicationRole>()
    .AddDefaultTokenProviders();
```

- `AddIdentityCore<ApplicationUser>` — registers UserManager, SignInManager, and all core Identity services for `ApplicationUser`. No cookie auth.
- `options.Password.*` — configures password validation rules.
- `options.Lockout.*` — configures account lockout behavior.
- `options.User.RequireUniqueEmail` — requires email to be unique across all users.
- `.AddEntityFrameworkStores<IdentityDbContext>()` — registers EF Core stores that use our DbContext for persistence.
- `.AddRoles<ApplicationRole>()` — enables role management with our custom `ApplicationRole` class.
- `.AddDefaultTokenProviders()` — registers the default token providers (for email confirmation, password reset, etc.). These generate tokens that are valid for a configurable time.

**Section 3 — JWT Authentication:**

```csharp
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
        ClockSkew = TimeSpan.Zero
    };
});
```

- `AddAuthentication` — registers the authentication services.
- `DefaultAuthenticateScheme` — the scheme to use when no scheme is specified. Set to JWT Bearer.
- `DefaultChallengeScheme` — the scheme to use when a user is not authenticated and the resource requires authentication. Set to JWT Bearer (returns 401).
- `AddJwtBearer` — adds the JWT Bearer authentication handler.
- `TokenValidationParameters` — controls how JWT tokens are validated:
  - `ValidateIssuer` — check that the token was issued by our server (`ValidIssuer`).
  - `ValidateAudience` — check that the token is for our API (`ValidAudience`).
  - `ValidateLifetime` — check that the token hasn't expired (`exp` claim).
  - `ValidateIssuerSigningKey` — check that the token was signed with our key.
  - `IssuerSigningKey` — the key used to sign and validate tokens. We use `SymmetricSecurityKey` (HMAC-SHA256) with our secret key.
  - `ClockSkew` — allows for slight time differences between servers. `TimeSpan.Zero` means no tolerance — the token expiration is checked exactly. Use a small skew (e.g., 30 seconds) in production to handle clock differences.

**Section 4 — Authorization:**

```csharp
builder.Services.AddAuthorization();
```

- Registers the authorization services.
- Enables `[Authorize]` attributes, policy-based authorization, and role/claim checks.
- Without this, `[Authorize]` attributes are ignored.

**Section 5 — Custom Services:**

```csharp
builder.Services.AddScoped<JwtService>();
```

- Registers our `JwtService` as a scoped service.
- Scoped means one instance per request — appropriate for a service that generates tokens (it reads configuration, builds a token, returns it — no state to share across requests).

**Section 6 — Controllers + Swagger:**

```csharp
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(...);
```

- `AddControllers()` — registers the controller infrastructure (routing, model binding, validation, etc.).
- `AddEndpointsApiExplorer()` — required for Swagger to discover endpoints.
- `AddSwaggerGen()` — configures Swagger generation. We also add JWT Bearer security definition so Swagger UI shows an "Authorize" button.

**Middleware Order:**

```csharp
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
```

- `UseAuthentication()` — adds the authentication middleware to the pipeline. It runs first, validates the JWT, and sets `HttpContext.User`.
- `UseAuthorization()` — adds the authorization middleware. It runs after authentication, checks `[Authorize]` attributes, and returns 401/403 if unauthorized.
- `MapControllers()` — maps controller routes to the pipeline.
- **Order matters:** Authentication must come before Authorization. If you swap them, Authorization runs before Authentication has set `HttpContext.User`, and it will always fail.

---

## 🎬 Video Recording Notes

**Opening (say this):**

> "This is where the magic happens — Program.cs. This single file configures everything: the database, Identity services, JWT authentication, authorization, and our custom services. I'll walk through it line by line, explain why each piece is there, and show you the most common mistakes people make when configuring Identity in an API."

**Show on screen:**

> The full `Program.cs` file. Highlight each section as you explain it. Show the `appsettings.json` file with the connection string and JWT settings. Show the Swagger UI with the "Authorize" button after running the API.

**Key points to emphasize (say this):**

> "AddIdentityCore — not AddIdentity. AddIdentity adds cookie authentication, which we don't want in an API. AddIdentityCore gives us UserManager, SignInManager, and all the Identity services without the cookie middleware."

> "JWT authentication has two parts: issuing tokens (we do that manually in our JwtService after login) and validating tokens (the JwtBearer middleware does that automatically on every request). Both are configured in Program.cs."

> "Middleware order is critical. UseAuthentication before UseAuthorization. If you get it wrong, every request fails with 401 even when the user is authenticated."

> "The secret key must be at least 256 bits for HS256. Store it securely in production — never commit it to source control. In development, use user secrets or a .env file."

> "ClockSkew = TimeSpan.Zero means no tolerance for clock differences. In production, consider a small skew (30 seconds) to handle servers with slightly different clocks."

**Analogy (say this):**

> "Program.cs is like the control room of a building. The database context is the wiring that connects to the database. Identity Core is the security system installer — it sets up the cameras, the badge readers, the access control. JWT Bearer is the badge scanner at the door — it reads badges and decides who gets in. Authorization is the access control policy — it checks if the person with the badge is allowed in that room. And the middleware order is the order you walk through the building — you scan your badge (authenticate) before the door checks if you're allowed (authorize)."

**Common viewer questions:**

> "Why not use AddIdentity?" — AddIdentity adds cookie authentication, which sets cookies and does redirects. In an API, we want JWT bearer tokens and JSON responses, not cookies and redirects. AddIdentityCore is the lighter version that gives us the Identity services without the cookie infrastructure.

> "What if I want both JWT and cookies?" — You can add both authentication schemes. Set the default scheme to JWT Bearer for the API, and add cookie authentication as a secondary scheme for any MVC parts. But for a pure API, stick with JWT Bearer only.

> "How do I rotate the JWT secret key?" — Generate a new key, update the configuration, and issue new tokens. Old tokens signed with the old key will fail validation. This is a production ops concern — for the tutorial, we use a single key.

> "What's the difference between Issuer and Audience?" — Issuer is who created the token (our API). Audience is who the token is for (our API's clients). Both are validated to prevent tokens issued for one API from being used on another. In a simple setup, both can be the same string.

**What to show:**

- The full Program.cs file, section by section
- The appsettings.json file
- Swagger UI with the "Authorize" button
- Running the API and seeing it start without errors
- A test request to a non-existent endpoint returning 404 (to show the API is running)

**What to skip:**

- Data protection configuration (advanced — covered lightly if at all)
- Multiple authentication schemes (keep it simple with JWT Bearer only)
- OAuth / OpenID Connect configuration (different topic)
- Azure AD / external identity provider integration (different topic)

---

## Complete Implementation

### File: appsettings.json

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=IdentityApiDb;Trusted_Connection=True;TrustServerCertificate=True;"
  },
  "JwtSettings": {
    "SecretKey": "YourSuperSecretKeyThatIsAtLeast32CharactersLong!",
    "Issuer": "IdentityApiTutorial",
    "Audience": "IdentityApiTutorialClients",
    "ExpirationInMinutes": 60
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*"
}
```

**Important:** The `SecretKey` must be at least 32 characters (256 bits) for HS256. Replace with your own key. In production, use environment variables or Azure Key Vault — never store secrets in `appsettings.json` committed to source control.

### File: Program.cs — Complete Configuration

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Program.cs
// Video 04 — Identity + JWT Configuration for an API
// ─────────────────────────────────────────────────────────────────────────────
// This file configures:
//   1. Database context (IdentityDbContext with SQL Server)
//   2. Identity Core services (UserManager, SignInManager, RoleManager)
//   3. JWT Bearer authentication (token validation on incoming requests)
//   4. Authorization services ([Authorize] attributes, policies)
//   5. Custom services (JwtService for manual token generation)
//   6. Controllers + Swagger (with JWT Bearer security definition)
//
// This is the minimal hosting model (.NET 6+). No Startup.cs.
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using IdentityApiTutorial.Data;
using IdentityApiTutorial.Models;
using IdentityApiTutorial.Services;
using System.Text;

// ─────────────────────────────────────────────────────────────────────────────
// Create the WebApplicationBuilder.
//   → WebApplication.CreateBuilder(args) creates a builder with:
//     - Configuration (from appsettings.json, environment variables, etc.)
//     - DI container (IServiceCollection)
//     - Host configuration (Kestrel, etc.)
// ─────────────────────────────────────────────────────────────────────────────
var builder = WebApplication.CreateBuilder(args);

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 1: Database Context
// ═══════════════════════════════════════════════════════════════════════════════
// Register IdentityDbContext as a scoped service.
//   → Scoped = one instance per HTTP request.
//   → UseSqlServer = use the SQL Server EF Core provider.
//   → Connection string from appsettings.json via Configuration.
// ─────────────────────────────────────────────────────────────────────────────
builder.Services.AddDbContext<IdentityDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 2: Identity Core Services
// ═══════════════════════════════════════════════════════════════════════════════
// AddIdentityCore<ApplicationUser> registers:
//   → UserManager<ApplicationUser>
//   → SignInManager<ApplicationUser>
//   → IdentityErrorDescriber (error messages)
//   → PasswordHasher<ApplicationUser>
//   → And all other core Identity services
//
// Uses AddIdentityCore (NOT AddIdentity):
//   → AddIdentity adds cookie authentication (not wanted in API)
//   → AddIdentityCore gives us services only — we add JWT separately
//
// Configure options:
//   → Password: minimum length, digit, uppercase, lowercase, non-alphanumeric
//   → Lockout: 5 failed attempts → 5-minute lockout
//   → User: unique email required, allowed characters for UserName
// ─────────────────────────────────────────────────────────────────────────────
builder.Services.AddIdentityCore<ApplicationUser>(options =>
{
    // ─────────────────────────────────────────────────────────────────────────
    // Password settings — Identity validates these on CreateAsync and
    // ChangePasswordAsync. If any rule fails, IdentityResult has errors.
    // ─────────────────────────────────────────────────────────────────────────
    options.Password.RequireDigit = true;              // Must contain 0-9
    options.Password.RequiredLength = 8;               // Minimum 8 characters
    options.Password.RequireNonAlphanumeric = true;    // Must contain !, @, #, etc.
    options.Password.RequireUppercase = true;          // Must contain A-Z
    options.Password.RequireLowercase = true;          // Must contain a-z
    options.Password.MaxRepeatedChars = 3;             // No more than 3 identical consecutive chars

    // ─────────────────────────────────────────────────────────────────────────
    // Lockout settings — controls account lockout behavior.
    //   → DefaultLockoutTimeSpan: how long a lockout lasts (5 minutes)
    //   → MaxFailedAccessAttempts: failed logins before lockout (5)
    //   → AllowedForNewUsers: whether new users are lockout-enabled by default
    // ─────────────────────────────────────────────────────────────────────────
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // ─────────────────────────────────────────────────────────────────────────
    // User settings — controls UserName and Email validation.
    //   → RequireUniqueEmail: each email must be unique (no duplicates)
    //   → AllowedUserNameCharacters: characters allowed in UserName
    // ─────────────────────────────────────────────────────────────────────────
    options.User.RequireUniqueEmail = true;
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
})
// ─────────────────────────────────────────────────────────────────────────────
// AddEntityFrameworkStores<IdentityDbContext> — registers EF Core stores.
//   → IUserStore, IUserClaimStore, IUserRoleStore, IUserLoginStore,
//     IUserTokenStore, IUserPasswordStore, etc.
//   → All backed by IdentityDbContext and our database.
// ─────────────────────────────────────────────────────────────────────────────
.AddEntityFrameworkStores<IdentityDbContext>()
// ─────────────────────────────────────────────────────────────────────────────
// AddRoles<ApplicationRole> — enables role management with our custom role.
//   → Registers RoleManager<ApplicationRole>
//   → Without this, roles are not available (IdentityUser has no role support)
// ─────────────────────────────────────────────────────────────────────────────
.AddRoles<ApplicationRole>()
// ─────────────────────────────────────────────────────────────────────────────
// AddDefaultTokenProviders — registers token providers for:
//   → Email confirmation tokens
//   → Password reset tokens
//   → Any other token-based operations
//   → These tokens are time-limited and single-use.
// ─────────────────────────────────────────────────────────────────────────────
.AddDefaultTokenProviders();

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 3: JWT Bearer Authentication
// ═══════════════════════════════════════════════════════════════════════════════
// Configure JWT Bearer as the default authentication scheme.
//   → On incoming requests: validates JWT tokens from Authorization header
//   → On challenges: returns 401 when user is not authenticated
//
// TokenValidationParameters controls how tokens are validated:
//   → ValidateIssuer: check the "iss" claim matches our issuer
//   → ValidateAudience: check the "aud" claim matches our audience
//   → ValidateLifetime: check the "exp" claim (token not expired)
//   → ValidateIssuerSigningKey: check the signature with our key
//   → IssuerSigningKey: the key used to sign/validate (SymmetricSecurityKey)
//   → ClockSkew: time tolerance for clock differences (Zero = exact)
// ─────────────────────────────────────────────────────────────────────────────
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"];

builder.Services.AddAuthentication(options =>
{
    // Default scheme for authentication (validating incoming tokens)
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    // Default scheme for challenges (when user is not authenticated)
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        // Validate the issuer claim ("iss")
        ValidateIssuer = true,
        // Validate the audience claim ("aud")
        ValidateAudience = true,
        // Validate the expiration claim ("exp")
        ValidateLifetime = true,
        // Validate the token signature
        ValidateIssuerSigningKey = true,

        // The issuer — must match the "iss" claim in the token
        ValidIssuer = jwtSettings["Issuer"],

        // The audience — must match the "aud" claim in the token
        ValidAudience = jwtSettings["Audience"],

        // The signing key — used to validate the token signature.
        // SymmetricSecurityKey = HMAC-SHA256 (HS256 algorithm).
        // Encoding.UTF8.GetBytes converts the string key to bytes.
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),

        // Clock skew — time tolerance for differences between server clocks.
        // TimeSpan.Zero = no tolerance (exact matching).
        // In production, consider TimeSpan.FromMinutes(0.5) for 30-second tolerance.
        ClockSkew = TimeSpan.Zero
    };
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 4: Authorization Services
// ═══════════════════════════════════════════════════════════════════════════════
// AddAuthorization registers the authorization infrastructure:
//   → [Authorize] attribute support
//   → Policy-based authorization (requirements, handlers)
//   → Role-based authorization ([Authorize(Roles="Admin")])
//   → Claim-based authorization
//
// Without this, [Authorize] attributes are ignored and all endpoints are public.
// ─────────────────────────────────────────────────────────────────────────────
builder.Services.AddAuthorization();

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 5: Custom Services
// ═══════════════════════════════════════════════════════════════════════════════
// Register our custom JwtService as a scoped service.
//   → Scoped = one instance per HTTP request.
//   → JwtService generates JWT tokens manually (not through the auth system).
//   → It reads configuration, builds claims, signs the token, returns it.
// ─────────────────────────────────────────────────────────────────────────────
builder.Services.AddScoped<JwtService>();

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 6: Controllers + Swagger (OpenAPI)
// ═══════════════════════════════════════════════════════════════════════════════
// AddControllers — registers the controller infrastructure:
//   → Routing, model binding, model validation, JSON serialization.
//   → [ApiController] features: automatic 400 on invalid model, problem details.
//
// AddEndpointsApiExplorer — required for Swagger to discover endpoints.
//
// AddSwaggerGen — configures Swagger/OpenAPI document generation:
//   → SwaggerDoc: metadata (title, version, description).
//   → AddSecurityDefinition: adds "Bearer" security scheme to Swagger UI.
//   → AddSecurityRequirement: requires Bearer token for all endpoints.
//   → This makes Swagger UI show an "Authorize" button where you paste your JWT.
// ─────────────────────────────────────────────────────────────────────────────
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(c =>
{
    // Swagger document metadata
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "ASP.NET Core Identity API",
        Version = "v1",
        Description = "A complete API for user registration, login, roles, and authorization using ASP.NET Core Identity and JWT."
    });

    // Add JWT Bearer security definition
    // This adds an "Authorize" button to Swagger UI
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token in the text input below.",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    // Require the Bearer token for all endpoints
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
// BUILD THE APPLICATION
// ═══════════════════════════════════════════════════════════════════════════════
// builder.Build() creates the WebApplication with all configured services.
// ─────────────────────────────────────────────────────────────────────────────
var app = builder.Build();

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURE THE MIDDLEWARE PIPELINE
// ═══════════════════════════════════════════════════════════════════════════════
// The order of middleware is CRITICAL:
//   1. UseSwagger / UseSwaggerUI — only in development (Swagger UI)
//   2. UseHttpsRedirection — redirects HTTP to HTTPS
//   3. UseAuthentication — validates JWT tokens (sets HttpContext.User)
//   4. UseAuthorization — checks [Authorize] attributes (uses HttpContext.User)
//   5. MapControllers — routes requests to controllers
//
// Authentication MUST come before Authorization.
// ─────────────────────────────────────────────────────────────────────────────

// Swagger UI — only in development environment
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Identity API v1"));
}

// HTTPS redirection — redirect HTTP requests to HTTPS
app.UseHttpsRedirection();

// ──── AUTHENTICATION (before Authorization!) ────
// This middleware:
//   → Reads the Authorization: Bearer <token> header
//   → Validates the JWT token (signature, expiration, issuer, audience)
//   → Creates a ClaimsPrincipal from the JWT claims
//   → Sets HttpContext.User = the ClaimsPrincipal
//   → If no token or invalid token: HttpContext.User is unauthenticated
app.UseAuthentication();

// ──── AUTHORIZATION (after Authentication!) ────
// This middleware:
//   → Checks [Authorize] attributes on controllers and actions
//   → Checks policy requirements
//   → If user is not authenticated → returns 401 Unauthorized
//   → If user is authenticated but not authorized → returns 403 Forbidden
app.UseAuthorization();

// Map controller routes to the pipeline
app.MapControllers();

// Run the application
app.Run();
```

---

## Postman / Swagger Tests

### Swagger UI Test

1. Run the API: `dotnet run` (or press F5 in Visual Studio).
2. Navigate to `https://localhost:7001/swagger` (adjust port as needed).
3. You should see the Swagger UI with the title "ASP.NET Core Identity API".
4. Click the "Authorize" button — you'll see a dialog to enter a Bearer token.
5. Don't enter a token yet — we'll get one after Video 08.
6. Verify the Swagger UI shows no endpoints yet (we haven't added controllers).

### Postman Test — Verify API Is Running

1. Create a new request: `GET https://localhost:7001/swagger/v1/swagger.json`
2. Send the request.
3. Expected: `200 OK` with the Swagger JSON document (a large JSON object describing the API).
4. This confirms the API is running and Swagger is configured correctly.

### Postman Test — Verify Authentication Is Active

1. Create a new request: `GET https://localhost:7001/api/protected` (this endpoint doesn't exist yet, but we'll create it in Video 10).
2. Send the request without an Authorization header.
3. Expected: `404 Not Found` (endpoint doesn't exist yet) — but once we create it, it will return `401 Unauthorized` because the `[Authorize]` attribute will require a JWT token.

### Postman Test — Verify Swagger Security Definition

1. In Swagger UI, check that the "Authorize" button is present.
2. Click it — you should see a dialog with a field for the Bearer token.
3. This confirms that Swagger is configured to send JWT tokens with requests.

---

# Video 05 — The Identity Models — IdentityUser, IdentityRole, Custom Classes

## Theory & Definitions

### What Are Identity Models?

Identity models are the C# classes that represent users, roles, and related entities in your application. They are the foundation of Identity — every operation (create user, find user, add role, etc.) works with these classes.

### IdentityUser — The Default User Class

`IdentityUser` is the default user class provided by Identity. It has all the properties you need for a basic user:

| Property | Type | Purpose |
|----------|------|---------|
| `Id` | `string` | Primary key (GUID stored as string) |
| `UserName` | `string` | Unique login name |
| `NormalizedUserName` | `string` | Uppercase for case-insensitive lookups |
| `Email` | `string` | Email address |
| `NormalizedEmail` | `string` | Uppercase for case-insensitive lookups |
| `EmailConfirmed` | `bool` | Whether email has been verified |
| `PasswordHash` | `string` | Hashed password (never plaintext) |
| `SecurityStamp` | `string` | Random value that changes when credentials change |
| `ConcurrencyStamp` | `string` | Optimistic concurrency token |
| `PhoneNumber` | `string` | Phone number |
| `PhoneNumberConfirmed` | `bool` | Whether phone is verified |
| `TwoFactorEnabled` | `bool` | Whether 2FA is enabled |
| `LockoutEnabled` | `bool` | Whether lockout is enabled for this user |
| `LockoutEnd` | `DateTimeOffset?` | When lockout expires |
| `AccessFailedCount` | `int` | Failed login attempts count |
| `Claims` | `ICollection<IdentityUserClaim>` | Navigation to user's claims |
| `Roles` | `ICollection<IdentityUserRole>` | Navigation to user's roles |
| `Logins` | `ICollection<IdentityUserLogin>` | Navigation to external logins |
| `Tokens` | `ICollection<IdentityUserToken>` | Navigation to tokens |

### Why Subclass IdentityUser?

Subclass `IdentityUser` when you need extra properties on the Users table. The subclass becomes your application's user class, and Identity uses it everywhere (UserManager, SignInManager, DbContext, etc.).

**When to subclass:**

| Need | Approach |
|------|----------|
| Additional user properties (FullName, Department, Bio, etc.) | Subclass IdentityUser — they become columns in AspNetUsers |
| Data that's only for some users and is large (profile image, settings) | Separate table linked by UserId |
| Audit fields (CreatedDate, CreatedBy, ModifiedDate) | Subclass or implement as shadow properties in DbContext |
| Soft delete (IsDeleted flag) | Subclass with IsDeleted property |

**When NOT to subclass:**

| Situation | Approach |
|-----------|----------|
| Data that's not about the user identity (Orders, Posts, Comments) | Separate entity with UserId foreign key |
| Sensitive data that needs different security (SSN, payment info) | Separate secured table, NOT on IdentityUser |
| Properties that change frequently and are large ( preferences JSON) | Separate table or claim |

### ApplicationUser — Our Custom User Class

```csharp
public class ApplicationUser : IdentityUser
{
    public string? FullName { get; set; }
    public string? Department { get; set; }
    public DateTime? DateOfBirth { get; set; }
}
```

This class:
- Inherits all properties from `IdentityUser`.
- Adds `FullName`, `Department`, and `DateOfBirth` as nullable properties.
- When we run EF Core migrations, these become additional columns in the `AspNetUsers` table.

### ApplicationRole — Our Custom Role Class

```csharp
public class ApplicationRole : IdentityRole
{
    public string? Description { get; set; }
    public DateTime CreatedDate { get; set; } = DateTime.UtcNow;
}
```

This class:
- Inherits all properties from `IdentityRole` (Id, Name, NormalizedName, ConcurrencyStamp, Claims).
- Adds `Description` (human-readable explanation of the role) and `CreatedDate` (audit trail).
- When we run EF Core migrations, these become additional columns in the `AspNetRoles` table.

### IdentityUserClaim — What Claims Look Like in the Database

```csharp
// IdentityUserClaim is provided by Identity — you don't need to create it.
// It maps to the AspNetUserClaims table.

public class IdentityUserClaim : IdentityUserClaim<string>
{
    // Properties:
    //   Id (int) — primary key
    //   UserId (string) — foreign key to AspNetUsers
    //   ClaimType (string) — the claim type (e.g., "department", "role")
    //   ClaimValue (string) — the claim value (e.g., "Engineering", "Admin")
}
```

Claims are stored as rows in the `AspNetUserClaims` table, not as columns on the Users table. This is a key design decision — it allows unlimited claims per user without altering the Users table schema.

### IdentityUserRole — The User-Role Junction Table

```csharp
// IdentityUserRole is provided by Identity.
// It maps to the AspNetUserRoles table (junction table between Users and Roles).

public class IdentityUserRole : IdentityUserRole<string>
{
    // Properties:
    //   UserId (string) — foreign key to AspNetUsers
    //   RoleId (string) — foreign key to AspNetRoles
}
```

This is a many-to-many relationship between Users and Roles. A user can have multiple roles, and a role can have multiple users. The junction table `AspNetUserRoles` stores the associations.

### IdentityUserLogin — External Login Associations

```csharp
// IdentityUserLogin maps to AspNetUserLogins.
// Stores external login information (Google, Facebook, Microsoft, etc.).

public class IdentityUserLogin : IdentityUserLogin<string>
{
    // Properties:
    //   LoginProvider (string) — e.g., "Google", "Facebook"
    //   ProviderKey (string) — the user's ID from the external provider
    //   ProviderDisplayName (string) — display name of the provider
    //   UserId (string) — foreign key to AspNetUsers
}
```

Each user can have multiple external logins. This enables "Login with Google" / "Login with Facebook" — the user's Google account is linked to their Identity user account.

### IdentityUserToken — Tokens for Email Confirmation, Password Reset, etc.

```csharp
// IdentityUserToken maps to AspNetUserTokens.
// Stores tokens generated by Identity's token providers.

public class IdentityUserToken : IdentityUserToken<string>
{
    // Properties:
    //   UserId (string) — foreign key to AspNetUsers
    //   LoginProvider (string) — the provider that generated the token
    //   Name (string) — the token name/purpose (e.g., "EmailConfirmation", "PasswordReset")
    //   Value (string) — the token value (hashed, not plaintext)
}
```

These tokens are used for email confirmation and password reset flows. They are generated by `UserManager.GenerateEmailConfirmationTokenAsync` and `UserManager.GeneratePasswordResetTokenAsync`.

### How EF Core Maps These Classes to Tables

When you run `dotnet ef migrations add InitialCreate` and `dotnet ef database update`, EF Core creates these tables:

| C# Class | Database Table | Notes |
|----------|---------------|-------|
| `ApplicationUser` | `AspNetUsers` | Inherits from IdentityUser; extra properties → extra columns |
| `ApplicationRole` | `AspNetRoles` | Inherits from IdentityRole; extra properties → extra columns |
| `IdentityUserClaim` | `AspNetUserClaims` | Junction table for user claims |
| `IdentityUserRole` | `AspNetUserRoles` | Junction table for user-role associations |
| `IdentityUserLogin` | `AspNetUserLogins` | External login associations |
| `IdentityUserToken` | `AspNetUserTokens` | Tokens for email confirm, password reset |
| `IdentityRoleClaim` | `AspNetRoleClaims` | Claims attached to roles |

The table names are defaults — you can customize them in `OnModelCreating` if needed.

### The String Primary Key — Why string and not int?

Identity uses `string` as the primary key type by default. Why?

- **GUIDs as strings:** Identity generates user IDs as GUIDs (e.g., "3fa85f64-5717-4562-b3fc-2c963f66afa6"). Storing them as `string` avoids the need for a separate integer auto-increment column.
- **Flexibility:** Using `string` allows any string as the key — not just GUIDs. You could use email addresses, usernames, or custom identifiers.
- **Consistency:** All Identity entities (User, Role) use the same key type, making relationships simpler.

If you want integer keys, you can use `IdentityUser<int>` and `IdentityRole<int>`, but this is less common and requires more configuration.

---

## 🎬 Video Recording Notes

**Opening (say this):**

> "Now we define our models — the C# classes that represent users and roles in our system. We'll subclass IdentityUser and IdentityRole to add custom properties. I'll show you what properties Identity gives you by default, which ones you should keep, which ones you should add, and how EF Core maps all of this to database tables."

**Show on screen:**

> The `ApplicationUser` and `ApplicationRole` classes, side by side with the base `IdentityUser` and `IdentityRole` to show what's inherited and what's added. The EF Core migration output showing the tables and columns. A database viewer showing the AspNetUsers and AspNetRoles tables.

**Key points to emphasize (say this):**

> "Subclass IdentityUser when you need extra columns on the Users table. Don't subclass for data that belongs in a separate table — keep IdentityUser focused on identity data."

> "Claims are stored in a separate table (AspNetUserClaims), not as columns on the Users table. This is by design — it allows unlimited claims per user. Roles are also in a separate table (AspNetUserRoles) as a junction table."

> "The primary key is a string (GUID) by default. This is what Identity uses — don't change it unless you have a specific reason."

> "Every property you add to ApplicationUser becomes a column in AspNetUsers when you run migrations. Nullable properties become nullable columns. Non-nullable properties become NOT NULL columns."

**Analogy (say this):**

> "Think of ApplicationUser as an employee record. IdentityUser gives you the basic fields — ID, name, email, password. ApplicationUser adds the custom fields — FullName, Department, DateOfBirth. These are like adding columns to the employee table in the HR database. Claims are like stickers on the employee's badge — each sticker is a separate item (department, clearance level, project access) stored on a separate sheet, not written into the employee record itself."

**Common viewer questions:**

> "Can I add an integer Id instead of string?" — Yes, use `IdentityUser<int>`, but it's less common. The tutorial uses string (GUID) because that's Identity's default.

> "What if I need to add 20 custom properties?" — Consider whether they all belong on IdentityUser. If some are large or rarely used, put them in a separate table. IdentityUser should be lean — identity data, not everything about the user.

> "Do I need ApplicationRole if I don't add custom properties?" — No. You can use `IdentityRole` directly. But having a custom class is good practice — it gives you a place to add properties later and makes the code consistent.

**What to show:**

- ApplicationUser class with comments on each property
- ApplicationRole class with comments
- The EF Core migration command and output
- The database tables in a viewer (SQL Server Management Studio, Azure Data Studio, or a visual tool)
- A comparison: what IdentityUser gives you vs. what ApplicationUser adds

**What to skip:**

- Custom primary key types (int,Guid, etc.) — beyond scope
- TPH/TPT/TPC inheritance strategies — Identity uses TPH by default; changing it is advanced
- Shadow properties in EF Core — mention as an alternative for audit fields

---

## Complete Implementation

### File: Models/ApplicationUser.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Models/ApplicationUser.cs
// Video 05 — Identity Models: Custom User Class
// ─────────────────────────────────────────────────────────────────────────────
// ApplicationUser is our custom user class.
// It inherits from IdentityUser and adds custom properties.
//
// Design decisions:
//   → Inherit from IdentityUser (not implement IUser) — Identity's
//     UserManager, SignInManager, and stores expect IdentityUser semantics.
//   → Add only properties that belong on the Users table.
//   → Keep it lean — don't put everything here.
//   → Use nullable reference types (string?) for optional properties.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Show the IdentityUser base class properties (what we get for free)
//   - Show our custom properties (what we add)
//   - Explain why each custom property is here
//   - Show the EF Core migration that creates the extra columns
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Identity;

namespace IdentityApiTutorial.Models
{
    // ─────────────────────────────────────────────────────────────────────────────
    // ApplicationUser — our custom user class for the API.
    // ─────────────────────────────────────────────────────────────────────────────
    // Inherits from IdentityUser<string>, which gives us:
    //
    //   string Id                    — Primary key (GUID stored as string)
    //   string UserName              — Unique login name
    //   string NormalizedUserName    — Uppercase version for case-insensitive lookups
    //   string Email                 — Email address
    //   string NormalizedEmail       — Uppercase version for case-insensitive lookups
    //   bool EmailConfirmed          — Whether the email has been verified
    //   string PasswordHash          — Hashed password (PBKDF2 — NEVER plaintext)
    //   string SecurityStamp         — Random value; changes when credentials change;
    //                                 used to invalidate old tokens/JWTs
    //   string ConcurrencyStamp      — Optimistic concurrency token (changes on each update)
    //   string? PhoneNumber          — Phone number (nullable)
    //   bool PhoneNumberConfirmed    — Whether phone is verified
    //   bool TwoFactorEnabled        — Whether 2FA is enabled for this user
    //   bool LockoutEnabled          — Whether account lockout is enabled
    //   DateTimeOffset? LockoutEnd   — When the current lockout expires (null = not locked out)
    //   int AccessFailedCount        — Number of consecutive failed login attempts
    //   ICollection<IdentityUserClaim> Claims — Navigation to user's claims
    //   ICollection<IdentityUserRole> Roles  — Navigation to user's roles
    //   ICollection<IdentityUserLogin> Logins — Navigation to external logins
    //   ICollection<IdentityUserToken> Tokens — Navigation to tokens
    //
    // We add the following custom properties:
    // ─────────────────────────────────────────────────────────────────────────────
    public class ApplicationUser : IdentityUser
    {
        // ─────────────────────────────────────────────────────────────────────────
        // FullName — the user's display name (first + last name).
        //   → Nullable (string?) — not required at registration.
        //   → Becomes a NULLABLE NVARCHAR(256) column in AspNetUsers (by default).
        //   → Used for display purposes, not for authentication.
        //   → Why here and not a claim? It's always needed when displaying a user,
        //     so a column is more efficient than a claim lookup.
        // ─────────────────────────────────────────────────────────────────────────
        public string? FullName { get; set; }

        // ─────────────────────────────────────────────────────────────────────────
        // Department — the user's department or team.
        //   → Nullable — not all users belong to a department.
        //   → Becomes a NULLABLE NVARCHAR(256) column.
        //   → Could be a claim ("department" claim) instead. We use a column here
        //     because it's a simple string and we might filter by department.
        //   → If departments have complex data (head, members, budget), use a
        //     separate Department entity with a foreign key to ApplicationUser.
        // ─────────────────────────────────────────────────────────────────────────
        public string? Department { get; set; }

        // ─────────────────────────────────────────────────────────────────────────
        // DateOfBirth — the user's date of birth.
        //   → Nullable — not required.
        //   → Becomes a NULLABLE DATETIME2 column.
        //   → Used for age-restricted content, personalization, or analytics.
        //   → Privacy note: only collect this if you need it. Date of birth is
        //     personal data — handle it accordingly.
        // ─────────────────────────────────────────────────────────────────────────
        public DateTime? DateOfBirth { get; set; }
    }
}
```

### File: Models/ApplicationRole.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Models/ApplicationRole.cs
// Video 05 — Identity Models: Custom Role Class
// ─────────────────────────────────────────────────────────────────────────────
// ApplicationRole is our custom role class.
// It inherits from IdentityRole and adds custom properties.
//
// Design decisions:
//   → Inherit from IdentityRole — enables role management with our custom class.
//   → Add properties that describe the role (description, created date).
//   → Keep it lean — roles are simple entities.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Show the IdentityRole base class properties
//   - Show our custom properties
//   - Explain why Description and CreatedDate are useful
//   - Show how roles are created and managed (Video 09)
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Identity;

namespace IdentityApiTutorial.Models
{
    // ─────────────────────────────────────────────────────────────────────────────
    // ApplicationRole — our custom role class for the API.
    // ─────────────────────────────────────────────────────────────────────────────
    // Inherits from IdentityRole<string>, which gives us:
    //
    //   string Id                  — Primary key (GUID stored as string)
    //   string Name                — Human-readable role name ("Admin", "User")
    //   string NormalizedName      — Uppercase version for case-insensitive lookups
    //   string ConcurrencyStamp    — Optimistic concurrency token
    //   ICollection<IdentityRoleClaim> Claims — Navigation to role's claims
    //
    // We add:
    // ─────────────────────────────────────────────────────────────────────────────
    public class ApplicationRole : IdentityRole
    {
        // ─────────────────────────────────────────────────────────────────────────
        // Description — human-readable explanation of what the role allows.
        //   → Nullable — not all roles need a description.
        //   → Becomes a NULLABLE NVARCHAR(256) column in AspNetRoles.
        //   → Useful for admin UIs that show role descriptions when assigning roles.
        //   → Example: "Admin" → "Full access to all administrative functions"
        // ─────────────────────────────────────────────────────────────────────────
        public string? Description { get; set; }

        // ─────────────────────────────────────────────────────────────────────────
        // CreatedDate — when the role was created.
        //   → Set to DateTime.UtcNow by default (not nullable).
        //   → Becomes a DATETIME2 column with a default value.
        //   → Useful for auditing — you can see when each role was created.
        //   → Can be set explicitly when creating a role (in Video 09).
        // ─────────────────────────────────────────────────────────────────────────
        public DateTime CreatedDate { get; set; } = DateTime.UtcNow;
    }
}
```

### File: Data/IdentityDbContext.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Data/IdentityDbContext.cs
// Video 05 — Identity Models: DbContext
// ─────────────────────────────────────────────────────────────────────────────
// IdentityDbContext connects Identity to your database via EF Core.
// It maps ApplicationUser, ApplicationRole, and all Identity entities
// to database tables.
//
// Design decisions:
//   → Subclass IdentityDbContext<ApplicationUser, ApplicationRole, string>
//     to use our custom user and role classes.
//   → Call base.OnModelCreating to let Identity configure its tables.
//   → Add custom configurations only when needed.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Show the generic parameters (TUser, TRole, TKey)
//   - Explain that IdentityDbContext already includes all the Identity
//     DbSets (Users, Roles, Claims, etc.)
//   - Show the constructor pattern (takes DbContextOptions)
//   - Show OnModelCreating calling base first
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using IdentityApiTutorial.Models;

namespace IdentityApiTutorial.Data
{
    // ─────────────────────────────────────────────────────────────────────────────
    // IdentityDbContext — our Identity database context.
    // ─────────────────────────────────────────────────────────────────────────────
    // Generic parameters:
    //   TUser = ApplicationUser   — our custom user class
    //   TRole = ApplicationRole   — our custom role class
    //   TKey  = string            — primary key type (string = GUID)
    //
    // IdentityDbContext<TUser, TRole, TKey> already includes:
    //   DbSet<TUser> Users
    //   DbSet<TRole> Roles
    //   DbSet<IdentityUserClaim<TKey>> UserClaims
    //   DbSet<IdentityUserRole<TKey>> UserRoles
    //   DbSet<IdentityUserLogin<TKey>> UserLogins
    //   DbSet<IdentityUserToken<TKey>> UserTokens
    //   DbSet<IdentityRoleClaim<TKey>> RoleClaims
    //
    // We don't need to add these — they're already there.
    // ─────────────────────────────────────────────────────────────────────────────
    public class IdentityDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>
    {
        // ─────────────────────────────────────────────────────────────────────────
        // Constructor — takes DbContextOptions<IdentityDbContext>.
        //   → Options are configured in Program.cs with UseSqlServer and the
        //     connection string.
        //   → This is the standard pattern for all EF Core DbContexts.
        //   → The options include: connection string, provider, behaviors, etc.
        // ─────────────────────────────────────────────────────────────────────────
        public IdentityDbContext(DbContextOptions<IdentityDbContext> options)
            : base(options)
        {
        }

        // ─────────────────────────────────────────────────────────────────────────
        // OnModelCreating — customize the EF Core model.
        //   → Call base.OnModelCreating FIRST — Identity configures its tables,
        //     relationships, indexes, and constraints.
        //   → Add custom configurations AFTER the base call.
        //
        // Common customizations (not needed for our tutorial, but shown for
        // reference):
        //   → Rename a table: builder.Entity<ApplicationUser>().ToTable("MyUsers")
        //   → Rename a column: builder.Entity<ApplicationUser>()
        //       .Property(u => u.FullName).HasColumnName("Display_Name")
        //   → Change column type: builder.Entity<ApplicationUser>()
        //       .Property(u => u.FullName).HasColumnType("nvarchar(500)")
        //   → Add an index: builder.Entity<ApplicationUser>()
        //       .HasIndex(u => u.Department)
        //   → Configure a relationship: builder.Entity<ApplicationUser>()
        //       .HasOne<Department>().WithMany().HasForeignKey(u => u.DepartmentId)
        //
        // For our tutorial, we call base.OnModelCreating only — Identity's default
        // configuration is sufficient.
        // ─────────────────────────────────────────────────────────────────────────
        protected override void OnModelCreating(ModelBuilder builder)
        {
            // Call the base — Identity configures:
            //   → AspNetUsers table with all IdentityUser properties
            //   → AspNetRoles table with all IdentityRole properties
            //   → AspNetUserRoles junction table
            //   → AspNetUserClaims table
            //   → AspNetRoleClaims table
            //   → AspNetUserLogins table
            //   → AspNetUserTokens table
            //   → Indexes on UserName, NormalizedUserName, Email, NormalizedEmail
            //   → Unique constraints where needed
            base.OnModelCreating(builder);

            // Custom configurations go here (none needed for this tutorial).
            // Example: rename the Users table
            // builder.Entity<ApplicationUser>().ToTable("AppUsers");
        }
    }
}
```

---

## Postman / Swagger Tests

No testable endpoints yet — this is the models video. But here is what you can verify:

### Verify the Models Compile

1. Build the project: `dotnet build`
2. Expected: `Build succeeded.` with no errors.
3. If there are errors, check:
   - `ApplicationUser` inherits from `IdentityUser` (not `IdentityUser<string>` — the default is string).
   - `ApplicationRole` inherits from `IdentityRole`.
   - `IdentityDbContext` inherits from `IdentityDbContext<ApplicationUser, ApplicationRole, string>`.
   - All necessary `using` statements are present.

### Verify the DbContext Is Registered (in Program.cs)

Check that `Program.cs` has:

```csharp
builder.Services.AddDbContext<IdentityDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
```

And that `IdentityDbContext` is used in `AddEntityFrameworkStores<IdentityDbContext>()`.

### Swagger Verification

Run the API and navigate to Swagger UI. Verify:
- The API starts without errors.
- Swagger UI loads.
- No endpoints are shown yet (we haven't added any controllers).

---

# Video 06 — Database Setup — IdentityDbContext, Connection Strings, Migrations

## Theory & Definitions

### What We're Doing in This Video

We're setting up the database for Identity:
1. Configure the connection string in `appsettings.json`.
2. Create the database (or let EF Core create it).
3. Run EF Core migrations to create the Identity tables.
4. Verify the tables exist in the database.

### Connection Strings — What They Are and Why They Matter

A connection string tells EF Core how to connect to the database:
- **Server** — the database server address (e.g., `localhost`, `.\SQLEXPRESS`, a remote server name).
- **Database** — the database name (e.g., `IdentityApiDb`).
- **Authentication** — how to authenticate (Windows Authentication with `Trusted_Connection=True`, or SQL Server authentication with `User Id` and `Password`).
- **TrustServerCertificate** — for SSL/TLS connections; `True` bypasses certificate validation (useful for local development, not production).

Example (SQL Server with Windows Authentication):

```
Server=localhost;Database=IdentityApiDb;Trusted_Connection=True;TrustServerCertificate=True;
```

Example (SQL Server with SQL Authentication):

```
Server=localhost;Database=IdentityApiDb;User Id=sa;Password=YourPassword;TrustServerCertificate=True;
```

Example (SQLite):

```
Data Source=identity.db;
```

### EF Core Migrations — What They Are

Migrations are a way to incrementally evolve the database schema. Instead of manually writing SQL scripts, you:
1. Define your models (ApplicationUser, ApplicationRole, IdentityDbContext).
2. Run `dotnet ef migrations add MigrationName` — EF Core compares your models to the current database state and generates a migration class with `Up()` (apply changes) and `Down()` (revert changes) methods.
3. Run `dotnet ef database update` — applies the migration to the database.

Each migration is a C# class in the `Migrations/` folder. You can version-control them, review them, and apply them to different environments.

### The Migration Process for Identity

When you run your first migration for Identity:
1. EF Core scans `IdentityDbContext` and finds all the `DbSet` properties and relationships.
2. It includes the Identity entities (User, Role, Claims, etc.) because they're part of `IdentityDbContext`.
3. It generates a migration that creates all the Identity tables: `AspNetUsers`, `AspNetRoles`, `AspNetUserRoles`, `AspNetUserClaims`, `AspNetRoleClaims`, `AspNetUserLogins`, `AspNetUserTokens`.
4. It also includes any custom properties you added (FullName, Department, DateOfBirth on ApplicationUser; Description, CreatedDate on ApplicationRole).

### Installing the EF Core CLI Tools

The `dotnet ef` command is a .NET CLI tool. To use it, you need the `dotnet-ef` tool installed:

```bash
dotnet tool install --global dotnet-ef
```

If it's already installed, update it:

```bash
dotnet tool update --global dotnet-ef
```

The `Microsoft.EntityFrameworkCore.Tools` package (added to the .csproj) provides design-time services. The `dotnet-ef` global tool provides the CLI command.

### The Commands We Run

```bash
# Add the initial migration
dotnet ef migrations add InitialCreate

# Apply the migration to the database
dotnet ef database update

# (Optional) Check the database was created
# Open SQL Server Management Studio, Azure Data Studio, or use a CLI tool
# to verify the IdentityApiDb database exists with the Identity tables.
```

### What Happens When You Run `dotnet ef database update`

1. EF Core reads the migration history from the database (the `__EFMigrationsHistory` table).
2. It finds which migrations haven't been applied yet.
3. It executes the `Up()` method of each pending migration in order.
4. For `InitialCreate`, this creates all the Identity tables.
5. It records the migration in `__EFMigrationsHistory`.

### Generating User Secrets (Optional but Recommended for Development)

For the JWT secret key, use user secrets in development:

```bash
# Set up user secrets for the project
dotnet user-secrets init
dotnet user-secrets set "JwtSettings:SecretKey" "YourSuperSecretKeyThatIsAtLeast32CharactersLong!"
dotnet user-secrets set "JwtSettings:Issuer" "IdentityApiTutorial"
dotnet user-secrets set "JwtSettings:Audience" "IdentityApiTutorialClients"
dotnet user-secrets set "JwtSettings:ExpirationInMinutes" "60"
```

User secrets are stored in your user profile (not in the project folder), so they don't get committed to source control.

### Database Providers — Options

| Provider | Package | Connection String Example | Best For |
|----------|---------|--------------------------|----------|
| SQL Server | `Microsoft.EntityFrameworkCore.SqlServer` | `Server=localhost;Database=IdentityApiDb;Trusted_Connection=True;TrustServerCertificate=True;` | Production, Windows environments |
| SQLite | `Microsoft.EntityFrameworkCore.Sqlite` | `Data Source=identity.db;` | Development, testing, small apps |
| PostgreSQL | `Npgsql.EntityFrameworkCore.PostgreSQL` | `Host=localhost;Database=identityapi;Username=postgres;Password=secret;` | Production, Linux environments |
| MySQL | `Pomelo.EntityFrameworkCore.MySql` | `Server=localhost;Database=identityapi;User=root;Password=secret;` | Production, cross-platform |

The tutorial uses SQL Server, but all concepts apply to any provider.

### The __EFMigrationsHistory Table

EF Core maintains a table called `__EFMigrationsHistory` that records which migrations have been applied. Each row contains:
- `MigrationId` — the migration class name (e.g., "20240101120000_InitialCreate").
- `ProductVersion` — the EF Core version that generated the migration.

This table is automatically created by EF Core. You don't need to manage it manually.

---

## 🎬 Video Recording Notes

**Opening (say this):**

> "Now we connect Identity to a real database. We'll configure the connection string, run EF Core migrations, and create all the Identity tables. This is where Identity becomes real — users, roles, claims, all stored in your database. I'll show you the exact commands to run and what to expect."

**Show on screen:**

> The `appsettings.json` file with the connection string. The `dotnet ef migrations add` and `dotnet ef database update` commands running in the terminal. The database viewer showing the created tables. The `__EFMigrationsHistory` table.

**Key points to emphasize (say this):**

> "The connection string in appsettings.json must match your database server. If you're using SQL Server LocalDB or SQLEXPRESS, adjust the server name. If you're using SQLite, the connection string is completely different."

> "EF Core migrations are incremental — each migration builds on the previous one. You can have multiple migrations over time as your models change. For this tutorial, we create one initial migration that sets up all Identity tables."

> "The `dotnet ef` tool must be installed globally. The `Microsoft.EntityFrameworkCore.Tools` package in your .csproj provides design-time services that the tool uses."

> "After running migrations, verify the tables exist. Open your database viewer and check for AspNetUsers, AspNetRoles, AspNetUserRoles, AspNetUserClaims, AspNetRoleClaims, AspNetUserLogins, AspNetUserTokens, and __EFMigrationsHistory."

**Analogy (say this):**

> "Migrations are like version control for your database schema. Each migration is a snapshot of what changed. `InitialCreate` is the first snapshot — it creates all the tables. Later, if you add a property to ApplicationUser, you create a new migration that alters the table. EF Core tracks which migrations have been applied in the `__EFMigrationsHistory` table — like a commit history for your database."

**Common viewer questions:**

> "Can I create the database manually instead of using migrations?" — Yes, but migrations are the recommended approach. They're version-controlled, repeatable, and work across environments. Manual SQL scripts are error-prone and hard to maintain.

> "What if I get an error about the database already existing?" — If the database exists but has no tables, you can drop it and re-run migrations. If the database has tables from a previous migration, you can add a new migration to alter the schema. In development, dropping and recreating is fine.

> "Do I need to run migrations on the production server?" — Yes. On production, you apply the same migrations that you developed locally. This is typically done as part of the deployment process (e.g., `dotnet ef database update` as a deployment step, or using a CI/CD pipeline).

> "What about the JWT secret key in appsettings.json?" — In development, it's fine to have it in appsettings.json for testing. In production, use environment variables, Azure Key Vault, or user secrets. Never commit production secrets to source control.

**What to show:**

- The `appsettings.json` file with the connection string
- The `dotnet ef migrations add InitialCreate` command and the generated migration file
- The `dotnet ef database update` command
- The database viewer showing all the Identity tables
- The `__EFMigrationsHistory` table with the migration record

**What to skip:**

- Advanced migration scenarios (data migrations, splitting migrations, custom SQL in migrations)
- Database sharding, replication, high availability (out of scope)
- Connection string encryption (mention as a production concern)

---

## Complete Implementation

### File: appsettings.json — Connection String and JWT Settings

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=IdentityApiDb;Trusted_Connection=True;TrustServerCertificate=True;"
  },
  "JwtSettings": {
    "SecretKey": "YourSuperSecretKeyThatIsAtLeast32CharactersLong!",
    "Issuer": "IdentityApiTutorial",
    "Audience": "IdentityApiTutorialClients",
    "ExpirationInMinutes": 60
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*"
}
```

**Important notes:**

- Replace `localhost` with your actual SQL Server instance name if needed (e.g., `.\SQLEXPRESS` or `SERVER\SQLEXPRESS`).
- `TrustServerCertificate=True` is for development only — in production, configure proper SSL/TLS certificate validation.
- The `SecretKey` must be at least 32 characters (256 bits) for HS256. Replace with a strong, random key.
- In production, store the `SecretKey` in environment variables or a secrets manager — not in `appsettings.json`.

### Running the EF Core Migrations

**Step 1: Install the EF Core CLI tool (if not already installed)**

```bash
dotnet tool install --global dotnet-ef
# Or update if already installed:
dotnet tool update --global dotnet-ef
```

**Step 2: Add the initial migration**

```bash
cd IdentityApiTutorial
dotnet ef migrations add InitialCreate
```

This generates a migration file in the `Migrations/` folder. The file name includes a timestamp and the migration name (e.g., `20240101120000_InitialCreate.cs`).

The generated migration includes:
- `CreateTable` for `AspNetUsers` with all IdentityUser columns + our custom columns (FullName, Department, DateOfBirth).
- `CreateTable` for `AspNetRoles` with all IdentityRole columns + our custom columns (Description, CreatedDate).
- `CreateTable` for `AspNetUserRoles`, `AspNetUserClaims`, `AspNetRoleClaims`, `AspNetUserLogins`, `AspNetUserTokens`.
- `CreateIndex` for UserName, NormalizedUserName, Email, NormalizedEmail on AspNetUsers.
- `CreateIndex` for Name, NormalizedName on AspNetRoles.
- `AddForeignKey` for the relationships between tables.

**Step 3: Apply the migration to the database**

```bash
dotnet ef database update
```

This:
- Creates the `IdentityApiDb` database (if it doesn't exist).
- Creates all the Identity tables.
- Records the migration in `__EFMigrationsHistory`.

**Step 4: Verify the database**

Open SQL Server Management Studio (SSMS), Azure Data Studio, or your preferred database tool, and connect to your SQL Server instance. Verify:

1. The `IdentityApiDb` database exists.
2. The following tables exist:
   - `AspNetUsers` (with columns: Id, UserName, NormalizedUserName, Email, NormalizedEmail, EmailConfirmed, PasswordHash, SecurityStamp, ConcurrencyStamp, PhoneNumber, PhoneNumberConfirmed, TwoFactorEnabled, LockoutEnabled, LockoutEnd, AccessFailedCount, FullName, Department, DateOfBirth)
   - `AspNetRoles` (with columns: Id, Name, NormalizedName, ConcurrencyStamp, Description, CreatedDate)
   - `AspNetUserRoles` (UserId, RoleId)
   - `AspNetUserClaims` (Id, UserId, ClaimType, ClaimValue)
   - `AspNetRoleClaims` (Id, RoleId, ClaimType, ClaimValue)
   - `AspNetUserLogins` (LoginProvider, ProviderKey, ProviderDisplayName, UserId)
   - `AspNetUserTokens` (UserId, LoginProvider, Name, Value)
   - `__EFMigrationsHistory` (MigrationId, ProductVersion)

### File: Migrations/20240101120000_InitialCreate.cs (Example)

This file is generated by EF Core — you don't write it manually. Here's what it looks like (abbreviated):

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// This file is GENERATED by EF Core — do not edit manually.
// ─────────────────────────────────────────────────────────────────────────────
// It is created by: dotnet ef migrations add InitialCreate
// It is applied by: dotnet ef database update
//
// The Up() method creates the database schema.
// The Down() method reverts the schema (drops tables).
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.EntityFrameworkCore.Migrations;

namespace IdentityApiTutorial.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Create AspNetUsers table with all IdentityUser columns + custom columns
            migrationBuilder.CreateTable(
                name: "AspNetUsers",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    FullName = table.Column<string>(type: "nvarchar(256)", nullable: true),
                    Department = table.Column<string>(type: "nvarchar(256)", nullable: true),
                    DateOfBirth = table.Column<DateTime>(type: "datetime2", nullable: true),
                    UserName = table.Column<string>(type: "nvarchar(256)", nullable: true),
                    NormalizedUserName = table.Column<string>(type: "nvarchar(256)", nullable: true),
                    Email = table.Column<string>(type: "nvarchar(256)", nullable: true),
                    NormalizedEmail = table.Column<string>(type: "nvarchar(256)", nullable: true),
                    EmailConfirmed = table.Column<bool>(type: "bit", nullable: false),
                    PasswordHash = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SecurityStamp = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ConcurrencyStamp = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PhoneNumber = table.Column<string>(type: "nvarchar(256)", nullable: true),
                    PhoneNumberConfirmed = table.Column<bool>(type: "bit", nullable: false),
                    TwoFactorEnabled = table.Column<bool>(type: "bit", nullable: false),
                    LockoutEnabled = table.Column<bool>(type: "bit", nullable: false),
                    LockoutEnd = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    AccessFailedCount = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUsers", x => x.Id);
                });

            // Create AspNetRoles table with all IdentityRole columns + custom columns
            migrationBuilder.CreateTable(
                name: "AspNetRoles",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Description = table.Column<string>(type: "nvarchar(256)", nullable: true),
                    CreatedDate = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(256)", nullable: true),
                    NormalizedName = table.Column<string>(type: "nvarchar(256)", nullable: true),
                    ConcurrencyStamp = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetRoles", x => x.Id);
                });

            // Create junction table for User-Role relationships
            migrationBuilder.CreateTable(
                name: "AspNetUserRoles",
                columns: table => new
                {
                    UserId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    RoleId = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserRoles", x => new { x.UserId, x.RoleId });
                    table.ForeignKey(
                        name: "FK_AspNetUserRoles_AspNetRoles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "AspNetRoles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AspNetUserRoles_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            // ... (other tables: AspNetUserClaims, AspNetRoleClaims, AspNetUserLogins, AspNetUserTokens)

            // Create indexes for efficient lookups
            migrationBuilder.CreateIndex(
                name: "IX_AspNetUsers_Email",
                table: "AspNetUsers",
                column: "Email");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUsers_NormalizedUserName",
                table: "AspNetUsers",
                column: "NormalizedUserName",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AspNetRoles_NormalizedName",
                table: "AspNetRoles",
                column: "NormalizedName",
                unique: true);

            // Create __EFMigrationsHistory table
            migrationBuilder.CreateTable(
                name: "__EFMigrationsHistory",
                columns: table => new
                {
                    MigrationId = table.Column<string>(type: "nvarchar(150)", nullable: false),
                    ProductVersion = table.Column<string>(type: "nvarchar(32)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK___EFMigrationsHistory", x => x.MigrationId);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Drop all tables in reverse order (respecting foreign keys)
            migrationBuilder.DropTable(name: "__EFMigrationsHistory");
            migrationBuilder.DropTable(name: "AspNetUserTokens");
            migrationBuilder.DropTable(name: "AspNetUserLogins");
            migrationBuilder.DropTable(name: "AspNetRoleClaims");
            migrationBuilder.DropTable(name: "AspNetUserClaims");
            migrationBuilder.DropTable(name: "AspNetUserRoles");
            migrationBuilder.DropTable(name: "AspNetRoles");
            migrationBuilder.DropTable(name: "AspNetUsers");
        }
    }
}
```

---

## Postman / Swagger Tests

### Verify the Database Was Created

1. Open SQL Server Management Studio (SSMS) or Azure Data Studio.
2. Connect to your SQL Server instance (`localhost` or `.\SQLEXPRESS`).
3. Expand the `Databases` folder — you should see `IdentityApiDb`.
4. Expand `IdentityApiDb` → `Tables` — you should see all the Identity tables.
5. Expand the `__EFMigrationsHistory` table — you should see one row with the migration ID.

### Verify the API Still Builds and Runs

1. Build the project: `dotnet build`
2. Expected: `Build succeeded.`
3. Run the API: `dotnet run`
4. Navigate to Swagger UI: `https://localhost:7001/swagger`
5. Expected: Swagger UI loads without errors.

### Test: Check the Database Connection

1. Create a simple test endpoint (temporarily) that returns the database connection state, or use a health check.
2. Alternatively, run the API and check the terminal output — if the connection string is wrong, you'll see an error on startup.
3. Expected: API starts successfully, no database connection errors.

---

# Video 07 — User Registration API — Complete Endpoint

## Theory & Definitions

### What User Registration Does in an API

User registration is the endpoint that creates a new user account. In an API, this is typically:

```
POST /api/accounts/register
Content-Type: application/json

{
  "userName": "ahmad",
  "password": "Test@1234",
  "email": "ahmad@example.com",
  "fullName": "Ahmad Developer"
}
```

The API:
1. Validates the input (model validation — [Required], [StringLength], etc.).
2. Creates an `ApplicationUser` with the provided data.
3. Calls `UserManager.CreateAsync(user, password)` — this hashes the password and saves the user to the database.
4. Returns the created user (without the password hash) with a `201 Created` status.

### The Registration Flow — Step by Step

```
Client: POST /api/accounts/register { userName, password, email, fullName }
    ↓
[Model Validation] → If invalid → 400 Bad Request with validation errors
    ↓
AccountsController.Register()
    ↓
Create ApplicationUser instance:
  → UserName = request.UserName
  → Email = request.Email
  → FullName = request.FullName
  → EmailConfirmed = false (by default — user must confirm email)
    ↓
UserManager.CreateAsync(user, password)
    ↓
  → Password hashed with PBKDF2 (PasswordHasher)
  → User saved to AspNetUsers table (via IUserStore / EF Core)
  → IdentityResult returned:
    → Success: user created
    → Failed: IdentityError list (password too weak, email not unique, etc.)
    ↓
If Success:
  → Return 201 Created with user data (exclude PasswordHash, SecurityStamp, etc.)
If Failed:
  → Return 400 Bad Request with IdentityError messages
```

### The DTO (Data Transfer Object) Pattern

We use DTOs to separate the API contract from the internal models. The `RegisterRequest` DTO defines what the client sends. The `ApplicationUser` model is what Identity uses internally. We map between them in the controller.

**Why DTOs:**

| Reason | Explanation |
|--------|-------------|
| **Decoupling** | The API contract (what the client sends) is separate from the internal model (what Identity uses). You can change the internal model without breaking the API. |
| **Validation** | DTOs use data annotations ([Required], [StringLength]) for model validation. IdentityUser doesn't have these annotations. |
| **Security** | You control what data is exposed. The response DTO excludes sensitive fields (PasswordHash, SecurityStamp, etc.). |
| **Clarity** | The DTO clearly defines what the endpoint expects and returns. |

### Password Hashing — What Happens Inside CreateAsync

When you call `UserManager.CreateAsync(user, password)`:

1. Identity's `PasswordHasher` hashes the password using PBKDF2 (Password-Based Key Derivation Function 2) with a random salt.
2. The hash is stored in `user.PasswordHash` as a string (Base64 encoded).
3. The user is saved to the database with the hashed password.
4. The original plaintext password is **never stored** — only the hash.

**What PBKDF2 does:**

```
Input: password (plaintext), salt (random bytes), iterations (10,000+)
Output: hash (derived key)

The salt ensures that the same password produces different hashes for different users.
The iterations make brute-force attacks expensive (each guess requires 10,000+ iterations).
```

When the user logs in, Identity uses the same salt (stored with the hash) and the same iterations to hash the provided password and compares it to the stored hash.

### Email Confirmation — Why It's False by Default

When a user registers, `EmailConfirmed` is `false` by default. This means:
- The user exists in the database.
- The user cannot log in until they confirm their email (if you enforce this).
- You send a confirmation email with a token.
- The user clicks the link, and you call `UserManager.ConfirmEmailAsync(user, token)`.

**For the tutorial**, we don't enforce email confirmation for login (we allow login even if email is not confirmed). In production, you would typically require email confirmation before allowing login.

### The Registration Response

A successful registration returns:

```json
{
  "success": true,
  "data": {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "userName": "ahmad",
    "email": "ahmad@example.com",
    "fullName": "Ahmad Developer",
    "emailConfirmed": false,
    "createdAt": "2024-01-01T12:00:00Z"
  },
  "message": "User registered successfully."
}
```

The response excludes:
- `passwordHash` — never send the password hash to the client.
- `securityStamp` — internal use only.
- `concurrencyStamp` — internal use only.
- `accessFailedCount` — internal use only.
- Any other sensitive/internal fields.

### Error Responses

If registration fails, the API returns:

```json
{
  "success": false,
  "data": null,
  "message": "Registration failed.",
  "errors": {
    "Password": ["Passwords must be at least 8 characters."],
    "Email": ["A user with that email already exists."],
    "UserName": ["User name 'ahmad' is already taken."]
  }
}
```

The errors come from `IdentityResult.Errors` — each `IdentityError` has a `Description` that explains what went wrong.

### Common Registration Errors

| Error | Cause | Solution |
|-------|-------|----------|
| "Passwords must be at least {n} characters." | Password too short | Enter a longer password |
| "Passwords must contain at least one digit." | No digit in password | Add a digit (0-9) |
| "Passwords must contain at least one uppercase character." | No uppercase letter | Add an uppercase letter (A-Z) |
| "Passwords must contain at least one lowercase character." | No lowercase letter | Add a lowercase letter (a-z) |
| "Passwords must contain at least one non-alphanumeric character." | No special character | Add a special character (!, @, #, etc.) |
| "A user with that email already exists." | Email is not unique | Use a different email |
| "User name 'xyz' is already taken." | UserName is not unique | Use a different UserName |
| "NamePasswordMismatch" | (Rare) password validation failed | Check password against all rules |

---

## 🎬 Video Recording Notes

**Opening (say this):**

> "This is the first real endpoint we build — user registration. We'll create a POST endpoint that takes a username, password, email, and full name, validates the input, creates the user with a hashed password, and saves it to the database. I'll show you the DTO, the controller, the service call, and exactly what happens to the password."

**Show on screen:**

> The `RegisterRequest` DTO with data annotations. The `AccountsController.Register` method, line by line. The `UserManager.CreateAsync` call. The Postman request and response. The database viewer showing the new user in AspNetUsers (with the hashed password, not plaintext).

**Key points to emphasize (say this):**

> "Use DTOs for your API contracts — RegisterRequest for input, UserResponse for output. Never expose IdentityUser directly — it has sensitive fields like PasswordHash that should never leave the API."

> "UserManager.CreateAsync does two things: it hashes the password (PBKDF2 with salt) and saves the user to the database. You pass the plaintext password, and Identity handles the hashing. You never hash the password yourself."

> "Model validation happens automatically with [ApiController]. If the DTO has [Required] and the client doesn't send it, you get a 400 Bad Request automatically. You don't need to write validation code for required fields."

> "The response excludes sensitive data. PasswordHash, SecurityStamp, ConcurrencyStamp — these stay on the server. The client gets back only what it needs: ID, UserName, Email, FullName."

> "IdentityResult tells you if the operation succeeded. If it failed, the Errors collection tells you why. Always check IdentityResult and return the errors to the client."

**Analogy (say this):**

> "Registration is like applying for a library card. You fill out a form (RegisterRequest DTO) with your name, email, and a password. The librarian (UserManager.CreateAsync) checks that the form is valid, creates a record in the database, and gives you a card (the response with your user ID). The password is like your PIN — it's stored as a hash, not written down. If you forget your PIN, you can reset it (Video 17), but the librarian never sees your actual PIN — only the hash."

**Common viewer questions:**

> "Why not use IdentityUser directly in the controller?" — Because IdentityUser has sensitive properties (PasswordHash, SecurityStamp) that should never be sent to the client. DTOs give you control over what's exposed.

> "What if I want to require email confirmation before login?" — Set `options.SignIn.RequireConfirmedEmail = true` in the Identity options. Then `CheckPasswordSignInAsync` will fail with `IsNotAllowed` if the email is not confirmed. You'd also need to send confirmation emails (Video 17).

> "Can I add more fields to registration (phone, birth date, etc.)?" — Yes. Add them to the RegisterRequest DTO, map them to ApplicationUser in the controller, and they'll be saved to the database. The migration already has the columns (we added DateOfBirth in Video 05).

> "What if the password is too weak?" — Identity's PasswordOptions validation fails, and CreateAsync returns an IdentityError. We catch that and return it to the client. The client can then prompt the user to choose a stronger password.

**What to show:**

- The RegisterRequest DTO
- The UserResponse DTO
- The AccountsController.Register method (full, with comments)
- The Postman request (POST /api/accounts/register with JSON body)
- The Postman response (201 Created with user data)
- The database viewer showing the new user (with hashed password)
- A failed registration (e.g., password too short) showing the error response

**What to skip:**

- Email confirmation flow (covered in Video 17 — keep it simple for now)
- External registration (social login — covered in Video 16)
- Admin-created users (covered in Video 19 / admin endpoints)

---

## Complete Implementation

### File: DTOs/RegisterRequest.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: DTOs/RegisterRequest.cs
// Video 07 — User Registration: Register Request DTO
// ─────────────────────────────────────────────────────────────────────────────
// This DTO defines what the client sends to the registration endpoint.
// It uses data annotations for model validation.
//
// [ApiController] automatically validates this and returns 400 if invalid.
// ─────────────────────────────────────────────────────────────────────────────

using System.ComponentModel.DataAnnotations;

namespace IdentityApiTutorial.DTOs
{
    // ─────────────────────────────────────────────────────────────────────────────
    // RegisterRequest — the request body for POST /api/accounts/register.
    // ─────────────────────────────────────────────────────────────────────────────
    // Properties:
    //   → UserName: the unique login name (required, with length and character constraints)
    //   → Email: the user's email address (required, must be valid email format)
    //   → Password: the user's password (required, with minimum length for UX guidance)
    //   → FullName: optional display name (not required, mapped to ApplicationUser.FullName)
    //
    // Data annotations:
    //   → [Required]: the field must be present (not null, not empty)
    //   → [StringLength]: maximum length (and optional minimum)
    //   → [EmailAddress]: validates that the value is a valid email format
    //   → [RegularExpression]: validates against a pattern
    //
    // Note: Password validation (digit, uppercase, etc.) is done by Identity's
    // PasswordOptions, NOT by data annotations on this DTO. The DTO's
    // [StringLength] is just a UX guideline — the real enforcement is in Identity.
    // ─────────────────────────────────────────────────────────────────────────────
    public class RegisterRequest
    {
        // ─────────────────────────────────────────────────────────────────────────
        // UserName — the unique login name for the user.
        //   → [Required]: must be provided.
        //   → [StringLength(50, MinimumLength = 3)]: between 3 and 50 characters.
        //   → [RegularExpression]: allows letters, numbers, and certain special
        //     characters (@, ., -, _). This matches Identity's
        //     AllowedUserNameCharacters configuration.
        //   → Why these constraints? They match what Identity expects and prevent
        //     invalid user names from reaching UserManager.CreateAsync.
        // ─────────────────────────────────────────────────────────────────────────
        [Required(ErrorMessage = "User name is required.")]
        [StringLength(50, MinimumLength = 3,
            ErrorMessage = "User name must be between 3 and 50 characters.")]
        [RegularExpression(@"^[a-zA-Z0-9@.\-_]+$",
            ErrorMessage = "User name can only contain letters, numbers, and @ . - _ characters.")]
        public string UserName { get; set; } = string.Empty;

        // ─────────────────────────────────────────────────────────────────────────
        // Email — the user's email address.
        //   → [Required]: must be provided.
        //   → [EmailAddress]: validates email format (e.g., user@example.com).
        //   → [StringLength(256)]: max 256 characters (matches Identity's default).
        //   → Why validate email format here? To give the client immediate feedback
        //     before the request reaches Identity. Identity also validates email
        //     uniqueness, but format validation is a UX improvement.
        // ─────────────────────────────────────────────────────────────────────────
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Please provide a valid email address.")]
        [StringLength(256, ErrorMessage = "Email cannot exceed 256 characters.")]
        public string Email { get; set; } = string.Empty;

        // ─────────────────────────────────────────────────────────────────────────
        // Password — the user's password.
        //   → [Required]: must be provided.
        //   → [StringLength(100, MinimumLength = 8)]: between 8 and 100 characters.
        //   → Why MinimumLength = 8? This is a UX guideline that matches our
        //     PasswordOptions.RequiredLength. If the client sends a shorter password,
        //     they get an early error instead of waiting for Identity validation.
        //   → The actual password rules (digit, uppercase, etc.) are enforced by
        //     Identity's PasswordOptions in Program.cs — not by this DTO.
        // ─────────────────────────────────────────────────────────────────────────
        [Required(ErrorMessage = "Password is required.")]
        [StringLength(100, MinimumLength = 8,
            ErrorMessage = "Password must be between 8 and 100 characters.")]
        public string Password { get; set; } = string.Empty;

        // ─────────────────────────────────────────────────────────────────────────
        // FullName — the user's display name (optional).
        //   → No [Required] — it's optional.
        //   → [StringLength(100)]: max 100 characters if provided.
        //   → Mapped to ApplicationUser.FullName in the controller.
        //   → If not provided, ApplicationUser.FullName remains null.
        // ─────────────────────────────────────────────────────────────────────────
        [StringLength(100, ErrorMessage = "Full name cannot exceed 100 characters.")]
        public string? FullName { get; set; }
    }
}
```

### File: DTOs/UserResponse.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: DTOs/UserResponse.cs
// Video 07 — User Registration: User Response DTO
// ─────────────────────────────────────────────────────────────────────────────
// This DTO defines what the API returns to the client after registration.
// It excludes sensitive data (PasswordHash, SecurityStamp, etc.).
//
// We use this DTO for all user responses — registration, login, profile, etc.
// ─────────────────────────────────────────────────────────────────────────────

namespace IdentityApiTutorial.DTOs
{
    // ─────────────────────────────────────────────────────────────────────────────
    // UserResponse — the response body for user-related endpoints.
    // ─────────────────────────────────────────────────────────────────────────────
    // Properties:
    //   → Id: the user's unique identifier (GUID as string).
    //   → UserName: the user's login name.
    //   → Email: the user's email address.
    //   → FullName: the user's display name (nullable — may be null if not set).
    //   → EmailConfirmed: whether the email has been verified.
    //   → CreatedAt: when the user was created (we set this ourselves, not from
    //     Identity — Identity doesn't track creation date by default).
    //
    // What's NOT included (by design):
    //   → PasswordHash: never send this — it's sensitive.
    //   → SecurityStamp: internal use only.
    //   → ConcurrencyStamp: internal use only.
    //   → AccessFailedCount: internal use only.
    //   → LockoutEnd: internal use only.
    //   → PhoneNumber, TwoFactorEnabled, etc.: we can add these later if needed.
    // ─────────────────────────────────────────────────────────────────────────────
    public class UserResponse
    {
        // ─────────────────────────────────────────────────────────────────────────
        // Id — the user's unique identifier.
        //   → This is the primary key from the database (GUID as string).
        //   → The client can use this to reference the user in other requests
        //     (e.g., assigning roles to this user).
        // ─────────────────────────────────────────────────────────────────────────
        public string Id { get; set; } = string.Empty;

        // ─────────────────────────────────────────────────────────────────────────
        // UserName — the user's login name.
        //   → This is what the user uses to log in.
        //   → It's unique across all users (enforced by Identity).
        // ─────────────────────────────────────────────────────────────────────────
        public string UserName { get; set; } = string.Empty;

        // ─────────────────────────────────────────────────────────────────────────
        // Email — the user's email address.
        //   → This is used for email confirmation and password reset flows.
        //   → It's unique if RequireUniqueEmail is set (which we did in Program.cs).
        // ─────────────────────────────────────────────────────────────────────────
        public string Email { get; set; } = string.Empty;

        // ─────────────────────────────────────────────────────────────────────────
        // FullName — the user's display name (nullable).
        //   → May be null if the user didn't provide one at registration.
        //   → Displayed in UIs instead of UserName for a friendlier experience.
        // ─────────────────────────────────────────────────────────────────────────
        public string? FullName { get; set; }

        // ─────────────────────────────────────────────────────────────────────────
        // EmailConfirmed — whether the email has been verified.
        //   → False by default (user must confirm email to set this to true).
        //   → Used to determine if the user can log in (if we enforce confirmation).
        // ─────────────────────────────────────────────────────────────────────────
        public bool EmailConfirmed { get; set; }

        // ─────────────────────────────────────────────────────────────────────────
        // CreatedAt — when the user was created.
        //   → We set this to DateTime.UtcNow when creating the user.
        //   → Identity doesn't track this by default — we add it for auditing/UX.
        //   → Alternative: add a CreatedDate column to ApplicationUser and have
        //     EF Core set it automatically with a default value.
        // ─────────────────────────────────────────────────────────────────────────
        public DateTime CreatedAt { get; set; }
    }
}
```

### File: DTOs/ApiResponse.cs — Standardized Response Wrapper

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: DTOs/ApiResponse.cs
// Video 07 — User Registration: Standardized API Response Wrapper
// ─────────────────────────────────────────────────────────────────────────────
// Every endpoint returns this wrapper for consistency.
//
// Success response:
//   { "success": true, "data": {...}, "message": null, "errors": null }
//
// Error response:
//   { "success": false, "data": null, "message": "Error description",
//     "errors": { "PropertyName": ["Error 1", "Error 2"] } }
//
// This is NOT the default ASP.NET Core problem details format.
// We use this custom format for consistency across all endpoints.
// ─────────────────────────────────────────────────────────────────────────────

namespace IdentityApiTutorial.DTOs
{
    // ─────────────────────────────────────────────────────────────────────────────
    // ApiResponse<T> — standardized wrapper for all API responses.
    // ─────────────────────────────────────────────────────────────────────────────
    // Generic type T is the data type (UserResponse, LoginResponse, etc.).
    // For error responses with no data, we use ApiResponse<object> or
    // ApiResponse with T = null.
    //
    // Properties:
    //   → Success: true for success, false for error.
    //   → Data: the response data (populated on success, null on error).
    //   → Message: a human-readable message (optional, for both success and error).
    //   → Errors: a dictionary of property-name → error-messages (populated on
    //     validation errors or IdentityErrors).
    // ─────────────────────────────────────────────────────────────────────────────
    public class ApiResponse<T>
    {
        // ─────────────────────────────────────────────────────────────────────────
        // Success — indicates whether the operation succeeded.
        //   → true: the request was processed successfully.
        //   → false: the request failed (validation error, IdentityError, etc.).
        // ─────────────────────────────────────────────────────────────────────────
        public bool Success { get; set; }

        // ─────────────────────────────────────────────────────────────────────────
        // Data — the response payload.
        //   → On success: the requested data (user, token, etc.).
        //   → On error: null (no data to return).
        // ─────────────────────────────────────────────────────────────────────────
        public T? Data { get; set; }

        // ─────────────────────────────────────────────────────────────────────────
        // Message — a human-readable message.
        //   → On success: "User registered successfully." or null.
        //   → On error: "Registration failed." or the specific error description.
        // ─────────────────────────────────────────────────────────────────────────
        public string? Message { get; set; }

        // ─────────────────────────────────────────────────────────────────────────
        // Errors — validation errors or IdentityErrors, keyed by property name.
        //   → On validation errors: { "Password": ["Passwords must be at least 8 characters."] }
        //   → On IdentityErrors: { "Password": ["Passwords must contain a digit."] }
        //   → On success: null.
        // ─────────────────────────────────────────────────────────────────────────
        public Dictionary<string, string[]>? Errors { get; set; }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Non-generic ApiResponse for error responses without data.
    // Convenience type so we don't have to write ApiResponse<object> everywhere.
    // ─────────────────────────────────────────────────────────────────────────────
    public class ApiResponse : ApiResponse<object>
    {
    }
}
```

### File: Controllers/AccountsController.cs — Register Endpoint

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Controllers/AccountsController.cs
// Video 07 — User Registration: Complete Controller
// ─────────────────────────────────────────────────────────────────────────────
// This controller handles user account operations:
//   → Register (POST /api/accounts/register)
//   → Login (POST /api/accounts/login) — Video 08
//   → Profile (GET /api/accounts/me) — Video 07 (partial)
//   → Update Profile (PUT /api/accounts/me) — Video 07 (partial)
//   → Forgot Password (POST /api/accounts/forgot-password) — Video 17
//   → Reset Password (POST /api/accounts/reset-password) — Video 17
//   → Confirm Email (POST /api/accounts/confirm-email) — Video 17
//
// For Video 07, we implement Register and a basic GetMe endpoint.
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.DTOs;
using IdentityApiTutorial.Models;
using IdentityApiTutorial.Services;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Controllers
{
    // ─────────────────────────────────────────────────────────────────────────────
    // [ApiController] — enables API-specific behaviors:
    //   → Automatic model validation (returns 400 if the DTO is invalid).
    //   → Binding source inference ([FromBody] for complex types, [FromQuery] for
    //     simple types, etc.).
    //   → Problem details for error responses (consistent JSON format).
    //   → 400 on unbound parameters (if a parameter can't be bound, return 400).
    // ─────────────────────────────────────────────────────────────────────────────
    [ApiController]

    // ─────────────────────────────────────────────────────────────────────────────
    // [Route("api/[controller]")] — sets the URL prefix for all actions.
    //   → [controller] resolves to "Accounts" (from AccountsController).
    //   → Full route for Register: POST /api/accounts/register
    //   → Full route for Login: POST /api/accounts/login
    //   → Full route for GetMe: GET /api/accounts/me
    // ─────────────────────────────────────────────────────────────────────────────
    [Route("api/[controller]")]
    public class AccountsController : ControllerBase
    {
        // ─────────────────────────────────────────────────────────────────────────
        // _userManager — primary service for user operations.
        //   → Injected by DI (registered by AddIdentityCore in Program.cs).
        //   → Used for: CreateAsync, FindByNameAsync, FindByEmailAsync,
        //     UpdateAsync, DeleteAsync, AddClaimAsync, AddToRoleAsync, etc.
        // ─────────────────────────────────────────────────────────────────────────
        private readonly UserManager<ApplicationUser> _userManager;

        // ─────────────────────────────────────────────────────────────────────────
        // _jwtService — our custom service for generating JWT tokens.
        //   → Injected by DI (registered in Program.cs).
        //   → Used for: GenerateJwtToken(user) — creates a JWT with user claims.
        //   → Used in the Login endpoint (Video 08).
        // ─────────────────────────────────────────────────────────────────────────
        private readonly JwtService _jwtService;

        // ─────────────────────────────────────────────────────────────────────────
        // Constructor — ASP.NET Core DI injects all dependencies.
        //   → UserManager and JwtService are resolved from the DI container.
        //   → This controller is created per request (scoped).
        // ─────────────────────────────────────────────────────────────────────────
        public AccountsController(
            UserManager<ApplicationUser> userManager,
            JwtService jwtService)
        {
            _userManager = userManager;
            _jwtService = jwtService;
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // POST /api/accounts/register — Register a new user
        // ═══════════════════════════════════════════════════════════════════════════
        // Request body: { "userName": "...", "password": "...", "email": "...",
        //                "fullName": "..." }
        // Response: 201 Created with UserResponse (on success)
        //           400 Bad Request with ApiResponse errors (on failure)
        // ─────────────────────────────────────────────────────────────────────────────
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            // ─────────────────────────────────────────────────────────────────────────
            // Step 1: Create an ApplicationUser from the request.
            //   → Map the DTO properties to the ApplicationUser properties.
            //   → UserName comes from request.UserName.
            //   → Email comes from request.Email.
            //   → FullName comes from request.FullName (nullable — may be null).
            //   → EmailConfirmed is false by default (user must confirm email to
            //     set this to true — we don't enforce this for the tutorial).
            //   → SecurityStamp and ConcurrencyStamp are set by Identity automatically
            //     when the user is created (don't set them here).
            // ─────────────────────────────────────────────────────────────────────────
            var user = new ApplicationUser
            {
                UserName = request.UserName,
                Email = request.Email,
                FullName = request.FullName,
                EmailConfirmed = false  // User must confirm email (if we enforce it)
            };

            // ─────────────────────────────────────────────────────────────────────────
            // Step 2: Call UserManager.CreateAsync to create the user.
            //   → This is the key Identity call — it does several things:
            //     1. Validates the password against PasswordOptions rules
            //        (length, digit, uppercase, lowercase, non-alphanumeric).
            //     2. Hashes the password using PBKDF2 (PasswordHasher).
            //        The hash includes a random salt — different for each user.
            //     3. Sets user.SecurityStamp to a new random value.
            //     4. Sets user.ConcurrencyStamp to a new random value.
            //     5. Saves the user to the database (via IUserStore / EF Core).
            //        This inserts a row into AspNetUsers.
            //   → Returns Task<IdentityResult>:
            //     → Success: IdentityResult.Success (user was created).
            //     → Failed: IdentityResult with Errors (list of IdentityError).
            //   → The password parameter is the PLAINTEXT password from the request.
            //     Identity hashes it internally — we never hash it ourselves.
            // ─────────────────────────────────────────────────────────────────────────
            var result = await _userManager.CreateAsync(user, request.Password);

            // ─────────────────────────────────────────────────────────────────────────
            // Step 3: Check the result.
            //   → If Success: create the response and return 201 Created.
            //   → If Failed: create an error response with the IdentityErrors and
            //     return 400 Bad Request.
            // ─────────────────────────────────────────────────────────────────────────
            if (result.Succeeded)
            {
                // ─────────────────────────────────────────────────────────────────────────
                // Success: create the UserResponse.
                //   → Map the ApplicationUser properties to UserResponse.
                //   → Exclude sensitive fields (PasswordHash, SecurityStamp, etc.).
                //   → Include CreatedAt (set to DateTime.UtcNow — the time of creation).
                // ─────────────────────────────────────────────────────────────────────────
                var response = new UserResponse
                {
                    Id = user.Id,
                    UserName = user.UserName,
                    Email = user.Email,
                    FullName = user.FullName,
                    EmailConfirmed = user.EmailConfirmed,
                    CreatedAt = DateTime.UtcNow
                };

                // ─────────────────────────────────────────────────────────────────────────
                // Return 201 Created.
                //   → 201 Created indicates the resource was created.
                //   → The response body is the ApiResponse<UserResponse> with
                //     Success = true, Data = response, Message = "User registered successfully."
                //   → In a REST API, you might also return a Location header with
                //     the URL of the created resource. For simplicity, we return
                //     the data directly.
                // ─────────────────────────────────────────────────────────────────────────
                return Ok(new ApiResponse<UserResponse>
                {
                    Success = true,
                    Data = response,
                    Message = "User registered successfully."
                });
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Failure: create an error response from the IdentityErrors.
            //   → result.Errors is a collection of IdentityError objects.
            //   → Each IdentityError has:
            //     → Code: a machine-readable error code (e.g., "PasswordTooShort").
            //     → Description: a human-readable error message (e.g.,
            //       "Passwords must be at least 8 characters.").
            //   → We group errors by property name for the client.
            //   → The client can use these to show field-specific error messages.
            // ─────────────────────────────────────────────────────────────────────────
            var errors = new Dictionary<string, string[]>();

            foreach (var error in result.Errors)
            {
                // Determine which property this error is for.
                // IdentityError descriptions often mention the property name.
                // We use a simple heuristic: if the description mentions "Password",
                // we group it under "Password". Otherwise, we use a general key.
                //
                // A more sophisticated approach would parse the error Code
                // (e.g., "PasswordTooShort" → "Password").
                string propertyName = "General";

                if (error.Description.Contains("Password", StringComparison.OrdinalIgnoreCase))
                {
                    propertyName = "Password";
                }
                else if (error.Description.Contains("Email", StringComparison.OrdinalIgnoreCase))
                {
                    propertyName = "Email";
                }
                else if (error.Description.Contains("User name", StringComparison.OrdinalIgnoreCase))
                {
                    propertyName = "UserName";
                }

                // Add the error to the dictionary.
                // If the property already exists, add to the existing array.
                if (errors.ContainsKey(propertyName))
                {
                    var existing = errors[propertyName];
                    errors[propertyName] = existing.Append(error.Description).ToArray();
                }
                else
                {
                    errors[propertyName] = new[] { error.Description };
                }
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Return 400 Bad Request with the error response.
            //   → 400 Bad Request indicates the request was invalid.
            //   → The response body contains the errors grouped by property.
            //   → The client can use these to show field-specific error messages.
            // ─────────────────────────────────────────────────────────────────────────
            return BadRequest(new ApiResponse<object>
            {
                Success = false,
                Data = null,
                Message = "Registration failed. Please correct the errors below.",
                Errors = errors
            });
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // GET /api/accounts/me — Get the current user's profile
        // ═══════════════════════════════════════════════════════════════════════════
        // This endpoint requires authentication (JWT token).
        // It returns the profile of the currently authenticated user.
        //
        // We add [Authorize] to require a valid JWT token.
        // The user's ID is extracted from the JWT claims (ClaimTypes.NameIdentifier).
        //
        // For Video 07, this is a simple endpoint that shows how to:
        //   → Require authentication ([Authorize])
        //   → Get the current user's ID from claims
        //   → Look up the user with UserManager.FindByIdAsync
        //   → Return the user data (excluding sensitive fields)
        // ─────────────────────────────────────────────────────────────────────────────
        [Authorize]  // Requires a valid JWT token
        [HttpGet("me")]
        public async Task<IActionResult> GetMe()
        {
            // ─────────────────────────────────────────────────────────────────────────
            // Step 1: Get the current user's ID from the JWT claims.
            //   → When the JwtBearer middleware validates the JWT token, it creates
            //     a ClaimsPrincipal and sets HttpContext.User.
            //   → The user's ID is stored in the "sub" (subject) claim, which maps
            //     to ClaimTypes.NameIdentifier in .NET.
            //   → User.FindFirstValue(ClaimTypes.NameIdentifier) gets the user ID
            //     from the claims.
            //   → If the user is not authenticated (no valid JWT), this returns null,
            //     but [Authorize] already prevents unauthenticated requests from
            //     reaching this method (returns 401).
            // ─────────────────────────────────────────────────────────────────────────
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // ─────────────────────────────────────────────────────────────────────────
            // Step 2: Look up the user by ID.
            //   → UserManager.FindByIdAsync(userId) queries the database for the
            //     user with the given ID.
            //   → Returns Task<ApplicationUser?> (nullable — user may not exist).
            //   → If the user doesn't exist, we return 404 Not Found.
            // ─────────────────────────────────────────────────────────────────────────
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Data = null,
                    Message = "User not found."
                });
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Step 3: Return the user data (excluding sensitive fields).
            //   → Map ApplicationUser to UserResponse.
            //   → Exclude PasswordHash, SecurityStamp, etc.
            // ─────────────────────────────────────────────────────────────────────────
            var response = new UserResponse
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                FullName = user.FullName,
                EmailConfirmed = user.EmailConfirmed,
                CreatedAt = DateTime.UtcNow  // In a real app, store CreatedAt on the user
            };

            return Ok(new ApiResponse<UserResponse>
            {
                Success = true,
                Data = response,
                Message = null
            });
        }
    }
}
```

---

## Postman / Swagger Tests

### Test 1: Successful Registration

**Request:**
```
POST https://localhost:7001/api/accounts/register
Content-Type: application/json

{
  "userName": "ahmad",
  "password": "Test@1234",
  "email": "ahmad@example.com",
  "fullName": "Ahmad Developer"
}
```

**Expected Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "userName": "ahmad",
    "email": "ahmad@example.com",
    "fullName": "Ahmad Developer",
    "emailConfirmed": false,
    "createdAt": "2024-01-01T12:00:00Z"
  },
  "message": "User registered successfully."
}
```

**Verification:**
- The response has `success: true`.
- The `data` contains the user's ID, UserName, Email, FullName, EmailConfirmed, and CreatedAt.
- The `data` does NOT contain PasswordHash, SecurityStamp, or any sensitive fields.
- Save the `id` to use in later tests (role assignment, etc.).

### Test 2: Registration with Weak Password

**Request:**
```
POST https://localhost:7001/api/accounts/register
Content-Type: application/json

{
  "userName": "weakuser",
  "password": "123456",
  "email": "weak@example.com",
  "fullName": "Weak User"
}
```

**Expected Response (400 Bad Request):**
```json
{
  "success": false,
  "data": null,
  "message": "Registration failed. Please correct the errors below.",
  "errors": {
    "Password": [
      "Passwords must be at least 8 characters.",
      "Passwords must contain at least one digit ('0'-'9').",
      "Passwords must contain at least one uppercase ('A'-'Z') character.",
      "Passwords must contain at least one lowercase ('a'-'z') character.",
      "Passwords must contain at least one non-alphanumeric character."
    ]
  }
}
```

**Verification:**
- The response has `success: false`.
- The `errors` object contains a "Password" key with an array of error messages.
- Each error message describes a specific password rule that was violated.
- The user was NOT created (check the database — no new row in AspNetUsers).

### Test 3: Registration with Duplicate Email

**Request:**
```
POST https://localhost:7001/api/accounts/register
Content-Type: application/json

{
  "userName": "anotheruser",
  "password": "Test@1234",
  "email": "ahmad@example.com",
  "fullName": "Another User"
}
```

**Expected Response (400 Bad Request):**
```json
{
  "success": false,
  "data": null,
  "message": "Registration failed. Please correct the errors below.",
  "errors": {
    "Email": [
      "A user with that email already exists."
    ]
  }
}
```

**Verification:**
- The error is grouped under "Email".
- The message indicates the email is already in use.
- The user was NOT created.

### Test 4: Registration with Missing Required Fields

**Request:**
```
POST https://localhost:7001/api/accounts/register
Content-Type: application/json

{
  "userName": "nouser",
  "password": "Test@1234"
}
```

**Expected Response (400 Bad Request):**
```json
{
  "success": false,
  "data": null,
  "message": "One or more validation errors occurred.",
  "errors": {
    "Email": ["Email is required."]
  }
}
```

**Verification:**
- This is a model validation error (not an IdentityError).
- [ApiController] automatically returns 400 for validation errors.
- The error is under "Email" because Email is [Required] and was not provided.
- Note: This response format may differ from our custom ApiResponse format — [ApiController] uses the default problem details format for model validation errors. To use our custom format, we'd need to customize the error handler (covered in Video 19 / production readiness).

### Test 5: Get Current User Profile (Requires Authentication)

**Request:**
```
GET https://localhost:7001/api/accounts/me
Authorization: Bearer <token>
```

**Note:** This requires a valid JWT token. We'll get one in Video 08 (Login). For now, the endpoint returns 401 Unauthorized without a token.

**Expected Response (200 OK) — after login:**
```json
{
  "success": true,
  "data": {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "userName": "ahmad",
    "email": "ahmad@example.com",
    "fullName": "Ahmad Developer",
    "emailConfirmed": false,
    "createdAt": "2024-01-01T12:00:00Z"
  },
  "message": null
}
```

### Test 6: Get Current User Profile Without Token

**Request:**
```
GET https://localhost:7001/api/accounts/me
```

**Expected Response (401 Unauthorized):**
```json
{
  "type": "https://tools.ietf.org/html/rfc9110#section-15.5.5",
  "title": "Unauthorized",
  "status": 401,
  "traceId": "00-abc123def456..."
}
```

**Verification:**
- [Authorize] attribute returns 401 when no valid JWT token is provided.
- The response is the default ASP.NET Core problem details format (not our custom ApiResponse format — this is because the authorization middleware returns the default format; we can customize this later).

### Swagger Tests

1. Run the API and navigate to `https://localhost:7001/swagger`.
2. Find the `POST /api/accounts/register` endpoint.
3. Click "Try it out".
4. Enter the request body:
   ```json
   {
     "userName": "swaggeruser",
     "password": "Test@1234",
     "email": "swagger@example.com",
     "fullName": "Swagger User"
   }
   ```
5. Click "Execute".
6. Expected: `201 Created` with the user response.
7. Find the `GET /api/accounts/me` endpoint.
8. Click "Try it out".
9. Expected: `401 Unauthorized` (no token provided).
10. Click the "Authorize" button at the top of Swagger UI.
11. Enter a JWT token (we'll get one in Video 08).
12. Try `GET /api/accounts/me` again — expected: `200 OK` with the user profile.

---

# Video 08 — Login API — JWT Token Issuance

## Theory & Definitions

### What Login Does in an API

Login is the endpoint that verifies a user's credentials (username + password) and, if valid, issues a JWT token. The client then uses this token to authenticate subsequent requests.

```
POST /api/accounts/login
Content-Type: application/json

{
  "userName": "ahmad",
  "password": "Test@1234"
}
```

The API:
1. Finds the user by UserName (or Email, depending on your design).
2. Calls `SignInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true)`.
3. If the password is correct and the account is not locked out, returns a JWT token.
4. If the password is wrong or the account is locked out, returns an error.

### The Login Flow — Step by Step

```
Client: POST /api/accounts/login { userName, password }
    ↓
[Model Validation] → If invalid → 400 Bad Request
    ↓
AccountsController.Login()
    ↓
UserManager.FindByNameAsync(userName)
    ↓
  → If user not found → return failure (don't reveal "user not found" vs "wrong password"
    — for security, return the same error for both)
    ↓
SignInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true)
    ↓
  → Password verified against hash (PasswordHasher compares hashes)
  → Lockout checked (AccessFailedCount, LockoutEnd, LockoutEnabled)
  → SignInResult returned:
    → Succeeded: password is correct, account is not locked out
    → IsLockedOut: account is locked out (too many failed attempts)
    → IsNotAllowed: account is not allowed to sign in (e.g., email not confirmed)
    → Failed: password is wrong
    ↓
If Succeeded:
  → JwtService.GenerateJwtToken(user) → creates JWT with claims
  → Return 200 OK with { token, expiresIn, user }
If Failed / IsLockedOut / IsNotAllowed:
  → Return 401 Unauthorized with appropriate error message
```

### CheckPasswordSignInAsync vs. PasswordSignInAsync

| Method | Behavior | Use in API? |
|--------|----------|-------------|
| `CheckPasswordSignInAsync(user, password, lockoutOnFailure)` | Verifies the password and returns a `SignInResult` **without** signing the user in (no cookie, no session). | ✅ Yes — this is what we use in the API. |
| `PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure)` | Verifies the password and **signs the user in** (creates a cookie). | ❌ No — this creates a cookie, which is MVC/Razor Pages behavior. |
| `SignInAsync(user, isPersistent, authenticationMethod)` | Signs the user in (creates a cookie). | ❌ No — cookie-based, not API-friendly. |

**Why CheckPasswordSignInAsync:**

In an API, we don't want to create a cookie or establish a server-side session. We want to:
1. Verify the password.
2. If correct, generate a JWT token.
3. Return the token to the client.
4. The client includes the token in future requests.

`CheckPasswordSignInAsync` does step 1 without doing steps 2-4 (those are cookie-based). It gives us a `SignInResult` that we can use to decide whether to issue a token.

### The SignInResult — What It Tells You

`SignInResult` has these properties:

| Property | Type | Meaning |
|----------|------|---------|
| `Succeeded` | `bool` | True if the password is correct and the account is allowed to sign in. |
| `IsLockedOut` | `bool` | True if the account is locked out (too many failed attempts). |
| `IsNotAllowed` | `bool` | True if the account is not allowed to sign in (e.g., email not confirmed, phone not confirmed). |
| `HardwareTokenSupported` | `bool` | True if a hardware token (e.g., FIDO2) is supported. |
| `Token` | `string?` | The sign-in token (for external logins). |

We check `result.Succeeded` to determine if we should issue a JWT token.

### Lockout — How It Works

When `lockoutOnFailure: true` is passed to `CheckPasswordSignInAsync`:

1. If the password is **wrong**, Identity increments `AccessFailedCount` on the user.
2. If `AccessFailedCount` reaches `MaxFailedAccessAttempts` (5, configured in Program.cs), the account is locked out:
   - `LockoutEnd` is set to `DateTime.UtcNow + DefaultLockoutTimeSpan` (5 minutes, configured in Program.cs).
   - `IsLockedOut` is true.
3. If the password is **correct**, `AccessFailedCount` is reset to 0 and `LockoutEnd` is cleared.

**For the API**, we check `result.IsLockedOut` and return a message like "Account is locked out. Try again in X minutes."

### JWT Token Generation — What We Do

After a successful login, we generate a JWT token manually (not through the ASP.NET Core auth system). Our `JwtService` does this:

1. Create a `JwtSecurityToken` with:
   - `Issuer` — from configuration.
   - `Audience` — from configuration.
   - `Claims` — the user's claims (ID, UserName, Email, Roles).
   - `Expires` — current time + expiration window (60 minutes, from configuration).
   - `SigningCredentials` — HMAC-SHA256 with our secret key.
2. Write the token as a string (JWT format: header.payload.signature).
3. Return the token to the client.

The client stores the token (in memory, localStorage, or a secure store) and sends it in the `Authorization: Bearer <token>` header on future requests.

### The Login Response

A successful login returns:

```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": 3600,
    "tokenType": "Bearer",
    "user": {
      "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "userName": "ahmad",
      "email": "ahmad@example.com",
      "fullName": "Ahmad Developer",
      "emailConfirmed": false
    }
  },
  "message": "Login successful."
}
```

The response includes:
- `token` — the JWT token (the client sends this in the Authorization header).
- `expiresIn` — the token's lifetime in seconds (3600 = 1 hour).
- `tokenType` — "Bearer" (the client uses `Authorization: Bearer <token>`).
- `user` — the user's profile (so the client doesn't need to call /me immediately).

### Security Considerations for Login

| Concern | How We Address It |
|---------|-------------------|
| **Don't reveal whether the user exists** | Return the same error for "user not found" and "wrong password" — both return "Invalid credentials." |
| **Account lockout** | Check lockout status and return an appropriate message. Don't reveal "account locked" vs "wrong password" — but for the tutorial, we show the distinction for educational purposes. |
| **Password in request body** | Always use HTTPS. The password is sent in the request body (not URL, not headers). HTTPS encrypts the entire request. |
| **Token storage on client** | The client is responsible for storing the token securely. In a web app, use httpOnly cookies or memory. In a mobile app, use the secure storage. |
| **Token expiration** | Set a reasonable expiration (1 hour for access tokens). Use refresh tokens for longer sessions (covered in Video 17 / production). |
| **Brute force protection** | Account lockout (5 failed attempts → 5-minute lockout) prevents brute force. Rate limiting (Video 19) adds another layer. |

---

## 🎬 Video Recording Notes

**Opening (say this):**

> "Now we build the login endpoint — the most important endpoint in any authentication system. The user sends their username and password, we verify them, and if they're correct, we issue a JWT token. I'll show you exactly how CheckPasswordSignInAsync works, why we use it instead of SignInAsync, how the JWT token is generated, and what the response looks like."

**Show on screen:**

> The `LoginRequest` DTO. The `LoginResponse` DTO. The `AccountsController.Login` method, line by line. The `JwtService.GenerateJwtToken` method. The Postman request and response. A decoded JWT token (show the header, payload, and signature in the terminal or a JWT debugger).

**Key points to emphasize (say this):**

> "We use CheckPasswordSignInAsync — not PasswordSignInAsync or SignInAsync. Those create cookies. CheckPasswordSignInAsync just verifies the password and tells us if it succeeded — no cookie, no session. That's what we want in an API."

> "The SignInResult tells us more than just 'succeeded' or 'failed'. It tells us if the account is locked out, if it's not allowed to sign in (email not confirmed), etc. We handle each case differently."

> "After a successful login, we generate a JWT token manually. The JwtService creates a JWT with the user's claims (ID, UserName, Email, Roles) and signs it with our secret key. The client sends this token in the Authorization header on every request."

> "We don't reveal whether the user exists or the password is wrong — both return 'Invalid credentials.' This prevents user enumeration attacks (where an attacker tries to find valid usernames)."

> "The token has an expiration (1 hour by default). After it expires, the client must log in again. In production, you'd use refresh tokens for a better UX — we cover that in Video 17."

**Analogy (say this):**

> "Login is like showing your ID at a security checkpoint. You show your username (your name) and password (your PIN). The guard (CheckPasswordSignInAsync) checks your ID against the records. If everything matches, they give you a temporary badge (JWT token) that you wear for the next hour. Every time you enter a restricted area, the scanner reads your badge — it doesn't check your ID again, it just reads the badge. When the badge expires (1 hour), you have to go back to the checkpoint and get a new one."

**Common viewer questions:**

> "Why not just use the ASP.NET Core auth system to generate the token?" — The ASP.NET Core JWT Bearer middleware validates tokens but doesn't generate them. We generate tokens manually using System.IdentityModel.Tokens.Jwt. This gives us full control over the claims and the token structure.

> "What happens when the token expires?" — The client gets a 401 Unauthorized on the next request. The client must log in again to get a new token. In production, you'd use a refresh token flow to get a new access token without re-entering credentials.

> "Is the JWT token secure?" — The token is signed with our secret key. Anyone can decode the payload (it's Base64Url encoded, not encrypted), but they can't forge the signature without the key. The token is only as secure as the secret key — keep it safe. Use HTTPS to prevent token interception.

> "Can I include roles in the JWT token?" — Yes — we include the user's roles as claims in the JWT. This way, the authorization middleware can check roles without querying the database. We'll see this in Video 10 (RBAC).

**What to show:**

- The LoginRequest DTO
- The LoginResponse DTO
- The AccountsController.Login method (full, with comments)
- The JwtService.GenerateJwtToken method (full, with comments)
- The Postman request (POST /api/accounts/login with credentials)
- The Postman response (200 OK with JWT token)
- A decoded JWT token (use jwt.io or a similar tool to show the payload)
- A failed login (wrong password) showing the error response
- A locked-out account showing the lockout message

**What to skip:**

- Refresh token flow (covered in Video 17 — keep it simple for now)
- External login (Google, Facebook — covered in Video 16)
- 2FA login (covered in Video 15)

---

## Complete Implementation

### File: DTOs/LoginRequest.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: DTOs/LoginRequest.cs
// Video 08 — Login API: Login Request DTO
// ─────────────────────────────────────────────────────────────────────────────
// This DTO defines what the client sends to the login endpoint.
// ─────────────────────────────────────────────────────────────────────────────

using System.ComponentModel.DataAnnotations;

namespace IdentityApiTutorial.DTOs
{
    // ─────────────────────────────────────────────────────────────────────────────
    // LoginRequest — the request body for POST /api/accounts/login.
    // ─────────────────────────────────────────────────────────────────────────────
    // Properties:
    //   → UserName: the user's login name (required).
    //   → Password: the user's password (required).
    //
    // We don't validate the password format here — Identity does that during
    // account creation. During login, we just pass the password to
    // CheckPasswordSignInAsync and let Identity verify it.
    // ─────────────────────────────────────────────────────────────────────────────
    public class LoginRequest
    {
        // ─────────────────────────────────────────────────────────────────────────
        // UserName — the user's login name.
        //   → [Required]: must be provided.
        //   → The controller uses this to look up the user via
        //     UserManager.FindByNameAsync(userName).
        //   → Alternative: you could allow login by email instead of (or in
        //     addition to) UserName. For the tutorial, we use UserName.
        // ─────────────────────────────────────────────────────────────────────────
        [Required(ErrorMessage = "User name is required.")]
        public string UserName { get; set; } = string.Empty;

        // ─────────────────────────────────────────────────────────────────────────
        // Password — the user's password.
        //   → [Required]: must be provided.
        //   → The controller passes this to
        //     SignInManager.CheckPasswordSignInAsync(user, password, true).
        //   → Identity verifies the password against the stored hash.
        // ─────────────────────────────────────────────────────────────────────────
        [Required(ErrorMessage = "Password is required.")]
        public string Password { get; set; } = string.Empty;
    }
}
```

### File: DTOs/LoginResponse.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: DTOs/LoginResponse.cs
// Video 08 — Login API: Login Response DTO
// ─────────────────────────────────────────────────────────────────────────────
// This DTO defines what the API returns after a successful login.
// ─────────────────────────────────────────────────────────────────────────────

namespace IdentityApiTutorial.DTOs
{
    // ─────────────────────────────────────────────────────────────────────────────
    // LoginResponse — the response body for a successful login.
    // ─────────────────────────────────────────────────────────────────────────────
    // Properties:
    //   → Token: the JWT token (the client sends this in the Authorization header).
    //   → ExpiresIn: the token's lifetime in seconds (e.g., 3600 = 1 hour).
    //   → TokenType: "Bearer" (the client uses Authorization: Bearer <token>).
    //   → User: the user's profile (so the client has the user data without an
    //     additional request to /api/accounts/me).
    //
    // The Token is the most important field — without it, the client can't
    // authenticate subsequent requests.
    // ─────────────────────────────────────────────────────────────────────────────
    public class LoginResponse
    {
        // ─────────────────────────────────────────────────────────────────────────
        // Token — the JWT access token.
        //   → This is the signed JWT string (header.payload.signature).
        //   → The client stores this and sends it in the Authorization header
        //     on every request: Authorization: Bearer <token>.
        //   → The token contains the user's claims (ID, UserName, Email, Roles).
        //   → The token expires after ExpiresIn seconds.
        // ─────────────────────────────────────────────────────────────────────────
        public string Token { get; set; } = string.Empty;

        // ─────────────────────────────────────────────────────────────────────────
        // ExpiresIn — the token's lifetime in seconds.
        //   → The client can use this to show a countdown or to refresh the token
        //     before it expires.
        //   → For our tutorial, this is 3600 seconds (1 hour).
        // ─────────────────────────────────────────────────────────────────────────
        public int ExpiresIn { get; set; }

        // ─────────────────────────────────────────────────────────────────────────
        // TokenType — the token type (always "Bearer" for our API).
        //   → The client uses this to construct the Authorization header:
        //     Authorization: Bearer <token>
        // ─────────────────────────────────────────────────────────────────────────
        public string TokenType { get; set; } = "Bearer";

        // ─────────────────────────────────────────────────────────────────────────
        // User — the authenticated user's profile.
        //   → Included so the client has the user data immediately after login
        //     (doesn't need to call /api/accounts/me first).
        //   → Contains: Id, UserName, Email, FullName, EmailConfirmed.
        //   → Does NOT contain: PasswordHash, SecurityStamp, etc.
        // ─────────────────────────────────────────────────────────────────────────
        public UserResponse User { get; set; } = null!;
    }
}
```

### File: Services/JwtService.cs — JWT Token Generation

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Services/JwtService.cs
// Video 08 — Login API: JWT Token Generation Service
// ─────────────────────────────────────────────────────────────────────────────
// This service generates JWT tokens manually (not through the ASP.NET Core
// auth system).
//
// How it works:
//   1. Gets the user's claims (ID, UserName, Email, Roles).
//   2. Creates a JwtSecurityToken with the claims, issuer, audience, expiration,
//      and signing credentials.
//   3. Writes the token as a string (JWT format).
//   4. Returns the token and its expiration time.
//
// This service is called by the Login endpoint after a successful login.
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using IdentityApiTutorial.Models;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Services
{
    // ─────────────────────────────────────────────────────────────────────────────
    // JwtService — generates JWT tokens for authenticated users.
    // ─────────────────────────────────────────────────────────────────────────────
    // This is a custom service — not part of Identity.
    // It uses System.IdentityModel.Tokens.Jwt to create and sign JWT tokens.
    //
    // Design decisions:
    //   → Scoped service (one instance per request) — appropriate because it
    //     reads configuration and creates a token per request.
    //   → Reads JWT settings from IConfiguration (SecretKey, Issuer, Audience,
    //     ExpirationInMinutes).
    //   → Includes the user's roles as claims in the JWT (so authorization can
    //     check roles without querying the database).
    //
    // HOW TO USE THIS FOR YOUR VIDEO:
    //   - Show the GenerateJwtToken method line by line.
    //   - Explain each claim we add to the JWT.
    //   - Explain the signing credentials (SymmetricSecurityKey with HS256).
    //   - Explain the expiration.
    //   - Show a decoded JWT token (use jwt.io) to verify the claims are there.
    // ─────────────────────────────────────────────────────────────────────────────
    public class JwtService
    {
        // ─────────────────────────────────────────────────────────────────────────
        // _configuration — used to read JWT settings from appsettings.json.
        //   → IConfiguration is injected by DI (available by default in .NET).
        //   → We read: JwtSettings:SecretKey, JwtSettings:Issuer,
        //     JwtSettings:Audience, JwtSettings:ExpirationInMinutes.
        // ─────────────────────────────────────────────────────────────────────────
        private readonly IConfiguration _configuration;

        // ─────────────────────────────────────────────────────────────────────────
        // Constructor — IConfiguration is injected by DI.
        // ─────────────────────────────────────────────────────────────────────────
        public JwtService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // GenerateJwtToken — creates a JWT token for the given user.
        //   → Called after a successful login (CheckPasswordSignInAsync succeeded).
        //   → Returns a tuple: (token string, expires in seconds).
        //
        // Parameters:
        //   → user: the ApplicationUser that just logged in.
        //   → userManager: UserManager for getting the user's roles.
        //
        // Returns: Task<(string Token, int ExpiresIn)>
        //   → Token: the JWT token string.
        //   → ExpiresIn: the token's lifetime in seconds.
        // ─────────────────────────────────────────────────────────────────────────
        public async Task<(string Token, int ExpiresIn)> GenerateJwtToken(
            ApplicationUser user,
            UserManager<ApplicationUser> userManager)
        {
            // ─────────────────────────────────────────────────────────────────────────
            // Step 1: Read JWT settings from configuration.
            //   → SecretKey: the key used to sign the token (HMAC-SHA256).
            //     Must be at least 256 bits (32 characters).
            //   → Issuer: the entity that issued the token (our API).
            //   → Audience: the entity the token is for (our API's clients).
            //   → ExpirationInMinutes: how long the token is valid (default 60).
            // ─────────────────────────────────────────────────────────────────────────
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var secretKey = jwtSettings["SecretKey"]
                ?? throw new InvalidOperationException("JWT SecretKey is not configured.");
            var issuer = jwtSettings["Issuer"]
                ?? throw new InvalidOperationException("JWT Issuer is not configured.");
            var audience = jwtSettings["Audience"]
                ?? throw new InvalidOperationException("JWT Audience is not configured.");
            var expirationMinutes = int.Parse(jwtSettings["ExpirationInMinutes"] ?? "60");

            // ─────────────────────────────────────────────────────────────────────────
            // Step 2: Get the user's roles.
            //   → UserManager.GetRolesAsync(user) returns the roles assigned to the
            //     user (e.g., "Admin", "User").
            //   → We include these as claims in the JWT so that the authorization
            //     middleware can check roles without querying the database.
            //   → This is important for performance — the JWTBearer middleware doesn't
            //     have access to the database, it only reads the JWT claims.
            // ─────────────────────────────────────────────────────────────────────────
            var roles = await userManager.GetRolesAsync(user);

            // ─────────────────────────────────────────────────────────────────────────
            // Step 3: Create the claims for the JWT.
            //   → Claims are name-value pairs that describe the user.
            //   → The JWT payload is a JSON object with these claims.
            //   → We add the following claims:
            //     → ClaimTypes.NameIdentifier (sub): the user's ID — this is the
            //       standard "subject" claim in JWT. The authorization middleware
            //       uses this to identify the user.
            //     → ClaimTypes.Name (name): the user's UserName.
            //     → ClaimTypes.Email (email): the user's email.
            //     → Custom "fullName" claim: the user's full name (optional).
            //     → Role claims (role): one claim per role (e.g., "Admin", "User").
            //       These are used by [Authorize(Roles="Admin")] to check roles.
            // ─────────────────────────────────────────────────────────────────────────
            var claims = new List<Claim>
            {
                // Subject claim — the user's unique identifier.
                // This is the standard "sub" claim in JWT.
                // The authorization middleware uses this to identify the user
                // (User.FindFirstValue(ClaimTypes.NameIdentifier)).
                new Claim(ClaimTypes.NameIdentifier, user.Id),

                // Name claim — the user's UserName.
                // This is the standard "name" claim in JWT.
                new Claim(ClaimTypes.Name, user.UserName),

                // Email claim — the user's email address.
                // This is the standard "email" claim in JWT.
                new Claim(ClaimTypes.Email, user.Email ?? string.Empty),

                // Custom "fullName" claim — the user's display name.
                // Custom claims use any string as the type.
                // We use "fullName" as the claim type.
                new Claim("fullName", user.FullName ?? string.Empty),

                // Role claims — one claim per role.
                // Each role becomes a "role" claim in the JWT.
                // The authorization middleware checks these for
                // [Authorize(Roles="Admin")] etc.
                // Note: We use "role" (singular) as the claim type for each role.
                // Some systems use "roles" (array) — we use individual "role" claims
                // for simplicity and compatibility with ASP.NET Core's role authorization.
            };

            // Add a claim for each role.
            // [Authorize(Roles="Admin")] checks for a claim of type "role" with
            // value "Admin". By adding one "role" claim per user role, we enable
            // role-based authorization via JWT claims.
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
                // Also add a "role" claim (some systems expect this instead of
                // ClaimTypes.Role which is "http://schemas.microsoft.com/ws/2008/06/identity/claims/role").
                // Both work — ClaimTypes.Role is the standard .NET mapping.
                claims.Add(new Claim("role", role));
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Step 4: Create the signing credentials.
            //   → SymmetricSecurityKey: uses HMAC-SHA256 (HS256 algorithm).
            //   → The key is the secret key from configuration, converted to bytes.
            //   → This key is used to SIGN the token (create the signature).
            //   → The same key is used by the JwtBearer middleware to VALIDATE
            //     the token (verify the signature).
            //   → Security: keep this key secret. Anyone with the key can forge tokens.
            // ─────────────────────────────────────────────────────────────────────────
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // ─────────────────────────────────────────────────────────────────────────
            // Step 5: Create the JWT token.
            //   → JwtSecurityToken represents a JWT before it's written as a string.
            //   → Parameters:
            //     → issuer: the entity that issued the token.
            //     → audience: the entity the token is for.
            //     → claims: the claims to include in the token.
            //     → expires: when the token expires (current time + expiration).
            //     → signingCredentials: the key and algorithm used to sign the token.
            //   → The token is NOT encrypted — the payload is visible (Base64Url
            //     encoded). Only the signature is protected.
            // ─────────────────────────────────────────────────────────────────────────
            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(expirationMinutes),
                signingCredentials: credentials
            );

            // ─────────────────────────────────────────────────────────────────────────
            // Step 6: Write the token as a string.
            //   → new JwtSecurityTokenHandler().WriteToken(token) converts the
            //     JwtSecurityToken to a JWT string (header.payload.signature).
            //   → The result is a long string like:
            //     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw..."
            //   → This is the token that the client sends in the Authorization header.
            // ─────────────────────────────────────────────────────────────────────────
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenString = tokenHandler.WriteToken(token);

            // ─────────────────────────────────────────────────────────────────────────
            // Step 7: Return the token and expiration.
            //   → Token: the JWT string.
            //   → ExpiresIn: the token's lifetime in seconds (for the client to
            //     know when to refresh).
            // ─────────────────────────────────────────────────────────────────────────
            return (tokenString, expirationMinutes * 60);
        }
    }
}
```

### File: Controllers/AccountsController.cs — Login Endpoint (Add to Existing Controller)

Add this to the existing `AccountsController`:

```csharp
// ═══════════════════════════════════════════════════════════════════════════
// POST /api/accounts/login — Login and receive a JWT token
// ═══════════════════════════════════════════════════════════════════════════
// Request body: { "userName": "...", "password": "..." }
// Response: 200 OK with LoginResponse (on success)
//           401 Unauthorized with error message (on failure)
// ─────────────────────────────────────────────────────────────────────────────
[HttpPost("login")]
public async Task<IActionResult> Login([FromBody] LoginRequest request)
{
    // ─────────────────────────────────────────────────────────────────────────
    // Step 1: Find the user by UserName.
    //   → UserManager.FindByNameAsync looks up the user in the database.
    //   → Returns Task<ApplicationUser?> (nullable — user may not exist).
    //   → If the user doesn't exist, we return an error.
    //   → IMPORTANT: For security, we don't reveal whether the user exists.
    //     We return the same error for "user not found" and "wrong password".
    //     This prevents user enumeration attacks.
    // ─────────────────────────────────────────────────────────────────────────
    var user = await _userManager.FindByNameAsync(request.UserName);

    // ─────────────────────────────────────────────────────────────────────────
    // Step 2: If user not found, return error.
    //   → We return "Invalid credentials." — the same message we'd return for
    //     a wrong password. This prevents attackers from enumerating valid users.
    //   → In a production API, you might want to return the same generic message
    //     for all authentication failures.
    // ─────────────────────────────────────────────────────────────────────────
    if (user == null)
    {
        return Unauthorized(new ApiResponse<object>
        {
            Success = false,
            Data = null,
            Message = "Invalid credentials.",
            Errors = new Dictionary<string, string[]>
            {
                { "UserName", new[] { "Invalid credentials." } }
            }
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Step 3: Check the password using SignInManager.CheckPasswordSignInAsync.
    //   → This is the key Identity call for login in an API.
    //   → Parameters:
    //     → user: the user to check (from step 1).
    //     → password: the plaintext password from the request.
    //     → lockoutOnFailure: true — enables account lockout on failed attempts.
    //       If the password is wrong, AccessFailedCount is incremented.
    //       If AccessFailedCount reaches MaxFailedAccessAttempts (5), the account
    //       is locked out for DefaultLockoutTimeSpan (5 minutes).
    //   → Returns Task<SignInResult>:
    //     → Succeeded: password is correct, account is not locked out, account
    //       is allowed to sign in.
    //     → IsLockedOut: account is locked out (too many failed attempts).
    //     → IsNotAllowed: account is not allowed to sign in (e.g., email not
    //       confirmed, if we enforce that).
    //     → Failed: password is wrong (and lockout may have been triggered).
    //   → IMPORTANT: This does NOT create a cookie or sign the user in.
    //     It only verifies the password and returns the result.
    //     We then manually generate a JWT token if the result is Succeeded.
    // ─────────────────────────────────────────────────────────────────────────
    var result = await _signInManager.CheckPasswordSignInAsync(
        user, request.Password, lockoutOnFailure: true);

    // ─────────────────────────────────────────────────────────────────────────
    // Step 4: Handle the result.
    //   → If Succeeded: generate JWT token and return it.
    //   → If IsLockedOut: return 401 with lockout message.
    //   → If IsNotAllowed: return 401 with not-allowed message.
    //   → If Failed: return 401 with "Invalid credentials."
    // ─────────────────────────────────────────────────────────────────────────
    if (result.Succeeded)
    {
        // ─────────────────────────────────────────────────────────────────────────
        // Step 5: Generate the JWT token.
        //   → JwtService.GenerateJwtToken creates a JWT with the user's claims.
        //   → Returns (token string, expires in seconds).
        //   → The token includes:
        //     → User ID (sub claim)
        //     → UserName (name claim)
        //     → Email (email claim)
        //     → FullName (custom claim)
        //     → Roles (role claims — one per user role)
        // ─────────────────────────────────────────────────────────────────────────
        var (token, expiresIn) = await _jwtService.GenerateJwtToken(user, _userManager);

        // ─────────────────────────────────────────────────────────────────────────
        // Step 6: Create the login response.
        //   → LoginResponse contains: Token, ExpiresIn, TokenType, User.
        //   → The User field is a UserResponse (the user's profile).
        // ─────────────────────────────────────────────────────────────────────────
        var response = new LoginResponse
        {
            Token = token,
            ExpiresIn = expiresIn,
            TokenType = "Bearer",
            User = new UserResponse
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                FullName = user.FullName,
                EmailConfirmed = user.EmailConfirmed,
                CreatedAt = DateTime.UtcNow
            }
        };

        // ─────────────────────────────────────────────────────────────────────────
        // Step 7: Return 200 OK with the login response.
        //   → The client stores the token and uses it for subsequent requests.
        //   → The client includes the token in the Authorization header:
        //     Authorization: Bearer <token>
        // ─────────────────────────────────────────────────────────────────────────
        return Ok(new ApiResponse<LoginResponse>
        {
            Success = true,
            Data = response,
            Message = "Login successful."
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Handle IsLockedOut.
    //   → The account is locked out due to too many failed attempts.
    //   → We return 401 with a message indicating the lockout.
    //   → For security, you might not want to reveal that the account is locked out
    //     (attackers could use this to identify valid accounts). For the tutorial,
    //     we show the distinction for educational purposes.
    // ─────────────────────────────────────────────────────────────────────────
    if (result.IsLockedOut)
    {
        return Unauthorized(new ApiResponse<object>
        {
            Success = false,
            Data = null,
            Message = "Account is locked out due to too many failed login attempts. Please try again later.",
            Errors = new Dictionary<string, string[]>
            {
                { "UserName", new[] { "Account is locked out." } }
            }
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Handle IsNotAllowed.
    //   → The account exists but is not allowed to sign in (e.g., email not
    //     confirmed, if we enforce that).
    // ─────────────────────────────────────────────────────────────────────────
    if (result.IsNotAllowed)
    {
        return Unauthorized(new ApiResponse<object>
        {
            Success = false,
            Data = null,
            Message = "Login not allowed. Please confirm your email or contact support.",
            Errors = new Dictionary<string, string[]>
            {
                { "UserName", new[] { "Login not allowed." } }
            }
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Handle Failed (password is wrong).
    //   → Return "Invalid credentials." — the same message as "user not found".
    //   → This prevents user enumeration.
    // ─────────────────────────────────────────────────────────────────────────
    return Unauthorized(new ApiResponse<object>
    {
        Success = false,
        Data = null,
        Message = "Invalid credentials.",
        Errors = new Dictionary<string, string[]>
        {
            { "Password", new[] { "Invalid credentials." } }
        }
    });
}
```

**Note:** The `_signInManager` field must be added to the controller's constructor:

```csharp
private readonly SignInManager<ApplicationUser> _signInManager;

public AccountsController(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    JwtService jwtService)
{
    _userManager = userManager;
    _signInManager = signInManager;
    _jwtService = jwtService;
}
```

---

## Postman / Swagger Tests

### Test 1: Successful Login

**Request:**
```
POST https://localhost:7001/api/accounts/login
Content-Type: application/json

{
  "userName": "ahmad",
  "password": "Test@1234"
}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw...",
    "expiresIn": 3600,
    "tokenType": "Bearer",
    "user": {
      "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "userName": "ahmad",
      "email": "ahmad@example.com",
      "fullName": "Ahmad Developer",
      "emailConfirmed": false,
      "createdAt": "2024-01-01T12:00:00Z"
    }
  },
  "message": "Login successful."
}
```

**Verification:**
- `success: true`.
- `data.token` is a long JWT string (starts with "eyJ").
- `data.expiresIn` is 3600 (1 hour).
- `data.tokenType` is "Bearer".
- `data.user` contains the user's profile.
- Save the token to use in subsequent tests.

### Test 2: Decode the JWT Token

1. Copy the token from the response.
2. Go to https://jwt.io (or use a similar JWT debugger).
3. Paste the token in the "Encoded" field.
4. Verify the payload contains:
   - `sub`: the user's ID.
   - `name`: the user's UserName.
   - `email`: the user's email.
   - `fullName`: the user's full name.
   - `role`: the user's role(s) (if any — the user may not have roles yet).
   - `exp`: the expiration timestamp.
   - `iat`: the issued-at timestamp.
   - `iss`: the issuer.
   - `aud`: the audience.

### Test 3: Login with Wrong Password

**Request:**
```
POST https://localhost:7001/api/accounts/login
Content-Type: application/json

{
  "userName": "ahmad",
  "password": "WrongPassword123!"
}
```

**Expected Response (401 Unauthorized):**
```json
{
  "success": false,
  "data": null,
  "message": "Invalid credentials.",
  "errors": {
    "Password": ["Invalid credentials."]
  }
}
```

**Verification:**
- `success: false`.
- The message is "Invalid credentials." — the same as for "user not found".
- This prevents user enumeration.

### Test 4: Login with Non-Existent User

**Request:**
```
POST https://localhost:7001/api/accounts/login
Content-Type: application/json

{
  "userName": "nonexistent",
  "password": "Test@1234"
}
```

**Expected Response (401 Unauthorized):**
```json
{
  "success": false,
  "data": null,
  "message": "Invalid credentials.",
  "errors": {
    "UserName": ["Invalid credentials."]
  }
}
```

**Verification:**
- The response is the same as for a wrong password (but the error is under "UserName" instead of "Password" — for educational purposes; in production, use the same key for both).
- This prevents user enumeration.

### Test 5: Login with Valid Token — Access Protected Endpoint

1. Get a token from Test 1.
2. Create a new request:
   ```
   GET https://localhost:7001/api/accounts/me
   Authorization: Bearer <token>
   ```
3. Expected Response (200 OK):
   ```json
   {
     "success": true,
     "data": {
       "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
       "userName": "ahmad",
       "email": "ahmad@example.com",
       "fullName": "Ahmad Developer",
       "emailConfirmed": false,
       "createdAt": "2024-01-01T12:00:00Z"
     },
     "message": null
   }
   ```
4. Verification: The JWT token is validated by the JwtBearer middleware, and the /me endpoint returns the user's profile.

### Test 6: Access Protected Endpoint Without Token

**Request:**
```
GET https://localhost:7001/api/accounts/me
```

**Expected Response (401 Unauthorized):**
```json
{
  "type": "https://tools.ietf.org/html/rfc9110#section-15.5.5",
  "title": "Unauthorized",
  "status": 401,
  "traceId": "00-abc123..."
}
```

**Verification:**
- Without a valid JWT token, the [Authorize] attribute returns 401.

### Test 7: Access Protected Endpoint with Invalid Token

**Request:**
```
GET https://localhost:7001/api/accounts/me
Authorization: Bearer invalid.token.here
```

**Expected Response (401 Unauthorized):**
```json
{
  "type": "https://tools.ietf.org/html/rfc9110#section-15.5.5",
  "title": "Unauthorized",
  "status": 401,
  "traceId": "00-abc123..."
}
```

**Verification:**
- The JwtBearer middleware validates the token signature and rejects invalid tokens.

### Test 8: Account Lockout (Test After Multiple Failed Attempts)

1. Attempt to login with the wrong password 5 times:
   ```
   POST /api/accounts/login { "userName": "ahmad", "password": "wrong1" }
   POST /api/accounts/login { "userName": "ahmad", "password": "wrong2" }
   ...
   ```
2. After 5 failed attempts, the account should be locked out.
3. Attempt to login with the correct password:
   ```
   POST /api/accounts/login { "userName": "ahmad", "password": "Test@1234" }
   ```
4. Expected Response (401 Unauthorized):
   ```json
   {
     "success": false,
     "data": null,
     "message": "Account is locked out due to too many failed login attempts. Please try again later.",
     "errors": {
       "UserName": ["Account is locked out."]
     }
   }
   ```
5. Wait 5 minutes (the configured lockout duration) and try again — should succeed.

### Swagger Tests

1. Run the API and navigate to `https://localhost:7001/swagger`.
2. Find `POST /api/accounts/login`.
3. Click "Try it out".
4. Enter:
   ```json
   {
     "userName": "ahmad",
     "password": "Test@1234"
   }
   ```
5. Click "Execute".
6. Expected: `200 OK` with the JWT token.
7. Copy the token.
8. Click the "Authorize" button at the top of Swagger UI.
9. Paste the token (with "Bearer " prefix).
10. Click "Authorize" → "Close".
11. Find `GET /api/accounts/me`.
12. Click "Try it out" → "Execute".
13. Expected: `200 OK` with the user profile.

---

# Video 09 — Role Management API — CRUD Roles, Assign / Remove Users

## Theory & Definitions

### What Role Management Does

Role management is the set of endpoints that:
1. **Create roles** — add new roles to the system (e.g., "Admin", "Moderator", "User").
2. **Read roles** — list all roles, get a role by ID or name.
3. **Update roles** — change a role's name or description.
4. **Delete roles** — remove roles (and automatically remove the role from all users).
5. **Assign roles to users** — give a user one or more roles.
6. **Remove roles from users** — revoke a user's role.
7. **Get a user's roles** — list the roles assigned to a user.

### What Roles Are and Why They Matter

Roles are named groups that represent a set of permissions. Instead of checking individual permissions for each user, you check if the user belongs to a role.

**Example:**
- "Admin" role → can manage users, manage roles, access admin endpoints.
- "Moderator" role → can edit/delete posts, ban users.
- "User" role → can access their own data, edit their own profile.

Roles simplify authorization:
- `[Authorize(Roles="Admin")]` — only users with the "Admin" role can access.
- `[Authorize(Roles="Admin, Moderator")]` — users with either role can access.
- `[Authorize(Roles="Admin")]` and `[Authorize(Roles="Moderator")]` on different endpoints — different access levels.

### Role-Based Access Control (RBAC) — The Concept

RBAC is a security model where access is granted based on roles. The three main entities are:
1. **Users** — the people or entities that need access.
2. **Roles** — named groups that represent a set of permissions.
3. **Permissions** — the specific actions that can be performed (e.g., "create user", "delete post", "view report").

In RBAC:
- Users are assigned to roles.
- Roles are assigned permissions.
- Users inherit permissions from their roles.

In our API, we implement RBAC at the role level — roles are assigned to users, and endpoints check roles with `[Authorize(Roles="...")]`. Permissions within a role are implicit (the role defines what you can do).

### The Role Management Endpoints

| Method | Endpoint | Purpose | Required Role |
|--------|----------|---------|---------------|
| `POST` | `/api/roles` | Create a new role | Admin |
| `GET` | `/api/roles` | List all roles | Admin (or any authenticated user — depends on your design) |
| `GET` | `/api/roles/{id}` | Get a role by ID | Admin |
| `GET` | `/api/roles/name/{name}` | Get a role by name | Admin |
| `PUT` | `/api/roles/{id}` | Update a role | Admin |
| `DELETE` | `/api/roles/{id}` | Delete a role | Admin |
| `POST` | `/api/users/{userId}/roles` | Assign role(s) to a user | Admin |
| `DELETE` | `/api/users/{userId}/roles/{roleName}` | Remove a role from a user | Admin |
| `GET` | `/api/users/{userId}/roles` | Get a user's roles | Admin (or the user themselves) |

### The Role DTOs

**CreateRoleRequest:**
```json
{
  "name": "Admin",
  "description": "Full access to all administrative functions"
}
```

**RoleResponse:**
```json
{
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "name": "Admin",
  "normalizedName": "ADMIN",
  "description": "Full access to all administrative functions",
  "createdDate": "2024-01-01T12:00:00Z",
  "userCount": 5
}
```

### The Role CRUD Flow

**Create Role:**
```
POST /api/roles { name: "Admin", description: "..." }
    ↓
RolesController.CreateRole()
    ↓
Check if role already exists (RoleManager.RoleExistsAsync(name))
    ↓
If exists → return 400 Bad Request ("Role already exists.")
If not → create ApplicationRole { Name = name, Description = description }
    ↓
RoleManager.CreateAsync(role)
    ↓
If success → return 201 Created with RoleResponse
If failed → return 400 Bad Request with errors
```

**Assign Role to User:**
```
POST /api/users/{userId}/roles { roleName: "Admin" }
    ↓
UsersController.AssignRole()
    ↓
Check if user exists (UserManager.FindByIdAsync(userId))
    ↓
Check if role exists (RoleManager.RoleExistsAsync(roleName))
    ↓
UserManager.AddToRoleAsync(user, roleName)
    ↓
If success → return 200 OK
If failed → return 400 Bad Request with errors
```

### The RoleManager — Key Methods

| Method | Purpose |
|--------|---------|
| `CreateAsync(role)` | Creates a new role |
| `UpdateAsync(role)` | Updates a role's properties |
| `DeleteAsync(role)` | Deletes a role |
| `FindByIdAsync(id)` | Finds a role by ID |
| `FindByNameAsync(name)` | Finds a role by name |
| `RoleExistsAsync(roleName)` | Checks if a role with that name exists |
| `AddClaimAsync(role, claim)` | Adds a claim to the role |
| `RemoveClaimAsync(role, claim)` | Removes a claim from the role |
| `GetClaimsAsync(role)` | Gets the role's claims |

### The UserManager — Role-Related Methods

| Method | Purpose |
|--------|---------|
| `AddToRoleAsync(user, roleName)` | Adds a user to a role |
| `AddToRolesAsync(user, roleNames)` | Adds a user to multiple roles |
| `RemoveFromRoleAsync(user, roleName)` | Removes a user from a role |
| `RemoveFromRolesAsync(user, roleNames)` | Removes a user from multiple roles |
| `GetRolesAsync(user)` | Gets the user's roles |
| `IsInRoleAsync(user, roleName)` | Checks if the user is in a role |
| `GetRoleNamesAsync(user)` | Gets the user's role names (same as GetRolesAsync) |

### The User-Role Relationship — How It's Stored

When you call `UserManager.AddToRoleAsync(user, "Admin")`:

1. Identity creates a new row in the `AspNetUserRoles` table:
   - `UserId` = the user's ID.
   - `RoleId` = the role's ID (found by looking up the role by name).
2. The relationship is many-to-many: a user can have multiple roles, and a role can have multiple users.
3. When you call `UserManager.RemoveFromRoleAsync(user, "Admin")`, the row is deleted from `AspNetUserRoles`.

### Why We Check Role Existence Before Assigning

When assigning a role to a user, we check:
1. **User exists** — `UserManager.FindByIdAsync(userId)` returns a user.
2. **Role exists** — `RoleManager.RoleExistsAsync(roleName)` returns true.

If either check fails, we return an error. This prevents:
- Assigning a non-existent role to a user (would fail anyway, but we give a clear error).
- Adding a role to a non-existent user (would fail anyway, but we give a clear error).

### The NormalizedName — What It Is

`IdentityRole` has a `NormalizedName` property that stores the uppercase version of the role name. This is used for case-insensitive lookups:

```
Role name: "Admin"
NormalizedName: "ADMIN"
```

When you call `RoleManager.FindByNameAsync("admin")`, Identity normalizes the input to "ADMIN" and looks up by NormalizedName. This makes role lookups case-insensitive.

**For the API**, we accept any case for the role name in requests, but we store it in its original case (with NormalizedName for lookups).

### The Role Response — What We Include

The `RoleResponse` includes:
- `Id` — the role's unique identifier.
- `Name` — the role's name (original case).
- `NormalizedName` — the uppercase version (for diagnostic purposes).
- `Description` — the role's description (nullable).
- `CreatedDate` — when the role was created.
- `UserCount` — the number of users with this role (optional — useful for admin UIs).

---

## 🎬 Video Recording Notes

**Opening (say this):**

> "Now we build the role management API — create roles, list roles, update roles, delete roles, and assign roles to users. Roles are the foundation of authorization in Identity — they determine what users can do. We'll create a complete CRUD API for roles, plus endpoints to assign and remove roles from users."

**Show on screen:**

> The `CreateRoleRequest` and `RoleResponse` DTOs. The `RolesController` with all CRUD endpoints. The `UsersController` with assign/remove role endpoints. The Postman requests and responses for each operation. The database viewer showing the AspNetRoles and AspNetUserRoles tables.

**Key points to emphasize (say this):**

> "Roles are simple — they're just named groups. What makes them powerful is how you use them in authorization: [Authorize(Roles='Admin')] gates access to endpoints."

> "RoleManager handles role CRUD. UserManager handles role assignment (AddToRoleAsync, RemoveFromRoleAsync). Don't mix them up."

> "When you delete a role, Identity automatically removes the role from all users (via the AspNetUserRoles junction table). You don't need to do this manually."

> "Always check if a role exists before assigning it to a user. And check if the user exists before assigning a role to them. This gives clear error messages instead of letting Identity throw exceptions."

> "Roles are case-insensitive for lookups (NormalizedName handles this), but we store the original case for display."

**Analogy (say this):**

> "Roles are like job titles in a company. 'Admin' is like 'CEO' — full access. 'Moderator' is like 'Team Lead' — can manage the team but not the whole company. 'User' is like 'Employee' — can do their own work but not manage others. Assigning a role to a user is like giving someone a job title. Removing a role is like changing their title. And deleting a role is like eliminating a position — everyone with that title loses it."

**Common viewer questions:**

> "Do I need to create roles before users can log in?" — Not necessarily. A user can log in without any roles. But if you have [Authorize(Roles='Admin')] endpoints, users without the 'Admin' role can't access them. You should create the default roles (like 'User') before launching the application.

> "Can a user have multiple roles?" — Yes. A user can have 'Admin' and 'Moderator' at the same time. [Authorize(Roles='Admin, Moderator')] checks if the user has EITHER role. [Authorize(Roles='Admin')] and [Authorize(Roles='Moderator')] on different endpoints checks for the specific role.

> "What happens if I delete a role that's assigned to users?" — Identity automatically removes the role from all users (deletes the rows from AspNetUserRoles). The users still exist, they just lose that role.

> "Can I rename a role?" — Yes, by updating the role's Name property and calling RoleManager.UpdateAsync. But this is rarely needed — roles are usually created once and not renamed. If you need to rename, be aware that role lookups are case-insensitive (NormalizedName), so the new name will be normalized automatically.

**What to show:**

- CreateRoleRequest and RoleResponse DTOs
- RolesController with all CRUD endpoints
- UsersController with assign/remove endpoints
- Postman tests for each operation
- Database viewer showing AspNetRoles and AspNetUserRoles
- Swagger UI with the role endpoints

**What to skip:**

- Role claims (claims attached to roles — covered in Video 12 / policies)
- Dynamic role creation by end users (covered in Video 19 / production)
- Role hierarchy (Admin > Moderator > User — advanced, not covered in this tutorial)

---

## Complete Implementation

### File: DTOs/CreateRoleRequest.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: DTOs/CreateRoleRequest.cs
// Video 09 — Role Management: Create Role Request DTO
// ─────────────────────────────────────────────────────────────────────────────
// This DTO defines what the client sends to create a role.
// ─────────────────────────────────────────────────────────────────────────────

using System.ComponentModel.DataAnnotations;

namespace IdentityApiTutorial.DTOs
{
    // ─────────────────────────────────────────────────────────────────────────────
    // CreateRoleRequest — the request body for POST /api/roles.
    // ─────────────────────────────────────────────────────────────────────────────
    // Properties:
    //   → Name: the role's name (required, unique, with length constraints).
    //   → Description: optional description of what the role allows.
    //
    // The role name is the most important field — it's used in
    // [Authorize(Roles="Admin")] checks, so it must be unique and consistent.
    // ─────────────────────────────────────────────────────────────────────────────
    public class CreateRoleRequest
    {
        // ─────────────────────────────────────────────────────────────────────────
        // Name — the role's name.
        //   → [Required]: must be provided.
        //   → [StringLength(50, MinimumLength = 2)]: between 2 and 50 characters.
        //   → [RegularExpression]: allows letters, numbers, and spaces. No special
        //     characters that might cause issues in authorization checks.
        //   → Why these constraints? The role name is used in [Authorize(Roles="...")]
        //     attributes, so it should be simple and consistent.
        //   → Common role names: "Admin", "Moderator", "User", "Manager", "Editor".
        // ─────────────────────────────────────────────────────────────────────────
        [Required(ErrorMessage = "Role name is required.")]
        [StringLength(50, MinimumLength = 2,
            ErrorMessage = "Role name must be between 2 and 50 characters.")]
        [RegularExpression(@"^[a-zA-Z0-9\s]+$",
            ErrorMessage = "Role name can only contain letters, numbers, and spaces.")]
        public string Name { get; set; } = string.Empty;

        // ─────────────────────────────────────────────────────────────────────────
        // Description — optional description of the role.
        //   → No [Required] — it's optional.
        //   → [StringLength(256)]: max 256 characters.
        //   → Stored in ApplicationRole.Description (nullable column in AspNetRoles).
        // ─────────────────────────────────────────────────────────────────────────
        [StringLength(256, ErrorMessage = "Description cannot exceed 256 characters.")]
        public string? Description { get; set; }
    }
}
```

### File: DTOs/RoleResponse.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: DTOs/RoleResponse.cs
// Video 09 — Role Management: Role Response DTO
// ─────────────────────────────────────────────────────────────────────────────
// This DTO defines what the API returns for role-related endpoints.
// ─────────────────────────────────────────────────────────────────────────────

namespace IdentityApiTutorial.DTOs
{
    // ─────────────────────────────────────────────────────────────────────────────
    // RoleResponse — the response body for role-related endpoints.
    // ─────────────────────────────────────────────────────────────────────────────
    // Properties:
    //   → Id: the role's unique identifier.
    //   → Name: the role's name (original case).
    //   → NormalizedName: the uppercase version (for diagnostic purposes).
    //   → Description: the role's description (nullable).
    //   → CreatedDate: when the role was created.
    //   → UserCount: the number of users with this role (optional — useful for
    //     admin UIs that show role statistics).
    // ─────────────────────────────────────────────────────────────────────────────
    public class RoleResponse
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string NormalizedName { get; set; } = string.Empty;
        public string? Description { get; set; }
        public DateTime CreatedDate { get; set; }
        public int UserCount { get; set; }
    }
}
```

### File: DTOs/AssignRoleRequest.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: DTOs/AssignRoleRequest.cs
// Video 09 — Role Management: Assign Role Request DTO
// ─────────────────────────────────────────────────────────────────────────────
// This DTO defines what the client sends to assign a role to a user.
// ─────────────────────────────────────────────────────────────────────────────

using System.ComponentModel.DataAnnotations;

namespace IdentityApiTutorial.DTOs
{
    // ─────────────────────────────────────────────────────────────────────────────
    // AssignRoleRequest — the request body for POST /api/users/{userId}/roles.
    // ─────────────────────────────────────────────────────────────────────────────
    // Properties:
    //   → RoleName: the name of the role to assign (required).
    //
    // The role name must match an existing role (case-insensitive).
    // ─────────────────────────────────────────────────────────────────────────────
    public class AssignRoleRequest
    {
        // ─────────────────────────────────────────────────────────────────────────
        // RoleName — the name of the role to assign.
        //   → [Required]: must be provided.
        //   → [StringLength(50)]: max 50 characters (matches role name constraints).
        //   → The controller checks if the role exists before assigning.
        // ─────────────────────────────────────────────────────────────────────────
        [Required(ErrorMessage = "Role name is required.")]
        [StringLength(50, ErrorMessage = "Role name cannot exceed 50 characters.")]
        public string RoleName { get; set; } = string.Empty;
    }
}
```

### File: Controllers/RolesController.cs — Role CRUD

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Controllers/RolesController.cs
// Video 09 — Role Management: Roles Controller (CRUD)
// ─────────────────────────────────────────────────────────────────────────────
// This controller handles role management:
//   → Create role (POST /api/roles)
//   → List all roles (GET /api/roles)
//   → Get role by ID (GET /api/roles/{id})
//   → Get role by name (GET /api/roles/name/{name})
//   → Update role (PUT /api/roles/{id})
//   → Delete role (DELETE /api/roles/{id})
//
// All endpoints require the "Admin" role ([Authorize(Roles="Admin")]).
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.DTOs;
using IdentityApiTutorial.Models;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Controllers
{
    // ─────────────────────────────────────────────────────────────────────────────
    // [ApiController] + [Route("api/[controller]")] — same as AccountsController.
    // ─────────────────────────────────────────────────────────────────────────────
    [ApiController]
    [Route("api/[controller]")]
    public class RolesController : ControllerBase
    {
        // ─────────────────────────────────────────────────────────────────────────
        // _roleManager — handles all role operations.
        //   → Injected by DI (registered by AddIdentityCore with AddRoles in
        //     Program.cs).
        // ─────────────────────────────────────────────────────────────────────────
        private readonly RoleManager<ApplicationRole> _roleManager;

        public RolesController(RoleManager<ApplicationRole> roleManager)
        {
            _roleManager = roleManager;
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // POST /api/roles — Create a new role
        // ═══════════════════════════════════════════════════════════════════════════
        // Request body: { "name": "Admin", "description": "..." }
        // Response: 201 Created with RoleResponse (on success)
        //           400 Bad Request if role already exists or validation fails
        // ─────────────────────────────────────────────────────────────────────────────
        [Authorize(Roles = "Admin")]  // Only admins can create roles
        [HttpPost]
        public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequest request)
        {
            // ─────────────────────────────────────────────────────────────────────────
            // Step 1: Check if the role already exists.
            //   → RoleManager.RoleExistsAsync checks if a role with this name exists.
            //   → Role names are case-insensitive (NormalizedName handles this).
            //   → If the role exists, return 400 Bad Request.
            // ─────────────────────────────────────────────────────────────────────────
            if (await _roleManager.RoleExistsAsync(request.Name))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Data = null,
                    Message = $"Role '{request.Name}' already exists.",
                    Errors = new Dictionary<string, string[]>
                    {
                        { "Name", new[] { $"Role '{request.Name}' already exists." } }
                    }
                });
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Step 2: Create the ApplicationRole.
            //   → Set Name, Description, and CreatedDate.
            //   → CreatedDate is set to DateTime.UtcNow (or you could let EF Core
            //     set it with a default value in the model).
            // ─────────────────────────────────────────────────────────────────────────
            var role = new ApplicationRole
            {
                Name = request.Name,
                Description = request.Description,
                CreatedDate = DateTime.UtcNow
            };

            // ─────────────────────────────────────────────────────────────────────────
            // Step 3: Create the role using RoleManager.CreateAsync.
            //   → This saves the role to the AspNetRoles table.
            //   → Returns IdentityResult (Success or Failed with errors).
            // ─────────────────────────────────────────────────────────────────────────
            var result = await _roleManager.CreateAsync(role);

            // ─────────────────────────────────────────────────────────────────────────
            // Step 4: Check the result and return the response.
            //   → If Success: return 201 Created with the role data.
            //   → If Failed: return 400 Bad Request with the errors.
            // ─────────────────────────────────────────────────────────────────────────
            if (result.Succeeded)
            {
                return Ok(new ApiResponse<RoleResponse>
                {
                    Success = true,
                    Data = new RoleResponse
                    {
                        Id = role.Id,
                        Name = role.Name,
                        NormalizedName = role.NormalizedName,
                        Description = role.Description,
                        CreatedDate = role.CreatedDate,
                        UserCount = 0  // New role has no users yet
                    },
                    Message = $"Role '{request.Name}' created successfully."
                });
            }

            // Return errors
            var errors = new Dictionary<string, string[]>();
            foreach (var error in result.Errors)
            {
                errors["Name"] = errors["Name"] ?? new string[] { };
                errors["Name"] = errors["Name"].Append(error.Description).ToArray();
            }

            return BadRequest(new ApiResponse<object>
            {
                Success = false,
                Data = null,
                Message = "Failed to create role.",
                Errors = errors
            });
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // GET /api/roles — List all roles
        // ═══════════════════════════════════════════════════════════════════════════
        // Response: 200 OK with list of RoleResponse
        // ─────────────────────────────────────────────────────────────────────────────
        [Authorize(Roles = "Admin")]
        [HttpGet]
        public async Task<IActionResult> GetAllRoles()
        {
            // ─────────────────────────────────────────────────────────────────────────
            // Get all roles from the database.
            //   → RoleManager.Roles returns an IQueryable<ApplicationRole>.
            //   → We materialize it with ToListAsync (async).
            //   → For each role, we also get the user count (optional but useful).
            // ─────────────────────────────────────────────────────────────────────────
            var roles = await _roleManager.Roles.ToListAsync();
            var response = new List<RoleResponse>();

            foreach (var role in roles)
            {
                // Get the number of users with this role.
                // This is an optional field — you can omit it if you don't need it.
                var userCount = await _roleManager
                    .GetUsersInRoleAsync(role.Name)
                    .ContinueWith(t => t.Result.Count);

                response.Add(new RoleResponse
                {
                    Id = role.Id,
                    Name = role.Name,
                    NormalizedName = role.NormalizedName,
                    Description = role.Description,
                    CreatedDate = role.CreatedDate,
                    UserCount = userCount
                });
            }

            return Ok(new ApiResponse<List<RoleResponse>>
            {
                Success = true,
                Data = response,
                Message = null
            });
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // GET /api/roles/{id} — Get a role by ID
        // ═══════════════════════════════════════════════════════════════════════════
        // Response: 200 OK with RoleResponse (if found)
        //           404 Not Found (if not found)
        // ─────────────────────────────────────────────────────────────────────────────
        [Authorize(Roles = "Admin")]
        [HttpGet("{id}")]
        public async Task<IActionResult> GetRoleById(string id)
        {
            // ─────────────────────────────────────────────────────────────────────────
            // Find the role by ID.
            //   → RoleManager.FindByIdAsync returns the role or null.
            // ─────────────────────────────────────────────────────────────────────────
            var role = await _roleManager.FindByIdAsync(id);

            if (role == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Data = null,
                    Message = $"Role with ID '{id}' not found."
                });
            }

            var userCount = await _roleManager.GetUsersInRoleAsync(role.Name).ContinueWith(t => t.Result.Count);

            return Ok(new ApiResponse<RoleResponse>
            {
                Success = true,
                Data = new RoleResponse
                {
                    Id = role.Id,
                    Name = role.Name,
                    NormalizedName = role.NormalizedName,
                    Description = role.Description,
                    CreatedDate = role.CreatedDate,
                    UserCount = userCount
                },
                Message = null
            });
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // GET /api/roles/name/{name} — Get a role by name
        // ═══════════════════════════════════════════════════════════════════════════
        // Response: 200 OK with RoleResponse (if found)
        //           404 Not Found (if not found)
        // ─────────────────────────────────────────────────────────────────────────────
        [Authorize(Roles = "Admin")]
        [HttpGet("name/{name}")]
        public async Task<IActionResult> GetRoleByName(string name)
        {
            var role = await _roleManager.FindByNameAsync(name);

            if (role == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Data = null,
                    Message = $"Role '{name}' not found."
                });
            }

            var userCount = await _roleManager.GetUsersInRoleAsync(role.Name).ContinueWith(t => t.Result.Count);

            return Ok(new ApiResponse<RoleResponse>
            {
                Success = true,
                Data = new RoleResponse
                {
                    Id = role.Id,
                    Name = role.Name,
                    NormalizedName = role.NormalizedName,
                    Description = role.Description,
                    CreatedDate = role.CreatedDate,
                    UserCount = userCount
                },
                Message = null
            });
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // PUT /api/roles/{id} — Update a role
        // ═══════════════════════════════════════════════════════════════════════════
        // Request body: { "name": "...", "description": "..." } (partial update)
        // Response: 200 OK with updated RoleResponse
        //           404 Not Found if role doesn't exist
        //           400 Bad Request if validation fails
        // ─────────────────────────────────────────────────────────────────────────────
        [Authorize(Roles = "Admin")]
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateRole(string id, [FromBody] CreateRoleRequest request)
        {
            // ─────────────────────────────────────────────────────────────────────────
            // Step 1: Find the role by ID.
            // ─────────────────────────────────────────────────────────────────────────
            var role = await _roleManager.FindByIdAsync(id);

            if (role == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Data = null,
                    Message = $"Role with ID '{id}' not found."
                });
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Step 2: Update the role properties.
            //   → Only update the fields that were provided.
            //   → If the name is being changed, check if the new name already exists
            //     (to prevent duplicate role names).
            // ─────────────────────────────────────────────────────────────────────────
            if (!string.IsNullOrWhiteSpace(request.Name))
            {
                // Check if the new name already exists (and it's not the current role)
                if (await _roleManager.RoleExistsAsync(request.Name)
                    && !role.NormalizedName.Equals(request.Name.ToUpper(), StringComparison.OrdinalIgnoreCase))
                {
                    return BadRequest(new ApiResponse<object>
                    {
                        Success = false,
                        Data = null,
                        Message = $"Role '{request.Name}' already exists.",
                        Errors = new Dictionary<string, string[]>
                        {
                            { "Name", new[] { $"Role '{request.Name}' already exists." } }
                        }
                    });
                }

                role.Name = request.Name;
            }

            if (request.Description != null)
            {
                role.Description = request.Description;
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Step 3: Update the role using RoleManager.UpdateAsync.
            //   → This updates the role in the AspNetRoles table.
            // ─────────────────────────────────────────────────────────────────────────
            var result = await _roleManager.UpdateAsync(role);

            if (result.Succeeded)
            {
                return Ok(new ApiResponse<RoleResponse>
                {
                    Success = true,
                    Data = new RoleResponse
                    {
                        Id = role.Id,
                        Name = role.Name,
                        NormalizedName = role.NormalizedName,
                        Description = role.Description,
                        CreatedDate = role.CreatedDate,
                        UserCount = await _roleManager.GetUsersInRoleAsync(role.Name).ContinueWith(t => t.Result.Count)
                    },
                    Message = $"Role '{role.Name}' updated successfully."
                });
            }

            return BadRequest(new ApiResponse<object>
            {
                Success = false,
                Data = null,
                Message = "Failed to update role.",
                Errors = result.Errors.ToDictionary(e => "General", e => new[] { e.Description })
            });
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // DELETE /api/roles/{id} — Delete a role
        // ═══════════════════════════════════════════════════════════════════════════
        // Response: 200 OK with success message
        //           404 Not Found if role doesn't exist
        // ─────────────────────────────────────────────────────────────────────────────
        [Authorize(Roles = "Admin")]
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteRole(string id)
        {
            // ─────────────────────────────────────────────────────────────────────────
            // Step 1: Find the role by ID.
            // ─────────────────────────────────────────────────────────────────────────
            var role = await _roleManager.FindByIdAsync(id);

            if (role == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Data = null,
                    Message = $"Role with ID '{id}' not found."
                });
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Step 2: Delete the role using RoleManager.DeleteAsync.
            //   → This deletes the role from AspNetRoles.
            //   → Identity automatically removes the role from all users
            //     (deletes rows from AspNetUserRoles).
            // ─────────────────────────────────────────────────────────────────────────
            var result = await _roleManager.DeleteAsync(role);

            if (result.Succeeded)
            {
                return Ok(new ApiResponse<object>
                {
                    Success = true,
                    Data = null,
                    Message = $"Role '{role.Name}' deleted successfully."
                });
            }

            return BadRequest(new ApiResponse<object>
            {
                Success = false,
                Data = null,
                Message = "Failed to delete role.",
                Errors = result.Errors.ToDictionary(e => "General", e => new[] { e.Description })
            });
        }
    }
}
```

### File: Controllers/UsersController.cs — Assign / Remove Roles

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Controllers/UsersController.cs
// Video 09 — Role Management: Users Controller (Assign / Remove Roles)
// ─────────────────────────────────────────────────────────────────────────────
// This controller handles role assignment to users:
//   → Assign role(s) to a user (POST /api/users/{userId}/roles)
//   → Remove role from a user (DELETE /api/users/{userId}/roles/{roleName})
//   → Get a user's roles (GET /api/users/{userId}/roles)
//
// All endpoints require the "Admin" role ([Authorize(Roles="Admin")]).
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.DTOs;
using IdentityApiTutorial.Models;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Controllers
{
    // ─────────────────────────────────────────────────────────────────────────────
    // [ApiController] + [Route("api/[controller]")] — same pattern as other controllers.
    // ─────────────────────────────────────────────────────────────────────────────
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        // ─────────────────────────────────────────────────────────────────────────
        // _userManager — handles user operations including role assignment.
        // ─────────────────────────────────────────────────────────────────────────
        private readonly UserManager<ApplicationUser> _userManager;

        // ─────────────────────────────────────────────────────────────────────────
        // _roleManager — used to check if a role exists before assigning it.
        // ─────────────────────────────────────────────────────────────────────────
        private readonly RoleManager<ApplicationRole> _roleManager;

        public UsersController(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // POST /api/users/{userId}/roles — Assign a role to a user
        // ═══════════════════════════════════════════════════════════════════════════
        // Request body: { "roleName": "Admin" }
        // Response: 200 OK (on success)
        //           400 Bad Request if user or role doesn't exist, or role already assigned
        //           404 Not Found if user doesn't exist
        // ─────────────────────────────────────────────────────────────────────────────
        [Authorize(Roles = "Admin")]
        [HttpPost("{userId}/roles")]
        public async Task<IActionResult> AssignRole(string userId, [FromBody] AssignRoleRequest request)
        {
            // ─────────────────────────────────────────────────────────────────────────
            // Step 1: Check if the user exists.
            //   → UserManager.FindByIdAsync returns the user or null.
            // ─────────────────────────────────────────────────────────────────────────
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Data = null,
                    Message = $"User with ID '{userId}' not found."
                });
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Step 2: Check if the role exists.
            //   → RoleManager.RoleExistsAsync checks if a role with this name exists.
            //   → Role names are case-insensitive.
            // ─────────────────────────────────────────────────────────────────────────
            if (!await _roleManager.RoleExistsAsync(request.RoleName))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Data = null,
                    Message = $"Role '{request.RoleName}' does not exist.",
                    Errors = new Dictionary<string, string[]>
                    {
                        { "RoleName", new[] { $"Role '{request.RoleName}' does not exist." } }
                    }
                });
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Step 3: Check if the user already has this role.
            //   → UserManager.IsInRoleAsync checks if the user is already in the role.
            //   → If yes, return 400 Bad Request (no need to assign again).
            //   → This is optional — AddToRoleAsync would succeed anyway (it's
            //     idempotent), but we give a clear error message.
            // ─────────────────────────────────────────────────────────────────────────
            if (await _userManager.IsInRoleAsync(user, request.RoleName))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Data = null,
                    Message = $"User '{user.UserName}' already has the '{request.RoleName}' role.",
                    Errors = new Dictionary<string, string[]>
                    {
                        { "RoleName", new[] { $"User already has the '{request.RoleName}' role." } }
                    }
                });
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Step 4: Assign the role to the user.
            //   → UserManager.AddToRoleAsync adds the user to the role.
            //   → This creates a row in AspNetUserRoles (UserId, RoleId).
            //   → Returns IdentityResult (Success or Failed with errors).
            // ─────────────────────────────────────────────────────────────────────────
            var result = await _userManager.AddToRoleAsync(user, request.RoleName);

            if (result.Succeeded)
            {
                return Ok(new ApiResponse<object>
                {
                    Success = true,
                    Data = null,
                    Message = $"Role '{request.RoleName}' assigned to user '{user.UserName}' successfully."
                });
            }

            return BadRequest(new ApiResponse<object>
            {
                Success = false,
                Data = null,
                Message = "Failed to assign role.",
                Errors = result.Errors.ToDictionary(e => "General", e => new[] { e.Description })
            });
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // DELETE /api/users/{userId}/roles/{roleName} — Remove a role from a user
        // ═══════════════════════════════════════════════════════════════════════════
        // Response: 200 OK (on success)
        //           400 Bad Request if role not assigned
        //           404 Not Found if user doesn't exist
        // ─────────────────────────────────────────────────────────────────────────────
        [Authorize(Roles = "Admin")]
        [HttpDelete("{userId}/roles/{roleName}")]
        public async Task<IActionResult> RemoveRole(string userId, string roleName)
        {
            // ─────────────────────────────────────────────────────────────────────────
            // Step 1: Check if the user exists.
            // ─────────────────────────────────────────────────────────────────────────
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Data = null,
                    Message = $"User with ID '{userId}' not found."
                });
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Step 2: Check if the user has this role.
            //   → If not, return 400 Bad Request (nothing to remove).
            // ─────────────────────────────────────────────────────────────────────────
            if (!await _userManager.IsInRoleAsync(user, roleName))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Data = null,
                    Message = $"User '{user.UserName}' does not have the '{roleName}' role.",
                    Errors = new Dictionary<string, string[]>
                    {
                        { "RoleName", new[] { $"User does not have the '{roleName}' role." } }
                    }
                });
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Step 3: Remove the role from the user.
            //   → UserManager.RemoveFromRoleAsync removes the user from the role.
            //   → This deletes the row from AspNetUserRoles (UserId, RoleId).
            // ─────────────────────────────────────────────────────────────────────────
            var result = await _userManager.RemoveFromRoleAsync(user, roleName);

            if (result.Succeeded)
            {
                return Ok(new ApiResponse<object>
                {
                    Success = true,
                    Data = null,
                    Message = $"Role '{roleName}' removed from user '{user.UserName}' successfully."
                });
            }

            return BadRequest(new ApiResponse<object>
            {
                Success = false,
                Data = null,
                Message = "Failed to remove role.",
                Errors = result.Errors.ToDictionary(e => "General", e => new[] { e.Description })
            });
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // GET /api/users/{userId}/roles — Get a user's roles
        // ═══════════════════════════════════════════════════════════════════════════
        // Response: 200 OK with list of role names
        //           404 Not Found if user doesn't exist
        // ─────────────────────────────────────────────────────────────────────────────
        [Authorize(Roles = "Admin")]
        [HttpGet("{userId}/roles")]
        public async Task<IActionResult> GetUserRoles(string userId)
        {
            // ─────────────────────────────────────────────────────────────────────────
            // Step 1: Check if the user exists.
            // ─────────────────────────────────────────────────────────────────────────
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Data = null,
                    Message = $"User with ID '{userId}' not found."
                });
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Step 2: Get the user's roles.
            //   → UserManager.GetRolesAsync returns a list of role names.
            // ─────────────────────────────────────────────────────────────────────────
            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new ApiResponse<List<string>>
            {
                Success = true,
                Data = roles.ToList(),
                Message = null
            });
        }
    }
}
```

---

## Postman / Swagger Tests

### Test 1: Create a Role

**Request:**
```
POST https://localhost:7001/api/roles
Content-Type: application/json
Authorization: Bearer <admin-token>

{
  "name": "Admin",
  "description": "Full access to all administrative functions"
}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "name": "Admin",
    "normalizedName": "ADMIN",
    "description": "Full access to all administrative functions",
    "createdDate": "2024-01-01T12:00:00Z",
    "userCount": 0
  },
  "message": "Role 'Admin' created successfully."
}
```

**Verification:**
- `success: true`.
- The role is created with the specified name and description.
- `normalizedName` is "ADMIN" (uppercase version).
- `userCount` is 0 (no users have this role yet).
- Save the `id` for later tests.

### Test 2: Create a Duplicate Role

**Request:**
```
POST https://localhost:7001/api/roles
Content-Type: application/json
Authorization: Bearer <admin-token>

{
  "name": "Admin",
  "description": "Duplicate test"
}
```

**Expected Response (400 Bad Request):**
```json
{
  "success": false,
  "data": null,
  "message": "Role 'Admin' already exists.",
  "errors": {
    "Name": ["Role 'Admin' already exists."]
  }
}
```

**Verification:**
- The role is not created (check the database — no new row in AspNetRoles).
- The error is clear and indicates the role already exists.

### Test 3: List All Roles

**Request:**
```
GET https://localhost:7001/api/roles
Authorization: Bearer <admin-token>
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "data": [
    {
      "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "name": "Admin",
      "normalizedName": "ADMIN",
      "description": "Full access to all administrative functions",
      "createdDate": "2024-01-01T12:00:00Z",
      "userCount": 0
    }
  ],
  "message": null
}
```

### Test 4: Get Role by ID

**Request:**
```
GET https://localhost:7001/api/roles/3fa85f64-5717-4562-b3fc-2c963f66afa6
Authorization: Bearer <admin-token>
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "name": "Admin",
    "normalizedName": "ADMIN",
    "description": "Full access to all administrative functions",
    "createdDate": "2024-01-01T12:00:00Z",
    "userCount": 0
  },
  "message": null
}
```

### Test 5: Get Role by Name

**Request:**
```
GET https://localhost:7001/api/roles/name/Admin
Authorization: Bearer <admin-token>
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "name": "Admin",
    "normalizedName": "ADMIN",
    "description": "Full access to all administrative functions",
    "createdDate": "2024-01-01T12:00:00Z",
    "userCount": 0
  },
  "message": null
}
```

**Verification:**
- The role is found by name (case-insensitive — "admin", "Admin", "ADMIN" all work).

### Test 6: Update a Role

**Request:**
```
PUT https://localhost:7001/api/roles/3fa85f64-5717-4562-b3fc-2c963f66afa6
Content-Type: application/json
Authorization: Bearer <admin-token>

{
  "name": "SuperAdmin",
  "description": "Elevated admin with full system access"
}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "name": "SuperAdmin",
    "normalizedName": "SUPERADMIN",
    "description": "Elevated admin with full system access",
    "createdDate": "2024-01-01T12:00:00Z",
    "userCount": 0
  },
  "message": "Role 'SuperAdmin' updated successfully."
}
```

### Test 7: Delete a Role

**Request:**
```
DELETE https://localhost:7001/api/roles/3fa85f64-5717-4562-b3fc-2c963f66afa6
Authorization: Bearer <admin-token>
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "data": null,
  "message": "Role 'SuperAdmin' deleted successfully."
}
```

**Verification:**
- The role is deleted from AspNetRoles.
- If the role was assigned to users, the rows in AspNetUserRoles are also deleted.

### Test 8: Assign Role to User

**Request:**
```
POST https://localhost:7001/api/users/3fa85f64-5717-4562-b3fc-2c963f66afa6/roles
Content-Type: application/json
Authorization: Bearer <admin-token>

{
  "roleName": "Admin"
}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "data": null,
  "message": "Role 'Admin' assigned to user 'ahmad' successfully."
}
```

**Verification:**
- A row is added to AspNetUserRoles (UserId = user's ID, RoleId = Admin's ID).
- The user now has the "Admin" role.

### Test 9: Assign Non-Existent Role

**Request:**
```
POST https://localhost:7001/api/users/3fa85f64-5717-4562-b3fc-2c963f66afa6/roles
Content-Type: application/json
Authorization: Bearer <admin-token>

{
  "roleName": "NonExistentRole"
}
```

**Expected Response (400 Bad Request):**
```json
{
  "success": false,
  "data": null,
  "message": "Role 'NonExistentRole' does not exist.",
  "errors": {
    "RoleName": ["Role 'NonExistentRole' does not exist."]
  }
}
```

### Test 10: Assign Role to Non-Existent User

**Request:**
```
POST https://localhost:7001/api/users/nonexistent-user-id/roles
Content-Type: application/json
Authorization: Bearer <admin-token>

{
  "roleName": "Admin"
}
```

**Expected Response (404 Not Found):**
```json
{
  "success": false,
  "data": null,
  "message": "User with ID 'nonexistent-user-id' not found."
}
```

### Test 11: Remove Role from User

**Request:**
```
DELETE https://localhost:7001/api/users/3fa85f64-5717-4562-b3fc-2c963f66afa6/roles/Admin
Authorization: Bearer <admin-token>
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "data": null,
  "message": "Role 'Admin' removed from user 'ahmad' successfully."
}
```

**Verification:**
- The row is deleted from AspNetUserRoles.
- The user no longer has the "Admin" role.

### Test 12: Get User's Roles

**Request:**
```
GET https://localhost:7001/api/users/3fa85f64-5717-4562-b3fc-2c963f66afa6/roles
Authorization: Bearer <admin-token>
```

**Expected Response (200 OK) — after assigning Admin:**
```json
{
  "success": true,
  "data": ["Admin"],
  "message": null
}
```

**Expected Response (200 OK) — after removing Admin:**
```json
{
  "success": true,
  "data": [],
  "message": null
}
```

### Test 13: Assign Role Without Admin Token (Should Fail)

**Request:**
```
POST https://localhost:7001/api/users/3fa85f64-5717-4562-b3fc-2c963f66afa6/roles
Content-Type: application/json
Authorization: Bearer <regular-user-token>

{
  "roleName": "Admin"
}
```

**Expected Response (403 Forbidden):**
```json
{
  "type": "https://tools.ietf.org/html/rfc9110#section-15.5.4",
  "title": "Forbidden",
  "status": 403,
  "traceId": "00-abc123..."
}
```

**Verification:**
- [Authorize(Roles="Admin")] returns 403 when the user doesn't have the Admin role.
- Regular users cannot assign roles.

### Swagger Tests

1. Run the API and navigate to `https://localhost:7001/swagger`.
2. Find the `POST /api/roles` endpoint.
3. Click "Try it out".
4. Enter:
   ```json
   {
     "name": "Moderator",
     "description": "Can edit and delete content"
   }
   ```
5. Click "Execute".
6. Expected: `200 OK` with the created role.
7. Find `GET /api/roles`.
8. Click "Try it out" → "Execute".
9. Expected: `200 OK` with the list of roles.
10. Find `POST /api/users/{userId}/roles`.
11. Enter the user ID and `{"roleName": "Moderator"}`.
12. Click "Execute".
13. Expected: `200 OK` with success message.

---

# What's Next — Videos 10–19

This file covers Videos 01–09, which take you from concept through core API implementation (registration, login, JWT, roles). The remaining videos build on this foundation:

| Video | Title | What You'll Learn |
|-------|-------|-------------------|
| 10 | RBAC in API — [Authorize(Roles)], Policy Tests, Permission System | Secure endpoints with role-based authorization |
| 11 | Claims in API — Add/Remove Claims, Claim Policies, Reading Claims | Use claims for fine-grained authorization |
| 12 | Policy-Based Authorization — Custom Requirements & Handlers | Build custom authorization policies |
| 13 | Password Policies & Custom Validation | Configure password rules and custom validators |
| 14 | Account Lockout & Security Stamp | Protect against brute force, invalidate tokens |
| 15 | Two-Factor Authentication (2FA) — TOTP, Recovery Codes | Add a second factor to login |
| 16 | External Login Providers — Google, Facebook, Microsoft | Let users log in with external accounts |
| 17 | Token Providers — Email Confirmation, Password Reset, Custom Providers | Send confirmation and reset emails |
| 18 | Customizing Identity — Custom Stores, Custom SignInManager, JWT Customization | Extend Identity beyond the defaults |
| 19 | Production-Ready API Security — Best Practices, Audit Logging, Troubleshooting | Deploy with confidence |

Each video follows the same structure: Theory → 🎬 Recording Notes → Complete Implementation → Postman/Swagger Tests. The complete file for all 19 videos is `README.md` in the same folder.

# Video 10 — RBAC in API: [Authorize(Roles)], Policy Tests, Permission System

## Theory & Definitions

### What Is RBAC (Role-Based Access Control)?

RBAC is a security model where access is granted based on roles. A user is assigned to one or more roles, and each role has a set of permissions. When a user makes a request, the system checks if the user's roles grant access to the requested resource.

In ASP.NET Core Identity, RBAC is implemented through:
- **Roles** — named collections (Admin, User, Moderator)
- **[Authorize(Roles="...")]** — attribute that checks if the user has the specified role
- **Role claims in JWT** — the roles are encoded in the token so authorization is stateless

### How [Authorize(Roles)] Works

When you put `[Authorize(Roles="Admin")]` on a controller or action:

1. The JWT bearer middleware validates the token (signature, expiration, issuer, audience)
2. The claims are extracted from the token
3. ASP.NET Core checks if any of the user's claims match `ClaimTypes.Role` with value "Admin"
4. If a matching role claim is found, access is granted
5. If no matching role claim is found, access is denied (403 Forbidden)

**Important:** The role check happens on the CLAIM, not in the database. The roles are encoded in the JWT when the user logs in. This means:
- No database lookup on every request (stateless)
- Role changes don't take effect until the user re-logs in (token expiration)
- The role claim value must match exactly what's in the attribute

### Multiple Roles in [Authorize(Roles)]

You can specify multiple roles in two ways:

**Comma-separated (OR logic):**
```csharp
[Authorize(Roles = "Admin, Moderator")]
```
The user can access if they have EITHER "Admin" OR "Moderator" role.

**Multiple attributes (AND logic):**
```csharp
[Authorize(Roles = "Admin")]
[Authorize(Roles = "Manager")]
```
The user must have BOTH "Admin" AND "Manager" roles. (This is less common — usually OR is what you want.)

**Default behavior:** `[Authorize(Roles = "Admin,Moderator")]` uses OR logic. The user needs at least one of the specified roles.

### Where to Apply [Authorize(Roles)]

| Level | Scope | Use case |
|-------|-------|----------|
| Controller class | All actions in the controller | Entire controller is role-restricted (e.g., AdminController) |
| Action method | Single endpoint | Specific endpoint requires a role (e.g., DELETE requires Admin) |
| Both | Class + action | Class requires "User" role, action additionally requires "Admin" (AND logic) |

**Example — class-level:**
```csharp
[Authorize(Roles = "Admin")]
[ApiController]
[Route("api/[controller]")]
public class AdminController : ControllerBase
{
    // All endpoints here require Admin role
}
```

**Example — action-level:**
```csharp
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    [HttpGet]  // Any authenticated user can GET
    [Authorize]
    public IActionResult Get() { ... }

    [HttpPost]  // Only Admin can POST (create new users)
    [Authorize(Roles = "Admin")]
    public IActionResult Post() { ... }
}
```

### Permission System — Beyond Roles

Roles are a coarse-grained authorization mechanism. For fine-grained permissions, you build a permission system on top of roles:

**Approach 1: Claims-based permissions**
- Each permission is a claim (e.g., "can_edit_posts", "can_delete_users")
- Roles are collections of claims
- Users inherit claims from their roles
- [Authorize(Policy = "CanEditPosts")] checks for the claim

**Approach 2: Role hierarchy**
- Admin > Moderator > User (hierarchical)
- Admin inherits all Moderator permissions
- Moderator inherits all User permissions
- Implemented via claims or custom authorization logic

**Approach 3: Permission table**
- Database table mapping roles to permissions
- Checked at runtime (not stateless — requires database lookup)
- More flexible but less performant

For this tutorial, we'll show Approach 1 (claims-based permissions) in Video 11 and Video 12.

### "When to Use vs When Not to Use" — RBAC

| Decision | Use it | Don't use it |
|----------|--------|--------------|
| [Authorize(Roles)] | You have clear role distinctions (Admin, User, etc.) | Your authorization is purely claim-based (no roles) |
| Multiple roles per user | Users can have different combinations of roles | Each user has exactly one role (simpler but less flexible) |
| Class-level [Authorize] | Entire controller is restricted (admin-only controllers) | Every action has different requirements (action-level only) |
| Permission claims | You need fine-grained control (can_edit, can_delete, etc.) | Coarse-grained roles are sufficient (Admin vs User is enough) |
| Role hierarchy | You have a clear hierarchy (Admin > Moderator > User) | Roles are flat (no hierarchy, each role is independent) |
| Database-checked permissions | Permissions change frequently, need real-time checks | Permissions are stable, encoded in JWT (stateless, faster) |

### Key Insight: RBAC Is Simple but Limited

RBAC is the simplest authorization model. It works well when:
- You have a small number of well-defined roles
- Permissions map cleanly to roles
- Role changes are infrequent

RBAC struggles when:
- You have hundreds of permissions (too many roles to manage)
- Permissions are dynamic (change based on context, time, etc.)
- You need resource-level authorization (user can edit ONLY their own posts)

For complex scenarios, you combine RBAC with claims (Video 11) and policy-based authorization (Video 12).

---

## 🎬 Video Recording Notes

**Opening (say this):**
> \"Now we put roles to work. We've created roles, assigned users to roles. Now we protect endpoints with those roles. This is RBAC — Role-Based Access Control. We'll show [Authorize(Roles)] on controllers and actions, multiple roles, AND vs OR logic, and build a simple permission system on top of roles.\"

**Show on screen (do this):**
> Create a test controller with various [Authorize] configurations. Show a protected endpoint that works with the right role and returns 403 without it. Show multiple roles, show class-level vs action-level authorization. Then build a permission claim system.

**Key points to emphasize (say this):**
> \"[Authorize(Roles='Admin')] checks the JWT claims, not the database. The role is encoded in the token when the user logs in. This is stateless — no database lookup on every request. But it also means role changes don't take effect until the user re-logs in.\"

> \"Multiple roles in [Authorize(Roles='Admin,Moderator')] use OR logic. The user needs at least one of the roles. If you need AND logic (user must have BOTH), use multiple [Authorize] attributes.\"

> \"Class-level [Authorize] protects ALL endpoints in the controller. Action-level [Authorize] protects a single endpoint. You can use both — class-level for the baseline, action-level for additional restrictions.\"

> \"A permission system is built on top of roles. Instead of checking [Authorize(Roles='Admin')], you check [Authorize(Policy='CanDeleteUsers')]. The policy checks for a claim. Admin gets that claim because Admin role includes it. This is more flexible — you can give the 'CanDeleteUsers' claim to other roles without making them Admin.\"

**Analogy (say this):**
> \"Think of roles like keys. The Admin key opens all doors. The User key opens basic doors. The Moderator key opens content doors. [Authorize(Roles='Admin')] is like a door that only the Admin key opens. Multiple roles are like a door that opens with either the Admin key OR the Moderator key.\"

> \"Permissions are like specific actions. 'CanDeleteUsers' is a permission. Instead of checking if you have the Admin key, you check if you have the 'CanDeleteUsers' permission. Admin has it. Maybe a SeniorModerator also has it. The door checks for the permission, not the key.\"

**Common viewer question:**
> \"What's the difference between [Authorize] and [Authorize(Roles='...')]?\" — [Authorize] requires any authenticated user (any valid JWT). [Authorize(Roles='Admin')] requires an authenticated user AND the Admin role claim.

> \"Can I use [Authorize(Roles)] without JWT?\" — Yes, it works with any authentication scheme (cookies, JWT, etc.). The attribute checks the user's claims, regardless of how they were authenticated. But in an API, JWT is the standard.

> \"How do I make an endpoint accessible to Admin OR Moderator?\" — [Authorize(Roles='Admin,Moderator')] — comma-separated, OR logic.

**What to show:**
- Controller with [Authorize(Roles)] on class and actions
- Multiple roles (OR and AND)
- Permission claim system (claims for specific permissions)
- Postman tests: access with role, access without role (403), access with multiple roles
- Swagger UI tests

**What to skip:**
- Resource-based authorization (user can edit ONLY their own resource) — that's Video 12
- Complex permission hierarchies — beyond scope, mention as advanced
- Database-driven permissions — mention as alternative, focus on JWT claims

---

## Complete Implementation

### File: Controllers/ProtectedController.cs (RBAC Demo)

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Controllers/ProtectedController.cs
// Video 10 — RBAC Demonstration Controller
// ─────────────────────────────────────────────────────────────────────────────
// This controller demonstrates various [Authorize(Roles)] configurations.
//
// Endpoints:
//   - GET /api/protected/basic — requires any authenticated user
//   - GET /api/protected/user-only — requires "User" role
//   - GET /api/protected/admin-only — requires "Admin" role
//   - GET /api/protected/admin-or-moderator — requires "Admin" OR "Moderator"
//   - GET /api/protected/admin-and-manager — requires BOTH "Admin" AND "Manager"
//   - POST /api/protected/admin-create — requires "Admin" (action-level)
//   - DELETE /api/protected/admin-delete — requires "Admin" (action-level)
//
// This controller is for DEMONSTRATION. In a real project, you'd organize
// controllers by feature, not by authorization level.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Create this controller and show each [Authorize] configuration
//   - Test each endpoint with different users (Admin, User, Moderator)
//   - Show 403 responses when role is missing
//   - Show AND vs OR logic
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.DTOs;
using System.Security.Claims;

namespace IdentityApiTutorial.Controllers
{
    // ─────────────────────────────────────────────────────────────────────────────
    // ProtectedController — demonstrates RBAC configurations.
    //
    // Class-level [Authorize(Roles="User")] — all endpoints require at least
    // the "User" role. This is the baseline.
    //
    // Action-level [Authorize(Roles="Admin")] — additional restriction on top
    // of the class-level baseline. The action requires BOTH "User" AND "Admin".
    //
    // This is AND logic: class-level + action-level = user must have both roles.
    // ─────────────────────────────────────────────────────────────────────────────
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "User")]   // Class-level: all endpoints require "User" role
    public class ProtectedController : ControllerBase
    {
        private readonly ILogger<ProtectedController> _logger;

        public ProtectedController(ILogger<ProtectedController> logger)
        {
            _logger = logger;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // Basic — accessible to any authenticated user with "User" role.
        //
        // This is the baseline — class-level [Authorize(Roles="User")] applies.
        // Any user with the "User" role can access this.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("basic")]
        public IActionResult GetBasic()
        {
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Accessible to any user with 'User' role.",
                Data = new
                {
                    User = User.Identity?.Name,
                    Roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList(),
                    Timestamp = DateTime.UtcNow
                }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // UserOnly — explicitly requires "User" role (redundant with class-level,
        // but shown for clarity).
        //
        // This endpoint demonstrates explicit role specification on an action.
        // In practice, you'd use this when the class-level authorization is
        // different (e.g., class requires "Authenticated", action requires "User").
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("user-only")]
        [Authorize(Roles = "User")]   // Explicit — same as class-level
        public IActionResult GetUserOnly()
        {
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Accessible to 'User' role only.",
                Data = new { User = User.Identity?.Name }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // AdminOnly — requires "Admin" role.
        //
        // Class-level requires "User". Action-level requires "Admin".
        // Combined: user must have BOTH "User" AND "Admin" roles.
        //
        // In practice, Admin usually has "User" role too (or you skip the
        // class-level [Authorize] for admin controllers). But this demonstrates
        // the AND logic.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("admin-only")]
        [Authorize(Roles = "Admin")]   // Additional restriction — requires Admin
        public IActionResult GetAdminOnly()
        {
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Accessible to 'Admin' role only (requires both 'User' and 'Admin').",
                Data = new { User = User.Identity?.Name, Roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList() }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // AdminOrModerator — requires "Admin" OR "Moderator" role.
        //
        // Comma-separated roles = OR logic.
        // User must have at least one of the specified roles.
        //
        // Combined with class-level "User": user must have "User" AND ("Admin" OR "Moderator").
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("admin-or-moderator")]
        [Authorize(Roles = "Admin, Moderator")]   // OR logic — comma separated
        public IActionResult GetAdminOrModerator()
        {
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Accessible to 'Admin' OR 'Moderator' role.",
                Data = new { User = User.Identity?.Name, Roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList() }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // AdminAndManager — requires BOTH "Admin" AND "Manager" roles.
        //
        // Multiple [Authorize] attributes = AND logic.
        // User must have ALL specified roles.
        //
        // Note: This endpoint also inherits class-level "User" requirement.
        // So user needs "User" AND "Admin" AND "Manager" — three roles.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("admin-and-manager")]
        [Authorize(Roles = "Admin")]      // First role required
        [Authorize(Roles = "Manager")]    // Second role required (AND)
        public IActionResult GetAdminAndManager()
        {
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Accessible to users with BOTH 'Admin' AND 'Manager' roles.",
                Data = new { User = User.Identity?.Name, Roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList() }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // Create — POST endpoint that requires "Admin" role.
        //
        // Demonstrates action-level authorization on a mutable endpoint.
        // Only Admin can create resources.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("create")]
        [Authorize(Roles = "Admin")]   // Only Admin can create
        public IActionResult PostCreate([FromBody] object data)
        {
            _logger.LogInformation("Resource created by {UserId}", User.Identity?.Name);

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Resource created successfully.",
                Data = new { User = User.Identity?.Name, Action = "Create", Timestamp = DateTime.UtcNow }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // Delete — DELETE endpoint that requires "Admin" role.
        //
        // Demonstrates action-level authorization on a destructive endpoint.
        // Only Admin can delete resources.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpDelete("delete/{id}")]
        [Authorize(Roles = "Admin")]   // Only Admin can delete
        public IActionResult Delete(string id)
        {
            _logger.LogInformation("Resource deleted by {UserId}, ID: {Id}", User.Identity?.Name, id);

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Resource deleted successfully.",
                Data = new { User = User.Identity?.Name, Action = "Delete", Id = id, Timestamp = DateTime.UtcNow }
            });
        }
    }
}
```

### File: Controllers/PermissionController.cs (Permission System Demo)

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Controllers/PermissionController.cs
// Video 10 — Permission System Based on Claims
// ─────────────────────────────────────────────────────────────────────────────
// This controller demonstrates a permission system built on claims.
//
// Instead of [Authorize(Roles="Admin")], we use [Authorize(Policy="CanDoSomething")].
// Each policy checks for a specific claim.
//
// Permissions are claims like:
//   - "can_create_posts" — can create new posts
//   - "can_edit_posts" — can edit existing posts
//   - "can_delete_posts" — can delete posts
//   - "can_manage_users" — can manage user accounts
//   - "can_view_reports" — can view analytics reports
//
// Roles are assigned permissions:
//   - Admin: all permissions
//   - Moderator: can_create_posts, can_edit_posts, can_delete_posts
//   - User: can_create_posts
//
// When a user logs in, their roles are translated to permission claims.
// This happens in the JWT generation (Video 08) or in a custom claims
// transformation service.
//
// For this tutorial, we'll show the policy-based approach and explain how
// permission claims are added to the JWT.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Create permission policies in Program.cs (or show where they'd go)
//   - Create this controller with [Authorize(Policy)] attributes
//   - Explain the relationship between roles and permissions
//   - Show that Admin can access all, Moderator can access some, User can access few
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.DTOs;
using System.Security.Claims;

namespace IdentityApiTutorial.Controllers
{
    // ─────────────────────────────────────────────────────────────────────────────
    // PermissionController — demonstrates permission-based authorization.
    //
    // Uses [Authorize(Policy = "...")] instead of [Authorize(Roles = "...")].
    // Each policy checks for a specific permission claim.
    //
    // Policies are registered in Program.cs (shown in the comments below).
    // For this tutorial, we assume the following policies are registered:
    //
    //   builder.Services.AddAuthorization(options =>
    //   {
    //       options.AddPolicy("CanCreatePosts", policy =>
    //           policy.RequireClaim("permission", "can_create_posts"));
    //       options.AddPolicy("CanEditPosts", policy =>
    //           policy.RequireClaim("permission", "can_edit_posts"));
    //       options.AddPolicy("CanDeletePosts", policy =>
    //           policy.RequireClaim("permission", "can_delete_posts"));
    //       options.AddPolicy("CanManageUsers", policy =>
    //           policy.RequireClaim("permission", "can_manage_users"));
    //       options.AddPolicy("CanViewReports", policy =>
    //           policy.RequireClaim("permission", "can_view_reports"));
    //   });
    //
    // These policies check for a "permission" claim with the specified value.
    // The permission claims are added to the JWT when the user logs in,
    // based on their roles.
    // ─────────────────────────────────────────────────────────────────────────────
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]   // All endpoints require authentication (any role)
    public class PermissionController : ControllerBase
    {
        private readonly ILogger<PermissionController> _logger;

        public PermissionController(ILogger<PermissionController> logger)
        {
            _logger = logger;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // CreatePost — requires "can_create_posts" permission.
        //
        // Users with "User" role have this permission.
        // Users with "Moderator" role have this permission.
        // Users with "Admin" role have this permission.
        // Users with no role (or a role without this permission) cannot access.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("posts")]
        [Authorize(Policy = "CanCreatePosts")]
        public IActionResult CreatePost([FromBody] object postData)
        {
            _logger.LogInformation("Post created by {UserId}", User.Identity?.Name);

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Post created successfully.",
                Data = new { User = User.Identity?.Name, Action = "CreatePost", Timestamp = DateTime.UtcNow }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // EditPost — requires "can_edit_posts" permission.
        //
        // Users with "Moderator" role have this permission.
        // Users with "Admin" role have this permission.
        // Users with only "User" role do NOT have this permission.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPut("posts/{id}")]
        [Authorize(Policy = "CanEditPosts")]
        public IActionResult EditPost(string id, [FromBody] object postData)
        {
            _logger.LogInformation("Post edited by {UserId}, PostId: {PostId}", User.Identity?.Name, id);

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Post edited successfully.",
                Data = new { User = User.Identity?.Name, Action = "EditPost", PostId = id, Timestamp = DateTime.UtcNow }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // DeletePost — requires "can_delete_posts" permission.
        //
        // Users with "Moderator" role have this permission.
        // Users with "Admin" role have this permission.
        // Users with only "User" role do NOT have this permission.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpDelete("posts/{id}")]
        [Authorize(Policy = "CanDeletePosts")]
        public IActionResult DeletePost(string id)
        {
            _logger.LogInformation("Post deleted by {UserId}, PostId: {PostId}", User.Identity?.Name, id);

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Post deleted successfully.",
                Data = new { User = User.Identity?.Name, Action = "DeletePost", PostId = id, Timestamp = DateTime.UtcNow }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // ManageUsers — requires "can_manage_users" permission.
        //
        // Only users with "Admin" role have this permission.
        // Moderator and User roles do NOT have this permission.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("users")]
        [Authorize(Policy = "CanManageUsers")]
        public IActionResult CreateUser([FromBody] object userData)
        {
            _logger.LogInformation("User managed by {UserId}", User.Identity?.Name);

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "User managed successfully.",
                Data = new { User = User.Identity?.Name, Action = "ManageUser", Timestamp = DateTime.UtcNow }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // ViewReports — requires "can_view_reports" permission.
        //
        // Only users with "Admin" role have this permission.
        // This is a read-only endpoint that shows sensitive data.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("reports")]
        [Authorize(Policy = "CanViewReports")]
        public IActionResult GetReports()
        {
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Reports retrieved successfully.",
                Data = new
                {
                    User = User.Identity?.Name,
                    Reports = new[] { "Monthly Active Users", "Revenue", "Churn Rate" },
                    Timestamp = DateTime.UtcNow
                }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // GetAllPermissions — returns the current user's permissions.
        //
        // Useful for debugging and for client-side UI rendering.
        // The client can check which buttons/actions to show based on permissions.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("permissions")]
        public IActionResult GetPermissions()
        {
            var permissions = User.FindAll("permission").Select(c => c.Value).ToList();

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Permissions retrieved.",
                Data = new
                {
                    User = User.Identity?.Name,
                    Permissions = permissions,
                    Roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList()
                }
            });
        }
    }
}
```

### Adding Permission Claims to JWT (Update to GenerateJwtToken)

In Video 08, we showed `GenerateJwtToken`. To support the permission system, we add permission claims based on roles:

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// Add to GenerateJwtToken method in AccountController (Video 08)
// Video 10 — Adding permission claims based on roles
// ─────────────────────────────────────────────────────────────────────────────
//
// After adding role claims, add permission claims:
//
//   // Map roles to permissions
//   var permissions = new List<string>();
//   var roles = await _userManager.GetRolesAsync(user);
//
//   foreach (var role in roles)
//   {
//       switch (role.ToLower())
//       {
//           case "admin":
//               permissions.AddRange(new[] { "can_create_posts", "can_edit_posts", "can_delete_posts", "can_manage_users", "can_view_reports" });
//               break;
//           case "moderator":
//               permissions.AddRange(new[] { "can_create_posts", "can_edit_posts", "can_delete_posts" });
//               break;
//           case "user":
//               permissions.Add("can_create_posts");
//               break;
//       }
//   }
//
//   // Add permission claims
//   foreach (var permission in permissions)
//   {
//       claims.Add(new Claim("permission", permission));
//   }
//
// This adds a "permission" claim for each permission the user has.
// [Authorize(Policy = "CanCreatePosts")] checks for Claim("permission", "can_create_posts").
//
// IMPORTANT: When roles change, the user must re-login to get updated permissions.
// This is the same limitation as role claims — JWT is stateless.
// ─────────────────────────────────────────────────────────────────────────────
```

---

## Postman / Swagger Tests

**Test 1 — Access Endpoint with Correct Role:**

```
ENDPOINT: GET https://localhost:7001/api/protected/basic

AUTHENTICATION: Bearer token (User role)

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Accessible to any user with 'User' role.",
  "data": {
    "user": "testuser@example.com",
    "roles": ["User"],
    "timestamp": "2024-01-15T10:00:00Z"
  },
  "errors": []
}

WHAT THIS MEANS:
- User has "User" role — class-level [Authorize(Roles="User")] passes
- Endpoint is accessible
```

**Test 2 — Access Endpoint Without Required Role:**

```
ENDPOINT: GET https://localhost:7001/api/protected/admin-only

AUTHENTICATION: Bearer token (User role ONLY — no Admin)

EXPECTED RESPONSE (403 Forbidden):
{
  "type": "https://tools.ietf.org/html/rfc7231#section-6.5.3",
  "title": "Forbidden",
  "status": 403,
  "traceId": "..."
}

WHAT THIS MEANS:
- User does NOT have "Admin" role
- [Authorize(Roles="Admin")] rejected the request
- 403 Forbidden — authenticated but not authorized
```

**Test 3 — Access Endpoint with Admin Role:**

```
ENDPOINT: GET https://localhost:7001/api/protected/admin-only

AUTHENTICATION: Bearer token (Admin role)

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Accessible to 'Admin' role only.",
  "data": {
    "user": "admin@tutorial.local",
    "roles": ["Admin", "User"],
    "timestamp": "2024-01-15T10:00:00Z"
  },
  "errors": []
}

WHAT THIS MEANS:
- User has "Admin" role — [Authorize(Roles="Admin")] passes
- User also has "User" role (class-level requirement)
- Endpoint is accessible
```

**Test 4 — Access OR-Logic Endpoint:**

```
Test 4a — With Admin role:
ENDPOINT: GET https://localhost:7001/api/protected/admin-or-moderator
AUTH: Bearer token (Admin role)
EXPECTED: 200 OK — Admin has access (OR logic)

Test 4b — With Moderator role:
ENDPOINT: GET https://localhost:7001/api/protected/admin-or-moderator
AUTH: Bearer token (Moderator role)
EXPECTED: 200 OK — Moderator has access (OR logic)

Test 4c — With User role only:
ENDPOINT: GET https://localhost:7001/api/protected/admin-or-moderator
AUTH: Bearer token (User role only)
EXPECTED: 403 Forbidden — User doesn't have Admin or Moderator
```

**Test 5 — Access AND-Logic Endpoint:**

```
Test 5a — With Admin only (no Manager):
EXPECTED: 403 Forbidden — needs both Admin AND Manager

Test 5b — With Manager only (no Admin):
EXPECTED: 403 Forbidden — needs both Admin AND Manager

Test 5c — With both Admin AND Manager:
EXPECTED: 200 OK — has both required roles

Setup for Test 5c:
1. Assign "Manager" role to admin user (Video 09 endpoint)
2. Re-login to get new token with both roles
3. Access the endpoint
```

**Test 6 — Permission-Based Access:**

```
Test 6a — User creates post (has can_create_posts):
ENDPOINT: POST https://localhost:7001/api/permission/posts
AUTH: Bearer token (User role — has can_create_posts)
EXPECTED: 200 OK

Test 6b — User edits post (does NOT have can_edit_posts):
ENDPOINT: PUT https://localhost:7001/api/permission/posts/1
AUTH: Bearer token (User role)
EXPECTED: 403 Forbidden — User doesn't have can_edit_posts

Test 6c — Moderator edits post (has can_edit_posts):
ENDPOINT: PUT https://localhost:7001/api/permission/posts/1
AUTH: Bearer token (Moderator role)
EXPECTED: 200 OK

Test 6d — Admin views reports (has can_view_reports):
ENDPOINT: GET https://localhost:7001/api/permission/reports
AUTH: Bearer token (Admin role)
EXPECTED: 200 OK

Test 6e — User views reports (does NOT have can_view_reports):
ENDPOINT: GET https://localhost:7001/api/permission/reports
AUTH: Bearer token (User role)
EXPECTED: 403 Forbidden
```

**Test 7 — Check User's Permissions:**

```
ENDPOINT: GET https://localhost:7001/api/permission/permissions

AUTH: Bearer token (Admin role)

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Permissions retrieved.",
  "data": {
    "user": "admin@tutorial.local",
    "permissions": ["can_create_posts", "can_edit_posts", "can_delete_posts", "can_manage_users", "can_view_reports"],
    "roles": ["Admin", "User"]
  },
  "errors": []
}

WHAT THIS MEANS:
- Admin has all 5 permissions
- Admin has 2 roles (Admin + User)
- Client can use this to show/hide UI elements
```

---

# Video 11 — Claims in API: Add/Remove Claims, Claim Policies, Reading Claims from JWT

## Theory & Definitions

### What Are Claims?

A claim is a name-value pair that represents a fact about the user. Claims are the fundamental unit of identity in ASP.NET Core.

Examples of claims:
- `sub` (Subject): "user-123" — the user's unique identifier
- `email`: "user@example.com" — the user's email
- `name`: "John Doe" — the user's display name
- `role`: "Admin" — the user's role
- `permission`: "can_edit_posts" — a specific permission
- `tenant_id`: "tenant-456" — the user's tenant/organization
- `birthdate`: "1990-01-01" — the user's birthdate
- `custom_claim`: "custom_value" — any custom data you want

Claims are NOT roles. Roles are a specific type of claim (with `ClaimTypes.Role` as the type). But claims are more general — you can have any claim type with any value.

### Claims vs Roles — When to Use Each

| Use Claims | Use Roles |
|------------|-----------|
| You need fine-grained attributes (tenant ID, department, clearance level) | You have clear user categories (Admin, User, Moderator) |
| You need data that varies per user (preferences, settings) | You have a permission set that maps to a named group |
| You need to pass data to the client in the JWT (user profile info) | You want to use [Authorize(Roles)] for simple authorization |
| You need claims for auditing (who did what, with what attributes) | You're building RBAC (role-based access control) |
| You have a flat permission model (each user has individual permissions) | You have a hierarchical permission model (roles inherit from other roles) |

**Best practice:** Use BOTH. Roles for coarse-grained authorization (Admin vs User), claims for fine-grained data (tenant ID, permissions, attributes). Roles are claims — `ClaimTypes.Role` is just a claim type.

### Claim Types in ASP.NET Core

| Claim Type | Purpose | Used By |
|------------|---------|---------|
| `ClaimTypes.NameIdentifier` | User's unique ID | `User.Identity.Name` |
| `ClaimTypes.Name` | User's display name | `User.Identity.Name` (fallback) |
| `ClaimTypes.Role` | User's role | `[Authorize(Roles)]` |
| `ClaimTypes.Email` | User's email | Custom code, email confirmation |
| `JwtRegisteredClaimNames.Sub` | Subject (user ID) | JWT standard |
| `JwtRegisteredClaimNames.Email` | Email | JWT standard |
| `JwtRegisteredClaimNames.Jti` | JWT ID (unique token ID) | JWT standard, revocation |
| `JwtRegisteredClaimNames.Iat` | Issued at (timestamp) | JWT standard |
| `JwtRegisteredClaimNames.Exp` | Expiration (timestamp) | JWT standard (added automatically) |
| `JwtRegisteredClaimNames.Iss` | Issuer | JWT standard |
| `JwtRegisteredClaimNames.Aud` | Audience | JWT standard |
| Custom (e.g., "tenant_id", "permission") | Any custom data | Your custom code |

### How Claims Are Added to the JWT

In `GenerateJwtToken` (Video 08), we create claims and add them to the `JwtSecurityToken`:

```csharp
var claims = new List<Claim>
{
    new Claim(JwtRegisteredClaimNames.Sub, user.Id),
    new Claim(JwtRegisteredClaimNames.Email, user.Email),
    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
    new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
    new Claim(ClaimTypes.NameIdentifier, user.Id),
    new Claim(ClaimTypes.Name, user.UserName),
    // ... more claims
};

// Add role claims
var roles = await _userManager.GetRolesAsync(user);
foreach (var role in roles)
{
    claims.Add(new Claim(ClaimTypes.Role, role));
}

// Add custom claims
claims.Add(new Claim("tenant_id", user.TenantId.ToString()));
claims.Add(new Claim("permission", "can_edit_posts"));
```

Each claim becomes a JSON property in the JWT payload.

### UserManager and Claims

`UserManager<TUser>` provides claim management methods:

| Method | Purpose |
|--------|---------|
| `AddClaimAsync(user, claim)` | Add a claim to the user (persisted to database) |
| `AddClaimsAsync(user, claims)` | Add multiple claims |
| `RemoveClaimAsync(user, claim)` | Remove a claim from the user |
| `RemoveClaimsAsync(user, claims)` | Remove multiple claims |
| `GetClaimsAsync(user)` | Get all claims for a user (from database) |
| `GetClaimsAsync(user, cancellationToken)` | Get claims with cancellation |

**Important:** `UserManager` claims are PERSISTENT — they're stored in the `AspNetUserClaims` table. They survive logout, token expiration, and browser restarts. When the user logs in again, these claims are loaded and (optionally) added to the JWT.

**JWT claims vs UserManager claims:**
- **JWT claims** — ephemeral, in the token, expire with the token. They're a snapshot of the user's state at login time.
- **UserManager claims** — persistent, in the database, always current. They're the source of truth.

**The relationship:**
1. User logs in → we load persistent claims from UserManager → add them to JWT → return JWT to client
2. Client makes request with JWT → middleware validates JWT → extracts claims → authorizes
3. Admin updates user's claims (via API) → persistent claims updated → user must re-login to get new JWT with updated claims

### Claim Policies — Authorizing Based on Claims

A claim policy checks for a specific claim (type + value):

```csharp
// In Program.cs
builder.Services.AddAuthorization(options =>
{
    // Require a specific claim with a specific value
    options.AddPolicy("CanEditPosts", policy =>
        policy.RequireClaim("permission", "can_edit_posts"));

    // Require ANY of multiple values
    options.AddPolicy("CanManageContent", policy =>
        policy.RequireClaim("permission", "can_edit_posts", "can_delete_posts", "can_publish_posts"));

    // Require a claim to exist (any value)
    options.AddPolicy("HasTenant", policy =>
        policy.RequireClaim("tenant_id"));

    // Require a claim with a value matching a regex
    options.AddPolicy("ClearanceLevel", policy =>
        policy.RequireClaim("clearance", "high", "critical"));

    // Combine multiple requirements (AND logic)
    options.AddPolicy("AdminInTenant", policy =>
        policy.RequireClaim(ClaimTypes.Role, "Admin")
              .RequireClaim("tenant_id"));
});
```

### Reading Claims from the JWT in Controllers

In a controller, you access claims via `User` (ClaimsPrincipal):

```csharp
// Get a specific claim value
var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
var email = User.FindFirst(JwtRegisteredClaimNames.Email)?.Value;
var tenantId = User.FindFirst("tenant_id")?.Value;

// Get all claims of a type
var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
var permissions = User.FindAll("permission").Select(c => c.Value).ToList();

// Check if a claim exists
var hasPermission = User.HasClaim("permission", "can_edit_posts");

// Get the full claims principal
var allClaims = User.Claims.ToList();
```

### "When to Use vs When Not to Use" — Claims

| Decision | Use it | Don't use it |
|----------|--------|--------------|
| Custom claims in JWT | You need user data in the token for authorization or client use | You're putting too much data in the JWT (size limits, security) |
| Persistent claims in UserManager | Claims that survive logout and need to be managed (permissions, tenant) | Claims that are only needed in the token (JWT-specific data like Jti) |
| Claim policies | You have specific claim-based authorization requirements | Simple role-based authorization is sufficient (use [Authorize(Roles)] instead) |
| Many custom claims | You have a few important claims (tenant, permissions, clearance) | You're adding dozens of claims — JWT size grows, performance suffers |
| Claims for everything | You use claims as the universal authorization mechanism | You use claims for data that belongs in the user profile (not authorization) |

### Key Insight: Claims Are the Universal Language of Identity

Everything in Identity is ultimately claims:
- Roles are claims (ClaimTypes.Role)
- Permissions are claims (custom "permission" claim)
- User ID is a claim (ClaimTypes.NameIdentifier)
- Email is a claim (JwtRegisteredClaimNames.Email)
- Custom data is a claim (any custom type)

When you understand claims, you understand Identity. The JWT is a bag of claims. The [Authorize] attribute checks claims. UserManager manages claims. It's all claims.

---

## 🎬 Video Recording Notes

**Opening (say this):**
> \"Claims are the fundamental unit of identity. A claim is a fact about the user — their ID, their email, their roles, their permissions, their tenant. Today we'll understand claims deeply: what they are, how they're added to JWTs, how to add and remove them via the API, how to authorize based on claims with policies, and how to read claims from the JWT in your controllers.\"

**Show on screen (do this):**
> Show a JWT decoded on jwt.io — point to each claim and explain what it means. Then show the AddClaim and RemoveClaim endpoints. Then show a claim policy in Program.cs and a controller that uses [Authorize(Policy)]. Finally show how to read claims in a controller.

**Key points to emphasize (say this):**
> \"Claims and roles are not different things. Roles ARE claims — they're claims with type ClaimTypes.Role. When you add a role claim, you're adding a claim. When you add a custom claim like 'tenant_id', you're adding a claim. It's all the same mechanism.\"

> \"Claims in the JWT are a snapshot. They represent the user's state at login time. If you change a user's claims in the database, the JWT doesn't update until the user re-logs in. This is the stateless nature of JWT — the token is self-contained.\"

> \"Persistent claims (UserManager.AddClaimAsync) are stored in the database. They survive logout. When the user logs in again, these claims are loaded and added to the new JWT. Use persistent claims for data that needs to survive token expiration.\"

> \"Claim policies are more flexible than role policies. Instead of [Authorize(Roles='Admin')], you use [Authorize(Policy='CanEditPosts')]. The policy checks for a claim. This lets you give the 'CanEditPosts' permission to multiple roles without making them all Admin.\"

> \"Reading claims from the JWT is simple — User.FindFirst, User.FindAll, User.HasClaim. The ClaimsPrincipal is available in every controller. No database lookup needed — the claims are in the token.\"

**Analogy (say this):**
> \"Think of claims like facts on a resume. 'Name: John' is a claim. 'Role: Senior Developer' is a claim. 'Permission: CanReviewCode' is a claim. 'Tenant: Company A' is a claim. The JWT is the resume — it contains all the facts about the user. The [Authorize] attribute is the hiring manager — it checks specific facts on the resume to decide if you get the job (access).\"

> \"Persistent claims are like a personnel file. They're stored in the database and updated by HR (the admin). The resume (JWT) is generated from the personnel file when you're hired (login). If HR updates your file, your next resume reflects the change. But the old resume is still valid until you get a new one.\"

**Common viewer question:**
> \"How many claims can I put in a JWT?\" — Technically, hundreds. Practically, keep it under 10-20 claims. Each claim adds bytes to the token. A large token means larger headers on every request. Keep only what you need.

> \"Can I put sensitive data in claims?\" — No. The JWT is signed (not encrypted). Anyone with the token can decode it and read the claims. Only put non-sensitive data in claims. For sensitive data, use the database and look it up when needed.

> \"What's the difference between UserManager claims and JWT claims?\" — UserManager claims are persistent (database). JWT claims are ephemeral (token). When the user logs in, we copy persistent claims into the JWT. The JWT is a snapshot. If you update persistent claims, the user needs to re-login to get the update in their JWT.

**What to show:**
- Decoded JWT on jwt.io — point to each claim
- AddClaim endpoint (POST /api/claims/add)
- RemoveClaim endpoint (DELETE /api/claims/remove)
- Claim policy registration (Program.cs snippet)
- Controller with [Authorize(Policy)] attributes
- Reading claims in a controller (User.FindFirst, etc.)
- Postman tests for each

**What to skip:**
- Claim transformation services (IClaimsTransformation) — advanced, mention briefly
- Encryption of JWT (JWE) — beyond scope, claims are not encrypted by default
- Complex claim types (X.509, SAML) — not relevant for this API tutorial

---

## Complete Implementation

### File: DTOs/ClaimDtos.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: DTOs/ClaimDtos.cs
// Video 11 — Claim management DTOs
// ─────────────────────────────────────────────────────────────────────────────
// These DTOs define the API contract for claim management.
//
// ClaimAddRequest — what the client sends to add a claim
// ClaimRemoveRequest — what the client sends to remove a claim
// ClaimResponse — what the API returns for claim operations
// UserClaimsResponse — what the API returns for listing user claims
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Write each DTO and explain its fields
//   - Show that claims have a Type and a Value
//   - Explain that claim types can be standard (ClaimTypes.Role) or custom ("permission")
// ─────────────────────────────────────────────────────────────────────────────

using System.ComponentModel.DataAnnotations;

namespace IdentityApiTutorial.DTOs
{
    // ─────────────────────────────────────────────────────────────────────────────
    // ClaimAddRequest — DTO for adding a claim to a user.
    //
    // Fields:
    //   - ClaimType: The type of the claim (e.g., "permission", "tenant_id")
    //   - ClaimValue: The value of the claim (e.g., "can_edit_posts", "tenant-123")
    //
    // Validation:
    //   - Both fields are required
    //   - ClaimType: max 100 characters
    //   - ClaimValue: max 500 characters
    //
    // The claim type can be:
    //   - A standard claim type (ClaimTypes.Role, ClaimTypes.Email, etc.)
    //   - A custom claim type ("permission", "tenant_id", "clearance", etc.)
    //
    // For this tutorial, we use custom claim types for permissions.
    // ─────────────────────────────────────────────────────────────────────────────
    public class ClaimAddRequest
    {
        // ─────────────────────────────────────────────────────────────────────────
        // ClaimType — the type/name of the claim.
        //
        // Examples:
        //   - "permission" — for permission claims
        //   - "tenant_id" — for tenant/organization claims
        //   - "clearance" — for security clearance level
        //   - ClaimTypes.Role — for role claims (though we usually use AddToRoleAsync)
        //
        // Validation: Required, max 100 characters.
        // ─────────────────────────────────────────────────────────────────────────
        [Required]
        [StringLength(100)]
        public string ClaimType { get; set; } = string.Empty;

        // ─────────────────────────────────────────────────────────────────────────
        // ClaimValue — the value of the claim.
        //
        // Examples:
        //   - "can_edit_posts" — for permission claims
        //   - "tenant-456" — for tenant claims
        //   - "high" — for clearance claims
        //   - "Admin" — for role claims (if using ClaimTypes.Role as type)
        //
        // Validation: Required, max 500 characters.
        // ─────────────────────────────────────────────────────────────────────────
        [Required]
        [StringLength(500)]
        public string ClaimValue { get; set; } = string.Empty;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ClaimRemoveRequest — DTO for removing a claim from a user.
    //
    // To remove a claim, you need to specify both the type and value.
    // This is because a user can have multiple claims of the same type
    // with different values (e.g., multiple "permission" claims).
    //
    // Fields:
    //   - ClaimType: The type of the claim to remove
    //   - ClaimValue: The value of the claim to remove
    // ─────────────────────────────────────────────────────────────────────────────
    public class ClaimRemoveRequest
    {
        [Required]
        [StringLength(100)]
        public string ClaimType { get; set; } = string.Empty;

        [Required]
        [StringLength(500)]
        public string ClaimValue { get; set; } = string.Empty;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ClaimResponse — DTO for a single claim in API responses.
    // ─────────────────────────────────────────────────────────────────────────────
    public class ClaimResponse
    {
        public string Type { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // UserClaimsResponse — DTO for listing a user's claims.
    // ─────────────────────────────────────────────────────────────────────────────
    public class UserClaimsResponse
    {
        public string UserId { get; set; } = string.Empty;
        public string UserEmail { get; set; } = string.Empty;
        public List<ClaimResponse> Claims { get; set; } = new List<ClaimResponse>();
    }
}
```

### File: Controllers/ClaimController.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Controllers/ClaimController.cs
// Video 11 — Claim Management Endpoints
// ─────────────────────────────────────────────────────────────────────────────
// ClaimController handles claim management operations:
//   - POST /api/claims/add — add a claim to a user
//   - DELETE /api/claims/remove — remove a claim from a user
//   - GET /api/claims — list all claims for a user
//
// ALL endpoints require the "Admin" role (claim management is administrative).
//
// DI Dependencies:
//   UserManager<ApplicationUser> — manages user claims
//   ILogger<ClaimController> — logging
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Write the controller and each endpoint
//   - Explain the difference between persistent claims (UserManager) and JWT claims
//   - Show that adding a claim doesn't immediately affect the user's JWT
//   - Show that the user must re-login to get the new claim in their JWT
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.DTOs;
using IdentityApiTutorial.Models;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace IdentityApiTutorial.Controllers
{
    // ─────────────────────────────────────────────────────────────────────────────
    // ClaimController — manages user claims.
    //
    // All endpoints require Admin role.
    // Route: api/claims
    // ─────────────────────────────────────────────────────────────────────────────
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "Admin")]
    public class ClaimController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<ClaimController> _logger;

        public ClaimController(UserManager<ApplicationUser> userManager, ILogger<ClaimController> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // AddClaim — adds a claim to a user.
        //
        // POST /api/claims/add
        // Body: ClaimAddRequest (claimType, claimValue)
        // Query/string: userId (or from body — we use body for consistency)
        //
        // Flow:
        //   1. Validate ModelState
        //   2. Find user by ID (from request or route — we use request body here)
        //   3. Create the claim
        //   4. Call UserManager.AddClaimAsync(user, claim)
        //   5. Return success
        //
        // IMPORTANT: This adds a PERSISTENT claim to the database.
        // It does NOT update the user's existing JWT tokens.
        // The user must re-login to get the new claim in their JWT.
        //
        // If you need to immediately invalidate existing tokens, you must:
        //   - Change the user's SecurityStamp (invalidates all tokens)
        //   - Or implement a token blacklist
        //   - Or use short-lived tokens + refresh tokens
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("add")]
        public async Task<IActionResult> AddClaim([FromBody] ClaimAddRequest request)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList();

                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Validation failed.",
                    Errors = errors
                });
            }

            // For this example, we add the claim to the user identified by the
            // email in the request. In a real API, you'd use a route parameter
            // or a dedicated user ID field.
            var user = await _userManager.FindByEmailAsync(request.ClaimValue);

            if (user == null)
            {
                // If claimValue is not an email, try as user ID
                user = await _userManager.FindByIdAsync(request.ClaimValue);
            }

            if (user == null)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User not found.",
                    Errors = new List<string> { "Could not find user by the provided identifier." }
                });
            }

            // Create the claim
            var claim = new Claim(request.ClaimType, request.ClaimValue);

            // Add the claim to the user
            var result = await _userManager.AddClaimAsync(user, claim);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();

                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Failed to add claim.",
                    Errors = errors
                });
            }

            _logger.LogInformation("Claim added to user {UserId}: {ClaimType}={ClaimValue}",
                user.Id, request.ClaimType, request.ClaimValue);

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Claim added successfully. User must re-login to receive the updated token.",
                Data = new { UserId = user.Id, ClaimType = request.ClaimType, ClaimValue = request.ClaimValue }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // RemoveClaim — removes a claim from a user.
        //
        // DELETE /api/claims/remove
        // Body: ClaimRemoveRequest (claimType, claimValue)
        //
        // Flow:
        //   1. Validate ModelState
        //   2. Find user by ID
        //   3. Create the claim to remove (must match exactly)
        //   4. Call UserManager.RemoveClaimAsync(user, claim)
        //   5. Return success
        //
        // IMPORTANT: Same as AddClaim — this updates the database, not existing JWTs.
        // User must re-login to get the updated token without this claim.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpDelete("remove")]
        public async Task<IActionResult> RemoveClaim([FromBody] ClaimRemoveRequest request)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList();

                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Validation failed.",
                    Errors = errors
                });
            }

            // Find user — in a real API, use a proper user identifier
            var user = await _userManager.FindByEmailAsync(request.ClaimValue);
            if (user == null)
            {
                user = await _userManager.FindByIdAsync(request.ClaimValue);
            }

            if (user == null)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User not found.",
                    Errors = new List<string> { "Could not find user by the provided identifier." }
                });
            }

            // Create the claim to remove (must match exactly)
            var claim = new Claim(request.ClaimType, request.ClaimValue);

            // Remove the claim
            var result = await _userManager.RemoveClaimAsync(user, claim);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();

                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Failed to remove claim.",
                    Errors = errors
                });
            }

            _logger.LogInformation("Claim removed from user {UserId}: {ClaimType}={ClaimValue}",
                user.Id, request.ClaimType, request.ClaimValue);

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Claim removed successfully. User must re-login to receive the updated token.",
                Data = new { UserId = user.Id, ClaimType = request.ClaimType, ClaimValue = request.ClaimValue }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // GetUserClaims — lists all claims for a user.
        //
        // GET /api/claims?userId={userId}
        //
        // Flow:
        //   1. Get userId from query string
        //   2. Find user by ID
        //   3. Get claims via UserManager.GetClaimsAsync
        //   4. Return list of claims
        //
        // This is a read-only endpoint — useful for admin panels to view
        // a user's claims.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet]
        public async Task<IActionResult> GetUserClaims([FromQuery] string userId)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User ID is required.",
                    Errors = new List<string> { "Please provide a userId query parameter." }
                });
            }

            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User not found.",
                    Errors = new List<string> { $"No user found with ID '{userId}'." }
                });
            }

            var claims = await _userManager.GetClaimsAsync(user);

            var response = new UserClaimsResponse
            {
                UserId = user.Id,
                UserEmail = user.Email,
                Claims = claims.Select(c => new ClaimResponse
                {
                    Type = c.Type,
                    Value = c.Value
                }).ToList()
            };

            return Ok(new ApiResponse<UserClaimsResponse>
            {
                Success = true,
                Message = "User claims retrieved successfully.",
                Data = response
            });
        }
    }
}
```

### Reading Claims in a Controller (Example)

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// Example: Reading claims in a controller
// Video 11 — How to read claims from the JWT in your controllers
// ─────────────────────────────────────────────────────────────────────────────

using System.Security.Claims;

namespace IdentityApiTutorial.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class ClaimsReadingController : ControllerBase
    {
        // ─────────────────────────────────────────────────────────────────────────
        // GetMyClaims — returns all claims for the current user.
        //
        // Demonstrates how to read claims from the JWT in a controller.
        //
        // User is a ClaimsPrincipal — available in every controller.
        // It contains all the claims from the validated JWT.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("me")]
        public IActionResult GetMyClaims()
        {
            // ─────────────────────────────────────────────────────────────────────────
            // User.FindFirst — find the first claim with the specified type.
            //
            // Returns null if the claim doesn't exist.
            // Use null-conditional (?.) to safely access .Value.
            // ─────────────────────────────────────────────────────────────────────────
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var email = User.FindFirst(JwtRegisteredClaimNames.Email)?.Value;
            var userName = User.FindFirst(ClaimTypes.Name)?.Value;
            var tenantId = User.FindFirst("tenant_id")?.Value;

            // ─────────────────────────────────────────────────────────────────────────
            // User.FindAll — find ALL claims with the specified type.
            //
            // Returns an IEnumerable<Claim>. Use Select to extract values.
            // Useful for roles (a user can have multiple roles) and permissions.
            // ─────────────────────────────────────────────────────────────────────────
            var roles = User.FindAll(ClaimTypes.Role)
                .Select(c => c.Value)
                .ToList();

            var permissions = User.FindAll("permission")
                .Select(c => c.Value)
                .ToList();

            // ─────────────────────────────────────────────────────────────────────────
            // User.HasClaim — check if a specific claim exists.
            //
            // Overloads:
            //   - HasClaim(type, value) — check for specific type AND value
            //   - HasClaim(predicate) — check with a custom predicate
            //   - HasClaim(type) — check if any claim with this type exists
            // ─────────────────────────────────────────────────────────────────────────
            var canEditPosts = User.HasClaim("permission", "can_edit_posts");
            var isAdmin = User.HasClaim(ClaimTypes.Role, "Admin");
            var hasTenant = User.HasClaim("tenant_id");  // Any value

            // ─────────────────────────────────────────────────────────────────────────
            // User.Claims — all claims as a list.
            //
            // Useful for debugging or returning all claims to the client.
            // ─────────────────────────────────────────────────────────────────────────
            var allClaims = User.Claims.ToList();

            return Ok(new
            {
                UserId = userId,
                Email = email,
                UserName = userName,
                TenantId = tenantId,
                Roles = roles,
                Permissions = permissions,
                CanEditPosts = canEditPosts,
                IsAdmin = isAdmin,
                HasTenant = hasTenant,
                AllClaims = allClaims.Select(c => new { c.Type, c.Value }).ToList()
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // CheckPermission — demonstrates permission checking in an action.
        //
        // Shows how to check permissions manually (without a policy).
        // Useful when you need conditional logic based on permissions.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("check-permission")]
        public IActionResult CheckPermission([FromQuery] string permission)
        {
            var hasPermission = User.HasClaim("permission", permission);

            if (hasPermission)
            {
                return Ok(new ApiResponse<object>
                {
                    Success = true,
                    Message = $"User has permission: {permission}",
                    Data = new { Permission = permission, HasPermission = true }
                });
            }
            else
            {
                return Forbid(new ApiResponse<object>
                {
                    Success = false,
                    Message = $"User does not have permission: {permission}",
                    Errors = new List<string> { $"Missing permission: {permission}" }
                });
            }
        }
    }
}
```

### Claim Policy Registration (Program.cs snippet)

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Program.cs (claim policy registration)
// Video 11 — Registering claim policies
// ─────────────────────────────────────────────────────────────────────────────
//
// Add this to your Program.cs authorization configuration:
//
//   builder.Services.AddAuthorization(options =>
//   {
//       // Require a specific claim with a specific value
//       options.AddPolicy("CanEditPosts", policy =>
//           policy.RequireClaim("permission", "can_edit_posts"));
//
//       // Require ANY of multiple values (OR logic within the claim type)
//       options.AddPolicy("CanManageContent", policy =>
//           policy.RequireClaim("permission", "can_edit_posts", "can_delete_posts", "can_publish_posts"));
//
//       // Require a claim to exist (any value)
//       options.AddPolicy("HasTenant", policy =>
//           policy.RequireClaim("tenant_id"));
//
//       // Combine multiple requirements (AND logic across different claims)
//       options.AddPolicy("AdminInTenant", policy =>
//           policy.RequireClaim(ClaimTypes.Role, "Admin")
//                 .RequireClaim("tenant_id"));
//
//       // Require a claim with a value matching a custom rule
//       options.AddPolicy("HighClearance", policy =>
//           policy.RequireAssertion(context =>
//           {
//               var clearanceClaim = context.User.FindFirst("clearance");
//               if (clearanceClaim == null) return false;
//               var clearance = clearanceClaim.Value;
//               return clearance == "high" || clearance == "critical";
//           }));
//   });
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Show the policy registration in Program.cs
//   - Explain each policy type
//   - Show a controller using [Authorize(Policy = "...")]
//   - Test with different users (different claims)
// ─────────────────────────────────────────────────────────────────────────────
```

---

## Postman / Swagger Tests

**Test 1 — Add a Claim to a User:**

```
ENDPOINT: POST https://localhost:7001/api/claims/add

AUTHENTICATION: Bearer token (Admin)

BODY (raw JSON):
{
  "claimType": "permission",
  "claimValue": "testuser@example.com"
}

NOTE: For this example, we use claimValue as the user identifier.
In a real API, you'd have a separate userId field.

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Claim added successfully. User must re-login to receive the updated token.",
  "data": {
    "userId": "abc123-guid-here",
    "claimType": "permission",
    "claimValue": "testuser@example.com"
  },
  "errors": []
}

WHAT THIS MEANS:
- Claim was added to the user in the database (AspNetUserClaims)
- Existing JWT tokens are NOT updated
- User must re-login to get the new claim in their JWT
```

**Test 2 — Remove a Claim from a User:**

```
ENDPOINT: DELETE https://localhost:7001/api/claims/remove

BODY:
{
  "claimType": "permission",
  "claimValue": "testuser@example.com"
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Claim removed successfully. User must re-login to receive the updated token.",
  "data": {
    "userId": "abc123-guid-here",
    "claimType": "permission",
    "claimValue": "testuser@example.com"
  },
  "errors": []
}

WHAT THIS MEANS:
- Claim was removed from the user in the database
- Existing JWT tokens still have the claim until they expire
- User must re-login to get the updated token
```

**Test 3 — List User's Claims:**

```
ENDPOINT: GET https://localhost:7001/api/claims?userId=abc123-guid-here

AUTHENTICATION: Bearer token (Admin)

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "User claims retrieved successfully.",
  "data": {
    "userId": "abc123-guid-here",
    "userEmail": "testuser@example.com",
    "claims": [
      { "type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", "value": "abc123-guid-here" },
      { "type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "value": "testuser@example.com" },
      { "type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "value": "testuser@example.com" },
      { "type": "role", "value": "User" },
      { "type": "permission", "value": "can_create_posts" }
    ]
  },
  "errors": []
}

WHAT THIS MEANS:
- User has 5 claims (including standard Identity claims and custom claims)
- Role claim is present ("User")
- Permission claim is present ("can_create_posts")
- These are the persistent claims from the database
```

**Test 4 — Read Claims from JWT (Current User):**

```
ENDPOINT: GET https://localhost:7001/api/claimsreading/me

AUTHENTICATION: Bearer token (any authenticated user)

EXPECTED RESPONSE (200 OK):
{
  "userId": "abc123-guid-here",
  "email": "testuser@example.com",
  "userName": "testuser@example.com",
  "tenantId": null,
  "roles": ["User"],
  "permissions": ["can_create_posts"],
  "canEditPosts": false,
  "isAdmin": false,
  "hasTenant": false,
  "allClaims": [
    { "type": "nameidentifier", "value": "abc123-guid-here" },
    { "type": "name", "value": "testuser@example.com" },
    { "type": "emailaddress", "value": "testuser@example.com" },
    { "type": "role", "value": "User" },
    { "type": "permission", "value": "can_create_posts" },
    { "type": "sub", "value": "abc123-guid-here" },
    { "type": "jti", "value": "a1b2c3d4..." },
    { "type": "iat", "value": "1705315800" },
    { "type": "exp", "value": "1705319400" }
  ]
}

WHAT THIS MEANS:
- All claims from the JWT are accessible via User.Claims
- Standard claims (sub, jti, iat, exp) are present
- Role and permission claims are present
- Custom claims (tenant_id) are null if not in the token
```

**Test 5 — Check Permission Endpoint:**

```
Test 5a — With permission:
ENDPOINT: GET https://localhost:7001/api/claimsreading/check-permission?permission=can_create_posts
AUTH: Bearer token (User — has can_create_posts)
EXPECTED: 200 OK — user has the permission

Test 5b — Without permission:
ENDPOINT: GET https://localhost:7001/api/claimsreading/check-permission?permission=can_delete_posts
AUTH: Bearer token (User — does NOT have can_delete_posts)
EXPECTED: 403 Forbidden — user doesn't have the permission
```

**Test 6 — Claim Policy Authorization:**

```
PRE-REQUISITE: Policies registered in Program.cs:
  - "CanEditPosts" requires claim("permission", "can_edit_posts")
  - "CanManageContent" requires claim("permission", "can_edit_posts") OR ("permission", "can_delete_posts")

Test 6a — User with can_edit_posts:
ENDPOINT: GET https://localhost:7001/api/permission/posts/1 (PUT — edit post)
AUTH: Bearer token (User with can_edit_posts claim)
EXPECTED: 200 OK

Test 6b — User without can_edit_posts:
ENDPOINT: GET https://localhost:7001/api/permission/posts/1 (PUT — edit post)
AUTH: Bearer token (User without can_edit_posts claim)
EXPECTED: 403 Forbidden

Test 6c — User with can_delete_posts (satisfies CanManageContent):
ENDPOINT: GET https://localhost:7001/api/permission/posts/1 (PUT — edit post)
AUTH: Bearer token (User with can_delete_posts but NOT can_edit_posts)
EXPECTED: 403 Forbidden — CanManageContent requires can_edit_posts OR can_delete_posts,
                       but the endpoint uses CanEditPosts policy (requires can_edit_posts specifically)
```

---

# Video 12 — Policy-Based Authorization in API: Custom Requirements & Handlers

## Theory & Definitions

### What Is Policy-Based Authorization?

Policy-based authorization is a flexible authorization model where you define policies (rules) that specify what claims, roles, or custom logic are required to access a resource. Instead of hardcoding authorization logic in controllers, you define policies and apply them with `[Authorize(Policy = "PolicyName")]`.

Policies are registered in `Program.cs` (or `Startup.cs`) and consist of one or more requirements. Each requirement is checked by a handler that decides if the requirement is met.

### The Policy Architecture

```
[Authorize(Policy = "CanDeleteUsers")]
        ↓
Policy "CanDeleteUsers" registered in Program.cs
        ↓
Requirements: List of IAuthorizationRequirement
        ↓
Handlers: IAuthorizationHandler implementations that evaluate each requirement
        ↓
Result: Succeeded or Failed (access granted or denied)
```

### Requirements vs Handlers

**Requirement** (`IAuthorizationRequirement`):
- A plain class that represents WHAT is required
- No logic — just data
- Example: `MinAgeRequirement` (int MinimumAge), `PermissionRequirement` (string Permission)

**Handler** (`IAuthorizationHandler`):
- A class that implements `HandleRequirementAsync`
- Contains the logic to check if the requirement is met
- Example: `MinAgeHandler` checks if user's age claim >= MinimumAge
- Example: `PermissionHandler` checks if user has the required permission claim

One requirement can have multiple handlers. If ANY handler succeeds, the requirement is met.

### Built-in Requirements

ASP.NET Core provides several built-in requirement types:

| Requirement | Purpose |
|-------------|---------|
| `RolesAuthorizationRequirement` | Requires specific roles (what [Authorize(Roles)] uses internally) |
| `AssertionRequirement` | Requires a custom assertion (Func<AuthorizationHandlerContext, bool>) |
| `NameAuthorizationRequirement` | Requires a specific user name |
| `ClaimsAuthorizationRequirement` | Requires a specific claim type and value |

Most of the time, you'll create custom requirements for your specific needs.

### Creating a Custom Requirement

```csharp
// A requirement is just a class that implements IAuthorizationRequirement.
// It carries data — no logic.

public class PermissionRequirement : IAuthorizationRequirement
{
    public string Permission { get; }

    public PermissionRequirement(string permission)
    {
        Permission = permission;
    }
}
```

That's it. The requirement just holds the permission name. The handler does the work.

### Creating a Custom Handler

```csharp
public class PermissionHandler : AuthorizationHandler<PermissionRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionRequirement requirement)
    {
        // Check if the user has the required permission claim
        if (context.User.HasClaim("permission", requirement.Permission))
        {
            // Grant access — mark the requirement as succeeded
            context.Succeed(requirement);
        }

        // If we don't call context.Succeed, the requirement fails.
        // Access is denied.

        return Task.CompletedTask;
    }
}
```

**Key points:**
- `context.User` is the ClaimsPrincipal (from the JWT)
- `context.Succeed(requirement)` grants access for this requirement
- If no handler calls `Succeed`, the policy fails
- Return `Task.CompletedTask` (handlers are async but often don't need async work)

### Registering Policies and Handlers

```csharp
// In Program.cs
builder.Services.AddAuthorization(options =>
{
    // Policy with a built-in requirement (claim requirement)
    options.AddPolicy("CanEditPosts", policy =>
        policy.RequireClaim("permission", "can_edit_posts"));

    // Policy with a custom requirement + handler
    options.AddPolicy("CanDeleteUsers", policy =>
        policy.AddRequirements(new PermissionRequirement("can_delete_users")));

    // Policy with multiple requirements (AND logic)
    options.AddPolicy("AdminInTenant", policy =>
    {
        policy.RequireRole("Admin");
        policy.RequireClaim("tenant_id");
    });
});

// Register the handler
builder.Services.AddSingleton<IAuthorizationHandler, PermissionHandler>();
```

### Resource-Based Authorization

Resource-based authorization is when the authorization decision depends on the resource being accessed, not just the user's claims.

Example: "A user can edit a post ONLY if they are the author OR an admin."

This requires:
1. A custom requirement that includes the resource
2. A handler that receives the resource and checks authorization
3. Calling `IAuthorizationService.AuthorizeAsync(user, resource, policy)` in the controller

```csharp
// Requirement
public class EditPostRequirement : IAuthorizationRequirement { }

// Handler
public class EditPostHandler : AuthorizationHandler<EditPostRequirement, Post>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        EditPostRequirement requirement,
        Post post)
    {
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (post.AuthorId == userId || context.User.IsInRole("Admin"))
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}

// Controller
[HttpPut("posts/{id}")]
public async Task<IActionResult> EditPost(string id, [FromBody] PostDto dto)
{
    var post = await _postService.GetByIdAsync(id);
    if (post == null) return NotFound();

    var authorizationResult = await _authorizationService.AuthorizeAsync(User, post, "CanEditPost");
    if (!authorizationResult.Succeeded)
    {
        return Forbid();
    }

    // Edit the post...
}
```

Resource-based authorization is more complex but necessary when authorization depends on the resource state.

### "When to Use vs When Not to Use" — Policy-Based Authorization

| Decision | Use it | Don't use it |
|----------|--------|--------------|
| Custom requirements + handlers | You have complex authorization logic that doesn't fit claims/roles | Simple role/claim checks are sufficient |
| Resource-based authorization | Authorization depends on the resource (owner check, etc.) | Authorization is purely user-based (roles/claims are enough) |
| Multiple requirements per policy | You need AND logic across different conditions | Single requirement is sufficient |
| Built-in policies (RequireRole, RequireClaim) | Standard role/claim checks | You need custom logic beyond built-in requirements |
| Assertion requirements | Simple custom logic (one-liner) | Complex logic that needs a full handler |

### Key Insight: Policies Decouple Authorization from Controllers

With policy-based authorization, controllers don't contain authorization logic. They just declare `[Authorize(Policy = "CanDeleteUsers")]`. The policy definition (in Program.cs) and the handler (a separate class) contain the logic. This makes controllers cleaner and authorization more testable.

---

## 🎬 Video Recording Notes

**Opening (say this):**
> \"Policy-based authorization is the most flexible authorization model in ASP.NET Core. Instead of hardcoding checks in your controllers, you define policies — rules that specify what's required. Today we'll build custom requirements, custom handlers, register policies, and even do resource-based authorization where access depends on the resource itself.\"

**Show on screen (do this):**
> Create a custom requirement class (PermissionRequirement). Create a handler (PermissionHandler). Register them in Program.cs. Create a controller using [Authorize(Policy)]. Then show resource-based authorization with a Post resource.

**Key points to emphasize (say this):**
> \"A requirement is just data — a plain class with properties. A handler is the logic — it checks if the requirement is met. One requirement can have multiple handlers.\"

> \"Policies are registered in Program.cs, not in controllers. Controllers just reference the policy name. This decouples authorization logic from the controller — cleaner code, easier testing.\"

> \"Resource-based authorization is when access depends on the resource. 'Can edit this post' depends on who owns the post. You can't do this with just claims — you need to check the resource. Use IAuthorizationService.AuthorizeAsync in the controller.\"

> \"Built-in requirements (RequireRole, RequireClaim) cover most common cases. Custom requirements are for when you need something specific — permission checks, age checks, tenant checks, etc.\"

**Analogy (say this):**
> \"Think of a policy like a bouncer's checklist. The bouncer (handler) has a list of requirements (requirement). 'Must be over 21' — that's a requirement. 'Must have a VIP pass' — that's another requirement. The bouncer checks each one. If all pass, you get in. If any fail, you don't.\"

> \"Resource-based authorization is like a locker check. 'Can I open this locker?' depends on whether I own the locker. The bouncer checks not just my ID, but also whether the locker is registered to me. The resource (locker) matters.\"

**Common viewer question:**
> \"When should I use policies vs [Authorize(Roles)]?\" — Use [Authorize(Roles)] for simple role checks. Use policies when you need custom logic, multiple conditions, or resource-based checks. Policies are more flexible but more complex.

> \"Can I use multiple handlers for one requirement?\" — Yes. If ANY handler succeeds, the requirement is met. This is useful for OR logic within a requirement (e.g., 'user can access if they have permission OR if they're an admin').

> \"What's the difference between policy and role-based authorization?\" — Role-based is a subset of policy-based. [Authorize(Roles)] uses a policy internally (RolesAuthorizationRequirement). Policies give you more control — custom requirements, handlers, resource-based checks.

**What to show:**
- Custom requirement class (PermissionRequirement)
- Custom handler class (PermissionHandler)
- Policy registration in Program.cs
- Controller with [Authorize(Policy)] attributes
- Resource-based authorization example (Post owner check)
- Postman tests: access with policy, access without policy

**What to skip:**
- Complex handler chains (multiple handlers with complex interactions) — keep it simple
- Dynamic policy registration (registering policies at runtime) — advanced, not needed for this tutorial
- Authorization middleware customization — beyond scope

---

## Complete Implementation

### File: Requirements/PermissionRequirement.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Requirements/PermissionRequirement.cs
// Video 12 — Custom Permission Requirement
// ─────────────────────────────────────────────────────────────────────────────
// A custom authorization requirement that specifies a permission name.
//
// This is a plain class — no logic, just data.
// The handler (PermissionHandler) contains the logic to check if the
// user has the required permission.
//
// IAuthorizationRequirement is a marker interface — it has no methods.
// Any class that implements it can be used as an authorization requirement.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Write the requirement class
//   - Explain that it's just data — the handler does the work
//   - Show that multiple requirements can be combined in a policy
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;

namespace IdentityApiTutorial.Requirements
{
    // ─────────────────────────────────────────────────────────────────────────────
    // PermissionRequirement — requires a specific permission claim.
    //
    // This requirement specifies that the user must have a claim with
    // type "permission" and the specified value.
    //
    // Example: new PermissionRequirement("can_delete_users")
    //   → User must have claim("permission", "can_delete_users")
    //
    // The handler (PermissionHandler) checks this.
    // ─────────────────────────────────────────────────────────────────────────────
    public class PermissionRequirement : IAuthorizationRequirement
    {
        // ─────────────────────────────────────────────────────────────────────────
        // Permission — the name of the permission required.
        //
        // This is the claim value that the handler checks for.
        // Example: "can_edit_posts", "can_delete_users", "can_manage_roles"
        // ─────────────────────────────────────────────────────────────────────────
        public string Permission { get; }

        // ─────────────────────────────────────────────────────────────────────────
        // Constructor — sets the required permission.
        // ─────────────────────────────────────────────────────────────────────────
        public PermissionRequirement(string permission)
        {
            Permission = permission;
        }
    }
}
```

### File: Requirements/AdminRequirement.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Requirements/AdminRequirement.cs
// Video 12 — Custom Admin Requirement (example)
// ─────────────────────────────────────────────────────────────────────────────
// This requirement checks if the user is an Admin.
// It's a simple example — in practice, you'd use RequireRole("Admin") instead.
//
// We include it to demonstrate that custom requirements can be simple
// or complex, depending on your needs.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Write the requirement
//   - Show the handler
//   - Explain that this is equivalent to RequireRole("Admin") but custom
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;

namespace IdentityApiTutorial.Requirements
{
    // ─────────────────────────────────────────────────────────────────────────────
    // AdminRequirement — requires the user to be an Admin.
    //
    // This is a simple requirement that checks for the "Admin" role claim.
    // In practice, you'd use the built-in RequireRole("Admin") instead.
    // But this shows the pattern for custom requirements.
    // ─────────────────────────────────────────────────────────────────────────────
    public class AdminRequirement : IAuthorizationRequirement
    {
        // No properties needed — this requirement just checks for Admin role.
        // If you needed to customize (e.g., specific admin levels), you'd add properties.
    }
}
```

### File: Requirements/MinAgeRequirement.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Requirements/MinAgeRequirement.cs
// Video 12 — Custom Minimum Age Requirement (example)
// ─────────────────────────────────────────────────────────────────────────────
// This requirement checks if the user meets a minimum age.
// It demonstrates a requirement with a numeric property.
//
// The handler checks the user's birthdate claim and calculates age.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Write the requirement with a numeric property
//   - Show the handler that calculates age from birthdate claim
//   - Explain that requirements can carry any data type
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;

namespace IdentityApiTutorial.Requirements
{
    // ─────────────────────────────────────────────────────────────────────────────
    // MinAgeRequirement — requires the user to be at least a certain age.
    //
    // The handler checks the user's birthdate claim (or a custom age claim)
    // and verifies they meet the minimum age.
    //
    // Example: new MinAgeRequirement(18) → user must be 18 or older
    // ─────────────────────────────────────────────────────────────────────────────
    public class MinAgeRequirement : IAuthorizationRequirement
    {
        // ─────────────────────────────────────────────────────────────────────────
        // MinimumAge — the minimum age required (in years).
        // ─────────────────────────────────────────────────────────────────────────
        public int MinimumAge { get; }

        public MinAgeRequirement(int minimumAge)
        {
            MinimumAge = minimumAge;
        }
    }
}
```

### File: Handlers/PermissionHandler.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Handlers/PermissionHandler.cs
// Video 12 — Permission Authorization Handler
// ─────────────────────────────────────────────────────────────────────────────
// This handler evaluates PermissionRequirement.
//
// It checks if the user has a claim with type "permission" and the
// value matching the requirement's Permission property.
//
// If the user has the claim, the requirement is met (context.Succeed).
// If not, the requirement fails (no Succeed call).
//
// IAuthorizationHandler<TRequirement> is a generic interface that tells
// ASP.NET Core this handler handles TRequirement.
//
// You can implement IAuthorizationHandler (non-generic) to handle multiple
// requirement types, but the generic version is simpler for single-requirement
// handlers.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Write the handler
//   - Explain HandleRequirementAsync
//   - Show context.User, context.Succeed
//   - Explain that returning without Succeed means failure
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;
using IdentityApiTutorial.Requirements;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Handlers
{
    // ─────────────────────────────────────────────────────────────────────────────
    // PermissionHandler — handles PermissionRequirement.
    //
    // This handler checks if the user has a "permission" claim with the
    // required value. If yes, it calls context.Succeed(requirement).
    //
    // AuthorizationHandler<PermissionRequirement> tells ASP.NET Core that
    // this handler handles PermissionRequirement specifically.
    //
    // Generic version (AuthorizationHandler<T>) is simpler — you only handle
    // one requirement type. Non-generic (IAuthorizationHandler) lets you handle
    // multiple types but requires more code.
    // ─────────────────────────────────────────────────────────────────────────────
    public class PermissionHandler : AuthorizationHandler<PermissionRequirement>
    {
        // ─────────────────────────────────────────────────────────────────────────
        // HandleRequirementAsync — evaluates the requirement for the current user.
        //
        // Parameters:
        //   context — AuthorizationHandlerContext containing:
        //     - User: The ClaimsPrincipal (from the JWT)
        //     - Requirements: All requirements for this policy
        //     - Succeed(requirement): Mark a requirement as met
        //     - Fail(): Mark the policy as failed (optional — not calling Succeed is enough)
        //   requirement — The PermissionRequirement to evaluate
        //
        // Returns: Task (async, but this handler is synchronous in practice)
        //
        // Logic:
        //   1. Check if the user has a claim with type "permission" and value = requirement.Permission
        //   2. If yes, call context.Succeed(requirement) to grant access
        //   3. If no, don't call Succeed — the requirement fails
        //
        // IMPORTANT: You must call context.Succeed(requirement) to grant access.
        // Not calling it (just returning) means the requirement is not met.
        // ─────────────────────────────────────────────────────────────────────────
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            PermissionRequirement requirement)
        {
            // Check if the user has the required permission claim
            // context.User is the ClaimsPrincipal from the validated JWT
            // HasClaim(type, value) checks for a specific claim type AND value
            if (context.User.HasClaim("permission", requirement.Permission))
            {
                // User has the permission — grant access for this requirement
                context.Succeed(requirement);
            }

            // If we didn't call Succeed, the requirement is not met.
            // The policy may still succeed if it has other requirements that are met
            // (OR logic within a policy — rare, usually policies use AND logic).

            return Task.CompletedTask;
        }
    }
}
```

### File: Handlers/AdminHandler.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Handlers/AdminHandler.cs
// Video 12 — Admin Authorization Handler
// ─────────────────────────────────────────────────────────────────────────────
// This handler evaluates AdminRequirement.
//
// It checks if the user has the "Admin" role claim.
// This is equivalent to RequireRole("Admin") but implemented as a custom handler
// to demonstrate the pattern.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Write the handler
//   - Show that it's similar to PermissionHandler but checks for role
//   - Explain that built-in RequireRole is usually sufficient
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;
using IdentityApiTutorial.Requirements;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Handlers
{
    // ─────────────────────────────────────────────────────────────────────────────
    // AdminHandler — handles AdminRequirement.
    //
    // Checks if the user has the "Admin" role claim.
    // ─────────────────────────────────────────────────────────────────────────────
    public class AdminHandler : AuthorizationHandler<AdminRequirement>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            AdminRequirement requirement)
        {
            // Check if the user has the Admin role
            if (context.User.HasClaim(ClaimTypes.Role, "Admin"))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
```

### File: Handlers/MinAgeHandler.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Handlers/MinAgeHandler.cs
// Video 12 — Minimum Age Authorization Handler
// ─────────────────────────────────────────────────────────────────────────────
// This handler evaluates MinAgeRequirement.
//
// It checks the user's birthdate claim and calculates if they meet
// the minimum age requirement.
//
// The handler looks for a "birthdate" claim (or "date_of_birth")
// and calculates the user's age from it.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Write the handler
//   - Show age calculation from birthdate claim
//   - Explain that handlers can do complex logic, not just claim checks
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;
using IdentityApiTutorial.Requirements;
using System;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Handlers
{
    // ─────────────────────────────────────────────────────────────────────────────
    // MinAgeHandler — handles MinAgeRequirement.
    //
    // Checks if the user's age (from birthdate claim) meets the minimum.
    // ─────────────────────────────────────────────────────────────────────────────
    public class MinAgeHandler : AuthorizationHandler<MinAgeRequirement>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            MinAgeRequirement requirement)
        {
            // Get the user's birthdate from claims
            // Try different claim types for flexibility
            var birthdateClaim = context.User.FindFirst("birthdate")
                ?? context.User.FindFirst("date_of_birth")
                ?? context.User.FindFirst(ClaimTypes.DateOfBirth);

            if (birthdateClaim == null)
            {
                // No birthdate claim — cannot verify age, deny access
                // (alternative: you could allow if no birthdate claim is present,
                // depending on your requirements)
                return Task.CompletedTask;
            }

            // Parse the birthdate
            if (!DateTime.TryParse(birthdateClaim.Value, out var birthdate))
            {
                // Invalid birthdate format — deny access
                return Task.CompletedTask;
            }

            // Calculate age
            var today = DateTime.Today;
            var age = today.Year - birthdate.Year;
            if (birthdate > today.AddYears(-age))
            {
                age--;  // Birthday hasn't occurred yet this year
            }

            // Check if age meets minimum
            if (age >= requirement.MinimumAge)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
```

### Updated Program.cs — Policy Registration

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Program.cs (authorization policy registration)
// Video 12 — Registering policies and handlers
// ─────────────────────────────────────────────────────────────────────────────
//
// Add this to your Program.cs after AddIdentityCore and before Build():
//
//   // Register authorization handlers
//   builder.Services.AddSingleton<IAuthorizationHandler, PermissionHandler>();
//   builder.Services.AddSingleton<IAuthorizationHandler, AdminHandler>();
//   builder.Services.AddSingleton<IAuthorizationHandler, MinAgeHandler>();
//
//   // Configure authorization policies
//   builder.Services.AddAuthorization(options =>
//   {
//       // ─────────────────────────────────────────────────────────────────────────
//       // Built-in claim policy — simplest form
//       //   - RequireClaim(type, values...) — user must have a claim with this type
//       //     and one of the specified values (OR logic within the claim type)
//       // ─────────────────────────────────────────────────────────────────────────
//       options.AddPolicy("CanCreatePosts", policy =>
//           policy.RequireClaim("permission", "can_create_posts"));
//
//       options.AddPolicy("CanEditPosts", policy =>
//           policy.RequireClaim("permission", "can_edit_posts"));
//
//       options.AddPolicy("CanDeletePosts", policy =>
//           policy.RequireClaim("permission", "can_delete_posts"));
//
//       // ─────────────────────────────────────────────────────────────────────────
//       // Custom requirement policy — uses PermissionRequirement + PermissionHandler
//       //   - AddRequirements(requirement) — adds a custom requirement
//       //   - The handler (PermissionHandler) is registered separately
//       // ─────────────────────────────────────────────────────────────────────────
//       options.AddPolicy("CanDeleteUsers", policy =>
//           policy.AddRequirements(new PermissionRequirement("can_delete_users")));
//
//       options.AddPolicy("CanManageRoles", policy =>
//           policy.AddRequirements(new PermissionRequirement("can_manage_roles")));
//
//       // ─────────────────────────────────────────────────────────────────────────
//       // Multiple requirements policy (AND logic)
//       //   - RequireRole + RequireClaim = user must have BOTH
//       //   - Useful for "Admin in specific tenant" scenarios
//       // ─────────────────────────────────────────────────────────────────────────
//       options.AddPolicy("AdminInTenant", policy =>
//       {
//           policy.RequireRole("Admin");
//           policy.RequireClaim("tenant_id");
//       });
//
//       // ─────────────────────────────────────────────────────────────────────────
//       // Assertion policy — inline custom logic
//       //   - RequireAssertion(Func<AuthorizationHandlerContext, bool>) — custom logic
//       //   - Less reusable than a handler, but good for one-off checks
//       // ─────────────────────────────────────────────────────────────────────────
//       options.AddPolicy("HighClearance", policy =>
//           policy.RequireAssertion(context =>
//           {
//               var clearanceClaim = context.User.FindFirst("clearance");
//               if (clearanceClaim == null) return false;
//               var clearance = clearanceClaim.Value.ToLower();
//               return clearance == "high" || clearance == "critical";
//           }));
//
//       // ─────────────────────────────────────────────────────────────────────────
//       // Minimum age policy — uses MinAgeRequirement + MinAgeHandler
//       //   - Useful for age-restricted content
//       // ─────────────────────────────────────────────────────────────────────────
//       options.AddPolicy("AdultContent", policy =>
//           policy.AddRequirements(new MinAgeRequirement(18)));
//   });
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Show the handler registrations (AddSingleton)
//   - Show each policy registration
//   - Explain the different policy types (built-in, custom, assertion, multi-requirement)
//   - Show a controller using these policies
// ─────────────────────────────────────────────────────────────────────────────
```

### File: Controllers/PolicyDemoController.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Controllers/PolicyDemoController.cs
// Video 12 — Policy-Based Authorization Demo Controller
// ─────────────────────────────────────────────────────────────────────────────
// This controller demonstrates various policy-based authorization scenarios.
//
// Endpoints:
//   - GET /api/policy/posts/create — requires "CanCreatePosts" policy
//   - GET /api/policy/posts/edit — requires "CanEditPosts" policy
//   - GET /api/policy/posts/delete — requires "CanDeletePosts" policy
//   - GET /api/policy/users/delete — requires "CanDeleteUsers" policy (custom requirement)
//   - GET /api/policy/roles/manage — requires "CanManageRoles" policy (custom requirement)
//   - GET /api/policy/admin/tenant — requires "AdminInTenant" policy (multiple requirements)
//   - GET /api/policy/clearance/high — requires "HighClearance" policy (assertion)
//   - GET /api/policy/adult — requires "AdultContent" policy (MinAgeRequirement)
//
// All endpoints require authentication ([Authorize] on class).
// Individual endpoints add policy requirements.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Create this controller
//   - Show each [Authorize(Policy)] attribute
//   - Test with different users (different claims)
//   - Show 403 when policy is not met
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.DTOs;
using System.Security.Claims;

namespace IdentityApiTutorial.Controllers
{
    // ─────────────────────────────────────────────────────────────────────────────
    // PolicyDemoController — demonstrates policy-based authorization.
    //
    // Class-level [Authorize] — all endpoints require authentication.
    // Action-level [Authorize(Policy)] — additional policy requirements.
    // ─────────────────────────────────────────────────────────────────────────────
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]   // All endpoints require authentication
    public class PolicyDemoController : ControllerBase
    {
        private readonly ILogger<PolicyDemoController> _logger;

        public PolicyDemoController(ILogger<PolicyDemoController> logger)
        {
            _logger = logger;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // CreatePost — requires "CanCreatePosts" policy.
        //
        // Policy: RequireClaim("permission", "can_create_posts")
        // User must have a "permission" claim with value "can_create_posts".
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("posts/create")]
        [Authorize(Policy = "CanCreatePosts")]
        public IActionResult CanCreatePost()
        {
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "User can create posts.",
                Data = new { User = User.Identity?.Name }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // EditPost — requires "CanEditPosts" policy.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("posts/edit")]
        [Authorize(Policy = "CanEditPosts")]
        public IActionResult CanEditPost()
        {
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "User can edit posts.",
                Data = new { User = User.Identity?.Name }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // DeletePost — requires "CanDeletePosts" policy.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("posts/delete")]
        [Authorize(Policy = "CanDeletePosts")]
        public IActionResult CanDeletePost()
        {
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "User can delete posts.",
                Data = new { User = User.Identity?.Name }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // DeleteUser — requires "CanDeleteUsers" policy.
        //
        // Policy: PermissionRequirement("can_delete_users") + PermissionHandler
        // Custom requirement checked by custom handler.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("users/delete")]
        [Authorize(Policy = "CanDeleteUsers")]
        public IActionResult CanDeleteUser()
        {
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "User can delete other users.",
                Data = new { User = User.Identity?.Name }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // ManageRoles — requires "CanManageRoles" policy.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("roles/manage")]
        [Authorize(Policy = "CanManageRoles")]
        public IActionResult CanManageRoles()
        {
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "User can manage roles.",
                Data = new { User = User.Identity?.Name }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // AdminInTenant — requires "AdminInTenant" policy.
        //
        // Policy: RequireRole("Admin") AND RequireClaim("tenant_id")
        // User must be an Admin AND have a tenant_id claim.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("admin/tenant")]
        [Authorize(Policy = "AdminInTenant")]
        public IActionResult AdminInTenant()
        {
            var tenantId = User.FindFirst("tenant_id")?.Value;

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Admin in a tenant.",
                Data = new { User = User.Identity?.Name, TenantId = tenantId }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // HighClearance — requires "HighClearance" policy.
        //
        // Policy: RequireAssertion — inline custom logic.
        // User must have a "clearance" claim with value "high" or "critical".
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("clearance/high")]
        [Authorize(Policy = "HighClearance")]
        public IActionResult HighClearance()
        {
            var clearance = User.FindFirst("clearance")?.Value;

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "User has high or critical clearance.",
                Data = new { User = User.Identity?.Name, Clearance = clearance }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // AdultContent — requires "AdultContent" policy.
        //
        // Policy: MinAgeRequirement(18) + MinAgeHandler
        // User must have a birthdate claim showing they are 18 or older.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("adult")]
        [Authorize(Policy = "AdultContent")]
        public IActionResult AdultContent()
        {
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "User is 18 or older.",
                Data = new { User = User.Identity?.Name }
            });
        }
    }
}
```

### File: Controllers/ResourceBasedAuthController.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Controllers/ResourceBasedAuthController.cs
// Video 12 — Resource-Based Authorization Demo
// ─────────────────────────────────────────────────────────────────────────────
// This controller demonstrates resource-based authorization.
//
// Resource-based authorization is when access depends on the resource,
// not just the user's claims. Example: "User can edit a post only if
// they are the author OR an admin."
//
// Implementation:
//   1. Create a requirement (EditPostRequirement)
//   2. Create a handler that takes the resource (EditPostHandler)
//   3. In the controller, call IAuthorizationService.AuthorizeAsync
//      with the user, resource, and policy name
//   4. If authorization fails, return Forbid()
//
// DI Dependencies:
//   IAuthorizationService — used to authorize against a resource
//   ILogger — logging
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Create the requirement and handler for resource-based auth
//   - Register them in Program.cs
//   - Create this controller
//   - Show that authorization depends on the resource (post owner)
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.DTOs;
using IdentityApiTutorial.Requirements;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Controllers
{
    // ─────────────────────────────────────────────────────────────────────────────
    // ResourceBasedAuthController — demonstrates resource-based authorization.
    //
    // For this demo, we use a simple in-memory "post" store.
    // In a real application, you'd use a database service.
    //
    // Endpoints:
    //   - PUT /api/resource/posts/{id} — edit a post (owner or admin only)
    //   - DELETE /api/resource/posts/{id} — delete a post (owner or admin only)
    //
    // Authorization:
    //   - User can edit/delete their own posts
    //   - Admin can edit/delete any post
    //   - Other users cannot edit/delete posts they don't own
    // ─────────────────────────────────────────────────────────────────────────────
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class ResourceBasedAuthController : ControllerBase
    {
        private readonly IAuthorizationService _authorizationService;
        private readonly ILogger<ResourceBasedAuthController> _logger;

        // In-memory post store for demo purposes
        // In a real app, this would be a database service
        private static readonly List<Post> _posts = new List<Post>
        {
            new Post { Id = "1", Title = "First Post", AuthorId = "user-1" },
            new Post { Id = "2", Title = "Second Post", AuthorId = "user-2" },
            new Post { Id = "3", Title = "Admin Post", AuthorId = "admin-1" }
        };

        public ResourceBasedAuthController(
            IAuthorizationService authorizationService,
            ILogger<ResourceBasedAuthController> logger)
        {
            _authorizationService = authorizationService;
            _logger = logger;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // EditPost — edits a post (resource-based authorization).
        //
        // The user can edit the post if:
        //   - They are the author (post.AuthorId == user ID), OR
        //   - They are an Admin
        //
        // We use IAuthorizationService.AuthorizeAsync to check this.
        // The handler (EditPostHandler) evaluates the policy with the resource.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPut("posts/{id}")]
        public async Task<IActionResult> EditPost(string id, [FromBody] PostDto dto)
        {
            // Find the post
            var post = _posts.FirstOrDefault(p => p.Id == id);
            if (post == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Post not found.",
                    Errors = new List<string> { $"No post found with ID '{id}'." }
                });
            }

            // Authorize: can this user edit this post?
            var authorizationResult = await _authorizationService.AuthorizeAsync(
                User, post, "CanEditPost");

            if (!authorizationResult.Succeeded)
            {
                _logger.LogWarning("User {UserId} failed to authorize for editing post {PostId}",
                    User.Identity?.Name, id);

                return Forbid(new ApiResponse<object>
                {
                    Success = false,
                    Message = "You are not authorized to edit this post.",
                    Errors = new List<string> { "You can only edit your own posts, or you must be an Admin." }
                });
            }

            // Authorization succeeded — update the post
            post.Title = dto.Title;
            _logger.LogInformation("Post {PostId} edited by {UserId}", id, User.Identity?.Name);

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Post edited successfully.",
                Data = new { PostId = id, Title = post.Title }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // DeletePost — deletes a post (resource-based authorization).
        //
        // Same authorization logic as EditPost: owner or admin.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpDelete("posts/{id}")]
        public async Task<IActionResult> DeletePost(string id)
        {
            var post = _posts.FirstOrDefault(p => p.Id == id);
            if (post == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Post not found.",
                    Errors = new List<string> { $"No post found with ID '{id}'." }
                });
            }

            var authorizationResult = await _authorizationService.AuthorizeAsync(
                User, post, "CanDeletePost");

            if (!authorizationResult.Succeeded)
            {
                _logger.LogWarning("User {UserId} failed to authorize for deleting post {PostId}",
                    User.Identity?.Name, id);

                return Forbid(new ApiResponse<object>
                {
                    Success = false,
                    Message = "You are not authorized to delete this post.",
                    Errors = new List<string> { "You can only delete your own posts, or you must be an Admin." }
                });
            }

            _posts.Remove(post);
            _logger.LogInformation("Post {PostId} deleted by {UserId}", id, User.Identity?.Name);

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Post deleted successfully.",
                Data = new { PostId = id }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // GetPosts — returns all posts (read-only, no authorization beyond authentication).
        //
        // Any authenticated user can view posts.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("posts")]
        public IActionResult GetPosts()
        {
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Posts retrieved.",
                Data = _posts.Select(p => new { p.Id, p.Title, p.AuthorId }).ToList()
            });
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Post — simple post model for resource-based authorization demo.
    // ─────────────────────────────────────────────────────────────────────────────
    public class Post
    {
        public string Id { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string AuthorId { get; set; } = string.Empty;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PostDto — DTO for post operations.
    // ─────────────────────────────────────────────────────────────────────────────
    public class PostDto
    {
        public string Title { get; set; } = string.Empty;
    }
}
```

### Resource-Based Authorization Handler

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Handlers/EditPostHandler.cs
// Video 12 — Resource-Based Authorization Handler for Posts
// ─────────────────────────────────────────────────────────────────────────────
// This handler evaluates whether a user can edit/delete a post.
//
// It handles EditPostRequirement for the Post resource type.
//
// The handler checks:
//   1. Is the user the author of the post? (post.AuthorId == user ID)
//   2. Is the user an Admin? (role claim = "Admin")
//
// If either is true, the requirement is met.
//
// IAuthorizationHandler<TRequirement, TResource> is the generic interface
// for resource-based handlers. TRequirement is the requirement type,
// TResource is the resource type.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Write the handler
//   - Explain the resource parameter (Post post)
//   - Show the handler in Program.cs registration
//   - Show the controller using IAuthorizationService
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;
using IdentityApiTutorial.Requirements;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Handlers
{
    // ─────────────────────────────────────────────────────────────────────────────
    // EditPostHandler — handles EditPostRequirement for Post resources.
    //
    // AuthorizationHandler<EditPostRequirement, Post> tells ASP.NET Core that
    // this handler handles EditPostRequirement when the resource is a Post.
    //
    // The HandleRequirementAsync signature includes the resource parameter:
    //   Task HandleRequirementAsync(AuthorizationHandlerContext context,
    //                                EditPostRequirement requirement,
    //                                Post resource)
    //
    // This is different from non-resource handlers — they don't have the
    // resource parameter.
    // ─────────────────────────────────────────────────────────────────────────────
    public class EditPostHandler : AuthorizationHandler<EditPostRequirement, Post>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            EditPostRequirement requirement,
            Post post)
        {
            // Get the user's ID from the claims
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            // Check if the user is the author of the post
            if (post.AuthorId == userId)
            {
                // User is the author — grant access
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            // Check if the user is an Admin
            if (context.User.HasClaim(ClaimTypes.Role, "Admin"))
            {
                // User is an Admin — grant access (admins can edit any post)
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            // User is neither the author nor an Admin — don't call Succeed
            // The requirement fails, access is denied

            return Task.CompletedTask;
        }
    }
}
```

### EditPostRequirement

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Requirements/EditPostRequirement.cs
// Video 12 — Resource-Based Edit Post Requirement
// ─────────────────────────────────────────────────────────────────────────────
// A requirement for editing posts. This is a marker requirement —
// it doesn't carry data. The handler (EditPostHandler) contains all
// the logic, using the resource (Post) passed to it.
//
// For resource-based authorization, the requirement is often simple
// because the resource provides the context.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Write the requirement (simple, no properties)
//   - Show the handler that uses the resource
//   - Explain that resource-based requirements are often marker-only
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;

namespace IdentityApiTutorial.Requirements
{
    // ─────────────────────────────────────────────────────────────────────────────
    // EditPostRequirement — requirement for editing a post.
    //
    // This is a marker requirement — no properties needed.
    // The handler uses the resource (Post) to determine authorization.
    // ─────────────────────────────────────────────────────────────────────────────
    public class EditPostRequirement : IAuthorizationRequirement
    {
        // No properties — the handler uses the resource for context.
    }
}
```

---

## Postman / Swagger Tests

**Test 1 — Policy-Based Access (Permission Policy):**

```
Test 1a — User with can_create_posts:
ENDPOINT: GET https://localhost:7001/api/policy/posts/create
AUTH: Bearer token (User — has can_create_posts claim)
EXPECTED: 200 OK

Test 1b — User without can_create_posts:
ENDPOINT: GET https://localhost:7001/api/policy/posts/create
AUTH: Bearer token (User — does NOT have can_create_posts claim)
EXPECTED: 403 Forbidden
```

**Test 2 — Custom Requirement Policy (PermissionHandler):**

```
Test 2a — Admin with can_delete_users:
ENDPOINT: GET https://localhost:7001/api/policy/users/delete
AUTH: Bearer token (Admin — has can_delete_users claim)
EXPECTED: 200 OK

Test 2b — User without can_delete_users:
ENDPOINT: GET https://localhost:7001/api/policy/users/delete
AUTH: Bearer token (User — does NOT have can_delete_users claim)
EXPECTED: 403 Forbidden
```

**Test 3 — Multiple Requirements Policy (AdminInTenant):**

```
Test 3a — Admin with tenant_id:
ENDPOINT: GET https://localhost:7001/api/policy/admin/tenant
AUTH: Bearer token (Admin + tenant_id claim)
EXPECTED: 200 OK

Test 3b — Admin without tenant_id:
ENDPOINT: GET https://localhost:7001/api/policy/admin/tenant
AUTH: Bearer token (Admin — no tenant_id claim)
EXPECTED: 403 Forbidden — missing tenant_id

Test 3c — User with tenant_id (not Admin):
ENDPOINT: GET https://localhost:7001/api/policy/admin/tenant
AUTH: Bearer token (User + tenant_id claim — not Admin)
EXPECTED: 403 Forbidden — not an Admin
```

**Test 4 — Assertion Policy (HighClearance):**

```
Test 4a — High clearance:
ENDPOINT: GET https://localhost:7001/api/policy/clearance/high
AUTH: Bearer token (clearance claim = "high")
EXPECTED: 200 OK

Test 4b — Critical clearance:
ENDPOINT: GET https://localhost:7001/api/policy/clearance/high
AUTH: Bearer token (clearance claim = "critical")
EXPECTED: 200 OK

Test 4c — Low clearance:
ENDPOINT: GET https://localhost:7001/api/policy/clearance/high
AUTH: Bearer token (clearance claim = "low")
EXPECTED: 403 Forbidden

Test 4d — No clearance claim:
ENDPOINT: GET https://localhost:7001/api/policy/clearance/high
AUTH: Bearer token (no clearance claim)
EXPECTED: 403 Forbidden
```

**Test 5 — Resource-Based Authorization:**

```
SETUP: Posts in memory:
  - Post 1: AuthorId = "user-1"
  - Post 2: AuthorId = "user-2"
  - Post 3: AuthorId = "admin-1"

Test 5a — User edits their own post:
ENDPOINT: PUT https://localhost:7001/api/resource/posts/1
AUTH: Bearer token (User with ID "user-1")
BODY: { "title": "Updated Title" }
EXPECTED: 200 OK — user is the author

Test 5b — User edits another user's post:
ENDPOINT: PUT https://localhost:7001/api/resource/posts/2
AUTH: Bearer token (User with ID "user-1")
EXPECTED: 403 Forbidden — user is not the author and not Admin

Test 5c — Admin edits any post:
ENDPOINT: PUT https://localhost:7001/api/resource/posts/2
AUTH: Bearer token (Admin)
EXPECTED: 200 OK — Admin can edit any post

Test 5d — User deletes their own post:
ENDPOINT: DELETE https://localhost:7001/api/resource/posts/1
AUTH: Bearer token (User with ID "user-1")
EXPECTED: 200 OK

Test 5e — User deletes another user's post:
ENDPOINT: DELETE https://localhost:7001/api/resource/posts/2
AUTH: Bearer token (User with ID "user-1")
EXPECTED: 403 Forbidden
```

**Test 6 — Minimum Age Policy:**

```
Test 6a — User 21 years old (meets minimum 18):
ENDPOINT: GET https://localhost:7001/api/policy/adult
AUTH: Bearer token (birthdate claim = "1995-01-01")
EXPECTED: 200 OK

Test 6b — User 16 years old (does NOT meet minimum 18):
ENDPOINT: GET https://localhost:7001/api/policy/adult
AUTH: Bearer token (birthdate claim = "2008-01-01")
EXPECTED: 403 Forbidden

Test 6c — User with no birthdate claim:
ENDPOINT: GET https://localhost:7001/api/policy/adult
AUTH: Bearer token (no birthdate claim)
EXPECTED: 403 Forbidden (handler denies when no birthdate claim)
```

---

# Video 13 — Password Policies & Custom Validation in API

## Theory & Definitions

### What Are Password Policies?

Password policies are the rules that determine whether a password is acceptable. Identity provides a built-in `PasswordOptions` class with configurable thresholds, and you can extend it with custom validators for more complex rules.

### PasswordOptions — Built-in Configuration

| Property | Default | Purpose |
|----------|---------|---------|
| `RequireDigit` | false | Password must contain at least one digit (0-9) |
| `RequiredLength` | 6 | Minimum password length |
| `RequireNonAlphanumeric` | false | Password must contain at least one non-alphanumeric character (!, @, #, etc.) |
| `RequireUppercase` | false | Password must contain at least one uppercase letter |
| `RequireLowercase` | false | Password must contain at least one lowercase letter |
| `MaxRepeatedChars` | 0 (disabled) | Maximum number of times a single character can repeat consecutively |

These are configured in Program.cs when setting up Identity:

```csharp
builder.Services.AddIdentityCore<ApplicationUser>(options =>
{
    options.Password.RequiredLength = 8;
    options.Password.RequireDigit = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.MaxRepeatedChars = 3;
})
.AddEntityFrameworkStores<IdentityDbContext>()
.AddRoles<ApplicationRole>();
```

### How Identity Validates Passwords

When you call `UserManager.CreateAsync(user, password)` or `UserManager.UpdateAsync(user)` (with a new password), Identity runs the password through the configured validators:

1. **Length check** — `RequiredLength` minimum
2. **Digit check** — `RequireDigit` requires at least one digit
3. **Uppercase check** — `RequireUppercase` requires at least one uppercase letter
4. **Lowercase check** — `RequireLowercase` requires at least one lowercase letter
5. **Non-alphanumeric check** — `RequireNonAlphanumeric` requires at least one special character
6. **Custom validators** — any `IPasswordValidator` implementations

If any check fails, `CreateAsync` returns an `IdentityResult` with errors. The errors are:
- "Passwords must be at least {RequiredLength} characters."]
- "Passwords must contain at least one digit ('0'-'9')."\]"
- "Passwords must contain at least one uppercase ('A'-'Z')."\]"
- "Passwords must contain at least one lowercase ('a'-'z')."\]"
- "Passwords must contain at least one non alphanumeric character."\]"

### Custom Password Validator — IPasswordValidator

For rules beyond `PasswordOptions`, you implement `IPasswordValidator<TUser>`:

```csharp
public class CustomPasswordValidator : IPasswordValidator<ApplicationUser>
{
    public Task<IdentityResult> ValidateAsync(UserManager<ApplicationUser> manager, string password)
    {
        var errors = new List<string>();

        // Custom rule: password cannot contain the user's email
        // (This requires the user to be passed — but ValidateAsync only gets manager and password,
        // so you'd use a different approach for user-specific validation)

        // Custom rule: password cannot contain common patterns
        if (password.Contains("123") || password.Contains("abc") || password.Contains("qwerty"))
        {
            errors.Add("Password contains common patterns that are easily guessed.");
        }

        // Custom rule: password must not be in a blacklist
        if (CommonPasswords.IsCommon(password))
        {
            errors.Add("Password is too common. Please choose a stronger password.");
        }

        if (errors.Any())
        {
            return Task.FromResult(IdentityResult.Failed(errors.Select(e => new IdentityError { Description = e }).ToArray()));
        }

        return Task.FromResult(IdentityResult.Success);
    }
}
```

Register in Program.cs:
```csharp
builder.Services.AddIdentityCore<ApplicationUser>(options =>
{
    // ... PasswordOptions configuration
})
.AddEntityFrameworkStores<IdentityDbContext>()
.AddRoles<ApplicationRole>()
.AddPasswordValidator<CustomPasswordValidator>();  // Add custom validator
```

### Password Strength Check Endpoint

A password strength check endpoint lets clients test a password BEFORE registration. This improves UX — the user gets immediate feedback instead of waiting for registration to fail.

```csharp
[HttpPost("check-password-strength")]
public IActionResult CheckPasswordStrength([FromBody] PasswordCheckRequest request)
{
    var score = CalculatePasswordStrength(request.Password);
    return Ok(new PasswordStrengthResponse
    {
        Score = score,
        Message = GetStrengthMessage(score),
        Suggestions = GetStrengthSuggestions(request.Password)
    });
}
```

### "When to Use vs When Not to Use" — Password Policies

| Decision | Use it | Don't use it |
|----------|--------|--------------|
| Strict password policies (8+ chars, digit, uppercase, etc.) | For production APIs with security requirements | For low-security internal tools (too much friction) |
| Custom password validators | For domain-specific rules (no email in password, blacklist check) | For simple rules that PasswordOptions covers |
| Password strength endpoint | For good UX — let users test before registering | For APIs where registration is rare (not worth the endpoint) |
| Password history (can't reuse last N passwords) | For high-security applications | For simple apps (complexity without much benefit) |
| MaxRepeatedChars | To prevent "aaaaaaaa" type passwords | If you have other strong policies (redundant) |
| Custom password hasher | For compliance requirements (specific algorithms) | For standard apps — Identity's PBKDF2 is fine |
| Storing password hints/reminders | NEVER — security risk | N/A |
| Sending passwords in email | NEVER — security risk | N/A |

### Key Insight: Password Security Is Layered

Good password security is not one thing — it's layers:
1. **Password policy** — enforces minimum strength at creation time
2. **Password hashing** — protects stored passwords (PBKDF2 with salt)
3. **Lockout** — prevents brute force (Video 14)
4. **2FA** — adds a second factor (Video 15)
5. **Password reset** — allows recovery without admin help (Video 17)
6. **Security stamp** — invalidates old passwords/tokens (Video 14)

Each layer addresses a different threat. Password policy alone is not enough — it's one layer in a defense-in-depth strategy.

---

## 🎬 Video Recording Notes

**Opening (say this):**
> \"Passwords are the first line of defense. Today we configure password policies — minimum length, digit requirements, uppercase, lowercase, special characters. We'll also build a custom validator for rules that PasswordOptions can't handle, and create a password strength check endpoint so users can test their password before registering.\"

**Show on screen (do this):**
> Show PasswordOptions configuration in Program.cs. Show the CustomPasswordValidator. Show the password strength endpoint. Demonstrate with Postman: weak password rejected, strong password accepted, strength check returns score.

**Key points to emphasize (say this):**
> \"PasswordOptions configures the built-in rules. These run automatically when you call CreateAsync or UpdateAsync. You don't write validation code — Identity does it.\"

> \"Custom validators (IPasswordValidator) are for rules that PasswordOptions can't express. Like 'password cannot contain your email' or 'password is not in a common passwords list'. They run alongside the built-in validators.\"

> \"A password strength endpoint is a UX feature, not a security feature. It helps users choose better passwords BEFORE they hit register. The actual enforcement still happens in PasswordOptions — the strength endpoint is just feedback.\"

> \"Never store passwords in plaintext. Never send passwords in email. Never log passwords. Identity hashes passwords with PBKDF2 by default — that's what CreateAsync does internally.\"

**Analogy (say this):**
> \"Password policy is like a bouncer at a club. The bouncer checks your ID — is it valid? Are you old enough? You can't get in without meeting the requirements. PasswordOptions is the bouncer — it checks length, digits, uppercase, etc. Custom validators are like additional bouncers with special checks — 'no sneakers allowed' or 'no red shirts'.\"

**Common viewer question:**
> \"What's a good password policy?\" — Minimum 8 characters, require at least one digit, one uppercase, one lowercase, one special character. This is the NIST recommendation for most applications. For high-security, go to 12+ characters.

> \"Should I use a password strength meter?\" — Yes, for UX. It helps users choose better passwords. But the strength meter is advisory — the actual policy enforcement is what matters.

> \"Can I use a different password hasher?\" — Yes, implement IPasswordHasher and register it. But the default PBKDF2 is secure and well-tested. Only change it if you have a specific requirement.

**What to show:**
- PasswordOptions in Program.cs
- CustomPasswordValidator implementation
- Password strength check endpoint
- Postman tests: weak password fails registration, strong password succeeds, strength check returns score
- Database verification: PasswordHash is a hashed value, not plaintext

**What to skip:**
- Password history implementation (complex, beyond scope)
- Different hashing algorithms (bcrypt, argon2) — mention as alternatives
- Passwordless authentication — different topic, not Identity

---

## Complete Implementation

### File: Program.cs — PasswordOptions Configuration

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Program.cs (password options configuration)
// Video 13 — Password policy configuration
// ─────────────────────────────────────────────────────────────────────────────
//
// Add this to your AddIdentityCore configuration:
//
//   builder.Services.AddIdentityCore<ApplicationUser>(options =>
//   {
//       // ─────────────────────────────────────────────────────────────────────────
//       // Password settings — configure password requirements
//       // ─────────────────────────────────────────────────────────────────────────
//       options.Password.RequireDigit = true;              // Must contain 0-9
//       options.Password.RequiredLength = 8;               // Minimum 8 characters
//       options.Password.RequireNonAlphanumeric = true;    // Must contain !, @, #, etc.
//       options.Password.RequireUppercase = true;          // Must contain A-Z
//       options.Password.RequireLowercase = true;          // Must contain a-z
//       options.Password.MaxRepeatedChars = 3;             // No more than 3 identical consecutive chars
//   })
//   .AddEntityFrameworkStores<IdentityDbContext>()
//   .AddRoles<ApplicationRole>()
//   .AddPasswordValidator<CustomPasswordValidator>();  // Custom validator (shown below)
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Show the PasswordOptions configuration
//   - Explain each setting
//   - Show that these run automatically on CreateAsync
// ─────────────────────────────────────────────────────────────────────────────
```

### File: Validators/CustomPasswordValidator.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Validators/CustomPasswordValidator.cs
// Video 13 — Custom Password Validator
// ─────────────────────────────────────────────────────────────────────────────
// This custom validator implements IPasswordValidator<ApplicationUser>.
// It runs alongside the built-in PasswordOptions validation.
//
// IPasswordValidator<TUser> has one method:
//   Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, string password)
//
// Note: This method does NOT receive the user object. It only receives
// the manager and the password. This means user-specific validation
// (like "password cannot contain email") requires a different approach —
// you'd validate that in the controller before calling CreateAsync.
//
// For this tutorial, we implement general password rules that don't
// depend on the user.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Write the validator class
//   - Explain each custom rule
//   - Show registration in Program.cs
//   - Test with passwords that pass/fail the custom rules
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Validators
{
    // ─────────────────────────────────────────────────────────────────────────────
    // CustomPasswordValidator — custom password validation rules.
    //
    // Implements IPasswordValidator<ApplicationUser> so it runs automatically
    // when Identity validates passwords (CreateAsync, UpdateAsync).
    //
    // This validator runs AFTER the built-in PasswordOptions validation.
    // If PasswordOptions fails, this validator may not run (Identity short-circuits
    // on the first failure — actually, all validators run and all errors are collected).
    //
    // Design note: This validator checks general password quality rules.
    // User-specific rules (like "no email in password") would be checked in the
    // controller, not here, because IPasswordValidator doesn't receive the user.
    // ─────────────────────────────────────────────────────────────────────────────
    public class CustomPasswordValidator : IPasswordValidator<ApplicationUser>
    {
        // ─────────────────────────────────────────────────────────────────────────
        // ValidateAsync — validates a password against custom rules.
        //
        // Parameters:
        //   manager — UserManager instance (not used in this validator, but available)
        //   password — the password to validate (plaintext)
        //
        // Returns: Task<IdentityResult> — Success if password passes all rules,
        //   Failed with errors if any rule fails.
        //
        // Rules implemented:
        //   1. Password must not contain common sequential patterns (123, abc, qwerty)
        //   2. Password must not be in a list of commonly used passwords
        //   3. Password must not contain the word "password" (case-insensitive)
        // ─────────────────────────────────────────────────────────────────────────
        public Task<IdentityResult> ValidateAsync(UserManager<ApplicationUser> manager, string password)
        {
            var errors = new List<string>();

            // ─────────────────────────────────────────────────────────────────────────
            // Rule 1: Check for common sequential patterns.
            //
            // These are easily guessed and indicate a weak password.
            // We check for substrings — if the password contains "123", "abc",
            // "qwerty", etc., it fails this rule.
            // ─────────────────────────────────────────────────────────────────────────
            var commonPatterns = new[] { "123", "abc", "qwerty", "letmein", "admin", "login" };

            foreach (var pattern in commonPatterns)
            {
                if (password.ToLowerInvariant().Contains(pattern))
                {
                    errors.Add($"Password contains a common pattern ('{pattern}'). Please choose a stronger password.");
                    break;  // One pattern match is enough to fail this rule
                }
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Rule 2: Check against common passwords list.
            //
            // This is a small sample list for demonstration. In production, you'd
            // use a comprehensive list (e.g., the top 10,000 commonly used passwords).
            //
            // The list is stored as a HashSet for O(1) lookup.
            // ─────────────────────────────────────────────────────────────────────────
            var commonPasswords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "password", "123456", "12345678", "qwerty", "abc123",
                "monkey", "master", "dragon", "football", "baseball",
                "iloveyou", "trustno1", "sunshine", "princess", "welcome"
            };

            if (commonPasswords.Contains(password))
            {
                errors.Add("Password is too common. Please choose a stronger, less predictable password.");
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Rule 3: Check if password contains the word "password".
            //
            // Case-insensitive check. "Password123" fails this rule even though
            // it has uppercase, digits, and length — it contains the word "password".
            // ─────────────────────────────────────────────────────────────────────────
            if (password.ToLowerInvariant().Contains("password"))
            {
                errors.Add("Password contains the word 'password'. This is easily guessed.");
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Return the result.
            //
            // If errors is empty → IdentityResult.Success
            // If errors has items → IdentityResult.Failed with IdentityError objects
            //
            // IdentityError has Code and Description properties.
            // The Description is what gets returned to the client.
            // ─────────────────────────────────────────────────────────────────────────
            if (errors.Any())
            {
                var identityErrors = errors.Select(e => new IdentityError
                {
                    Code = "CustomPasswordValidation",
                    Description = e
                }).ToArray();

                return Task.FromResult(IdentityResult.Failed(identityErrors));
            }

            return Task.FromResult(IdentityResult.Success);
        }
    }
}
```

### File: DTOs/PasswordCheckRequest.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: DTOs/PasswordCheckRequest.cs
// Video 13 — Password strength check request DTO
// ─────────────────────────────────────────────────────────────────────────────
// Simple DTO for the password strength check endpoint.
// ─────────────────────────────────────────────────────────────────────────────

using System.ComponentModel.DataAnnotations;

namespace IdentityApiTutorial.DTOs
{
    public class PasswordCheckRequest
    {
        [Required]
        public string Password { get; set; } = string.Empty;
    }
}
```

### File: DTOs/PasswordStrengthResponse.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: DTOs/PasswordStrengthResponse.cs
// Video 13 — Password strength check response DTO
// ─────────────────────────────────────────────────────────────────────────────
// Returns a score (0-4), a message, and suggestions for improvement.
// ─────────────────────────────────────────────────────────────────────────────

namespace IdentityApiTutorial.DTOs
{
    public class PasswordStrengthResponse
    {
        public int Score { get; set; }  // 0-4 (0 = very weak, 4 = very strong)
        public string Message { get; set; } = string.Empty;
        public List<string> Suggestions { get; set; } = new List<string>();
    }
}
```

### File: Controllers/PasswordController.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Controllers/PasswordController.cs
// Video 13 — Password Policy & Strength Check Endpoints
// ─────────────────────────────────────────────────────────────────────────────
// Endpoints:
//   - POST /api/password/check-strength — check password strength (public)
//   - GET /api/password/policy — get current password policy requirements (public)
//
// Both endpoints are public (no authentication required) because users
// need to check their password BEFORE registering.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Create this controller
//   - Show the password strength calculation logic
//   - Show the policy endpoint returning current PasswordOptions
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.DTOs;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace IdentityApiTutorial.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class PasswordController : ControllerBase
    {
        private readonly ILogger<PasswordController> _logger;

        public PasswordController(ILogger<PasswordController> logger)
        {
            _logger = logger;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // CheckStrength — evaluates password strength and returns a score.
        //
        // POST /api/password/check-strength
        // Body: PasswordCheckRequest (password)
        // Response: PasswordStrengthResponse (score, message, suggestions)
        //
        // Score calculation (0-4):
        //   Score 0: Very weak (less than 8 chars OR common password)
        //   Score 1: Weak (8+ chars but only lowercase or only digits)
        //   Score 2: Fair (8+ chars, mixed case or digits + letters)
        //   Score 3: Strong (8+ chars, mixed case + digits)
        //   Score 4: Very strong (8+ chars, mixed case + digits + special chars)
        //
        // This is a heuristic — not a definitive measure of password strength.
        // Real password strength depends on entropy, which is hard to calculate
        // without knowing the threat model (dictionary attacks, brute force, etc.).
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("check-strength")]
        public IActionResult CheckPasswordStrength([FromBody] PasswordCheckRequest request)
        {
            if (string.IsNullOrEmpty(request.Password))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Password is required.",
                    Errors = new List<string> { "Password field cannot be empty." }
                });
            }

            var score = CalculatePasswordStrength(request.Password);
            var response = new PasswordStrengthResponse
            {
                Score = score,
                Message = GetStrengthMessage(score),
                Suggestions = GetStrengthSuggestions(request.Password)
            };

            _logger.LogDebug("Password strength check: score={Score}", score);

            return Ok(new ApiResponse<PasswordStrengthResponse>
            {
                Success = true,
                Message = "Password strength evaluated.",
                Data = response
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // GetPolicy — returns the current password policy requirements.
        //
        // GET /api/password/policy
        // Response: PasswordPolicyResponse (the current PasswordOptions)
        //
        // This is useful for clients — they can fetch the policy and show
        // the requirements to the user BEFORE they enter a password.
        //
        // In a real application, these values would come from configuration
        // (IOptions<PasswordOptions>), not hardcoded.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("policy")]
        public IActionResult GetPasswordPolicy()
        {
            // In a real app, inject IOptions<IdentityOptions> and read
            // options.Password.* from there. For this tutorial, we return
            // the values we configured in Program.cs.
            var response = new PasswordPolicyResponse
            {
                RequireDigit = true,
                RequiredLength = 8,
                RequireNonAlphanumeric = true,
                RequireUppercase = true,
                RequireLowercase = true,
                MaxRepeatedChars = 3,

                Message = "Your password must meet the following requirements:"
            };

            return Ok(new ApiResponse<PasswordPolicyResponse>
            {
                Success = true,
                Message = "Password policy retrieved.",
                Data = response
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // CalculatePasswordStrength — heuristic password strength calculation.
        //
        // Returns a score from 0 (very weak) to 4 (very strong).
        //
        // This is a SIMPLE heuristic. Real password strength analysis is complex
        // (entropy calculation, dictionary checking, pattern detection, etc.).
        // For a production API, consider using a dedicated library or service.
        // ─────────────────────────────────────────────────────────────────────────
        private int CalculatePasswordStrength(string password)
        {
            int score = 0;

            // Base score: length
            if (password.Length >= 8) score++;
            if (password.Length >= 12) score++;
            if (password.Length >= 16) score++;

            // Character diversity
            bool hasLower = password.Any(char.IsLower);
            bool hasUpper = password.Any(char.IsUpper);
            bool hasDigit = password.Any(char.IsDigit);
            bool hasSpecial = password.Any(c => !char.IsLetterOrDigit(c));

            if (hasLower) score++;
            if (hasUpper) score++;
            if (hasDigit) score++;
            if (hasSpecial) score++;

            // Check for common patterns (reduces score)
            var commonPatterns = new[] { "123", "abc", "qwerty" };
            foreach (var pattern in commonPatterns)
            {
                if (password.ToLower().Contains(pattern))
                {
                    score = Math.Max(0, score - 2);
                    break;
                }
            }

            // Cap score at 0-4 range
            if (score < 0) score = 0;
            if (score > 4) score = 4;

            return score;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // GetStrengthMessage — returns a human-readable message for the score.
        // ─────────────────────────────────────────────────────────────────────────
        private string GetStrengthMessage(int score)
        {
            return score switch
            {
                0 => "Very weak — choose a longer, more complex password.",
                1 => "Weak — add more characters and variety.",
                2 => "Fair — moderately strong, but could be better.",
                3 => "Strong — good password.",
                4 => "Very strong — excellent password.",
                _ => "Unknown strength."
            };
        }

        // ─────────────────────────────────────────────────────────────────────────
        // GetStrengthSuggestions — returns suggestions for improving the password.
        // ─────────────────────────────────────────────────────────────────────────
        private List<string> GetStrengthSuggestions(string password)
        {
            var suggestions = new List<string>();

            if (password.Length < 8)
                suggestions.Add("Make your password at least 8 characters long.");

            if (!password.Any(char.IsUpper))
                suggestions.Add("Add at least one uppercase letter (A-Z).");

            if (!password.Any(char.IsLower))
                suggestions.Add("Add at least one lowercase letter (a-z).");

            if (!password.Any(char.IsDigit))
                suggestions.Add("Add at least one digit (0-9).");

            if (!password.Any(c => !char.IsLetterOrDigit(c)))
                suggestions.Add("Add at least one special character (!, @, #, $, etc.).");

            if (password.ToLower().Contains("password") || password.ToLower().Contains("123"))
                suggestions.Add("Avoid common words and patterns.");

            return suggestions;
        }
    }
}
```

### File: DTOs/PasswordPolicyResponse.cs

```csharp
namespace IdentityApiTutorial.DTOs
{
    public class PasswordPolicyResponse
    {
        public bool RequireDigit { get; set; }
        public int RequiredLength { get; set; }
        public bool RequireNonAlphanumeric { get; set; }
        public bool RequireUppercase { get; set; }
        public bool RequireLowercase { get; set; }
        public int MaxRepeatedChars { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}
```

---

## Postman / Swagger Tests

**Test 1 — Check Password Strength (Weak):**

```
ENDPOINT: POST https://localhost:7001/api/password/check-strength

BODY:
{
  "password": "abc"
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Password strength evaluated.",
  "data": {
    "score": 0,
    "message": "Very weak — choose a longer, more complex password.",
    "suggestions": [
      "Make your password at least 8 characters long.",
      "Add at least one uppercase letter (A-Z).",
      "Add at least one lowercase letter (a-z).",
      "Add at least one digit (0-9).",
      "Add at least one special character (!, @, #, $, etc.)."
    ]
  },
  "errors": []
}

WHAT THIS MEANS:
- Short password (3 chars) gets score 0
- Suggestions show what's missing
```

**Test 2 — Check Password Strength (Strong):**

```
ENDPOINT: POST https://localhost:7001/api/password/check-strength

BODY:
{
  "password": "MyStr0ng!Passw0rd"
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Password strength evaluated.",
  "data": {
    "score": 4,
    "message": "Very strong — excellent password.",
    "suggestions": []
  },
  "errors": []
}

WHAT THIS MEANS:
- Long password with mixed case, digits, special chars gets score 4
- No suggestions — password meets all heuristic checks
```

**Test 3 — Get Password Policy:**

```
ENDPOINT: GET https://localhost:7001/api/password/policy

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Password policy retrieved.",
  "data": {
    "requireDigit": true,
    "requiredLength": 8,
    "requireNonAlphanumeric": true,
    "requireUppercase": true,
    "requireLowercase": true,
    "maxRepeatedChars": 3,
    "message": "Your password must meet the following requirements:"
  },
  "errors": []
}

WHAT THIS MEANS:
- Client can fetch the policy and display it to users
- These are the rules that CreateAsync will enforce
```

**Test 4 — Register with Weak Password (fails policy):**

```
ENDPOINT: POST https://localhost:7001/api/account/register

BODY:
{
  "email": "weakuser@example.com",
  "password": "weak",
  "confirmPassword": "weak"
}

EXPECTED RESPONSE (400 Bad Request):
{
  "success": false,
  "message": "Validation failed.",
  "errors": [
    "The Password field must be at least 8 characters long."
  ]
}

WHAT THIS MEANS:
- [MinLength(8)] on RegisterRequest DTO caught the short password
- ModelState validation rejected it before Identity even saw it
- This is the DTO layer protecting against invalid input
```

**Test 5 — Register with Password That Fails Custom Validator:**

```
ENDPOINT: POST https://localhost:7001/api/account/register

BODY:
{
  "email": "badpass@example.com",
  "password": "Password123",
  "confirmPassword": "Password123"
}

EXPECTED RESPONSE (400 Bad Request):
{
  "success": false,
  "message": "User registration failed.",
  "errors": [
    "Password contains the word 'password'. This is easily guessed."
  ]
}

WHAT THIS MEANS:
- DTO validation passed (length, etc.)
- Identity's PasswordOptions passed (has digit, uppercase, lowercase, special char)
- CustomPasswordValidator failed (contains "password")
- The custom validator's error is returned to the client
```

**Test 6 — Register with Strong Password (succeeds):**

```
ENDPOINT: POST https://localhost:7001/api/account/register

BODY:
{
  "email": "stronguser@example.com",
  "password": "MyStr0ng!Pass",
  "confirmPassword": "MyStr0ng!Pass"
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "User registered successfully.",
  "data": {
    "userId": "...",
    "email": "stronguser@example.com"
  },
  "errors": []
}

WHAT THIS MEANS:
- All validation passed (DTO, PasswordOptions, custom validator)
- User was created
- Password was hashed and stored
```

---

# Video 14 — Account Lockout & Security Stamp in API

## Theory & Definitions

### What Is Account Lockout?

Account lockout is a security feature that temporarily prevents a user from logging in after too many failed login attempts. It protects against brute-force password attacks — if an attacker tries thousands of passwords, lockout stops them after a threshold.

Identity's lockout mechanism:
1. Each failed login increments `AccessFailedCount`
2. When `AccessFailedCount` reaches `MaxFailedAccessAttempts` (default 5), the user is locked out
3. `LockoutEnd` is set to a future date/time (default 5 minutes)
4. Until `LockoutEnd` passes, all login attempts fail with `IsLockedOut = true`
5. After `LockoutEnd` passes, `AccessFailedCount` is reset and the user can try again

### Lockout Configuration

Configured in Program.cs with `IdentityOptions.Lockout`:

```csharp
options.Lockout.AllowedForNewUsers = true;  // Apply lockout to new users (default: true)
options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);  // How long lockout lasts
options.Lockout.MaxFailedAccessAttempts = 5;  // Number of failed attempts before lockout
```

### Lockout Endpoints

For an API, you need endpoints to manage lockout:

| Endpoint | Purpose |
|----------|---------|
| `POST /api/account/lockout` | Manually lock out a user (admin action) |
| `POST /api/account/unlock` | Manually unlock a user (admin action) |
| `GET /api/account/lockout-status` | Check a user's lockout status |

### UserManager Lockout Methods

| Method | Purpose |
|--------|---------|
| `SetLockoutEnabledAsync(user, enabled)` | Enable/disable lockout for a user |
| `IsLockedOutAsync(user)` | Check if user is currently locked out |
| `GetLockoutEnabledAsync(user)` | Check if lockout is enabled for this user |
| `AccessFailedAsync(user)` | Increment AccessFailedCount (called by CheckPasswordSignInAsync automatically) |
| `ResetAccessFailedCountAsync(user)` | Reset AccessFailedCount to 0 (called on successful login) |
| `LockoutEndAsync(user)` | Set LockoutEnd to a specific time |

### Security Stamp — What Is It?

The `SecurityStamp` is a random value stored on the user that changes EVERY time the user's security-relevant data changes:
- Password change
- Role assignment/removal
- Claim addition/removal
- Email confirmation change

It's stored in `IdentityUser.SecurityStamp` and is a GUID string.

### How Security Stamp Works with JWT

When a user logs in, their SecurityStamp is encoded in the token (as a claim). When you call `userManager.UpdateSecurityStampAsync(user)`, the stamp changes. Existing tokens that have the old stamp are now "stale" — they don't match the current stamp.

**Important:** The JWT bearer middleware does NOT automatically check the SecurityStamp. The stamp is just a claim in the token. To use it for token invalidation, you need to:
1. Add the SecurityStamp as a claim in the JWT
2. On each request, compare the token's stamp to the user's current stamp in the database
3. If they don't match, reject the request (or require re-login)

This is typically implemented as a custom authorization filter or a claims transformation service.

### "Sign Out Everywhere" — How It Works

"Sign out everywhere" means invalidating ALL of a user's tokens, not just the current one. This is implemented by:

1. **Change the SecurityStamp** — `userManager.UpdateSecurityStampAsync(user)`
2. **All tokens with the old stamp are now invalid** — but only if you check the stamp on each request

Without stamp checking, "sign out everywhere" doesn't work — the tokens are still valid until they expire.

### Lockout vs Security Stamp — Different Purposes

| Feature | Lockout | Security Stamp |
|---------|---------|----------------|
| Purpose | Prevent brute force attacks | Invalidate tokens when security changes |
| When it triggers | Too many failed logins | Password/role/claim changes |
| Duration | Temporary (minutes/hours) | Permanent (until next change) |
| Effect | Blocks login attempts | Invalidates existing tokens (if checked) |
| Stored in | AccessFailedCount, LockoutEnd | SecurityStamp property |

### "When to Use vs When Not to Use" — Lockout & Security Stamp

| Decision | Use it | Don't use it |
|----------|--------|--------------|
| Account lockout | For public-facing APIs (brute force protection) | For internal APIs with rate limiting (lockout is redundant) |
| Short lockout (5 min) | Good balance — annoying for attackers, not for users | Very long lockout (30 days) — too disruptive for legitimate users |
| Manual unlock endpoint | For admin panels to unlock users | If you don't have admin functionality |
| Security stamp checking on every request | For high-security apps (immediate token revocation) | For apps where token expiration is sufficient (stamp checking is overhead) |
| "Sign out everywhere" endpoint | For security-conscious apps (user can revoke all sessions) | If you don't need session management |
| Lockout for new users | Yes — new users should be protected too | If you have a different onboarding flow |

### Key Insight: Lockout and Security Stamp Are Both Security Features

Lockout stops brute force. Security stamp enables token revocation. They serve different purposes but both are important for a secure API. Lockout is built into Identity and works automatically. Security stamp requires explicit checking to be effective — it's not automatic with JWT.

---

## 🎬 Video Recording Notes

**Opening (say this):**
> \"Two important security features: lockout and security stamps. Lockout stops brute force attacks — too many failed logins and the account is temporarily frozen. Security stamps are how we invalidate tokens when a user's security changes — password change, role change, 'sign out everywhere'. Today we build lockout endpoints and show how security stamps work with JWT.\"

**Show on screen (do this):**
> Show lockout configuration in Program.cs. Show the lockout/unlock endpoints. Demonstrate: register a user, fail login 5 times, show lockout, unlock, login succeeds. Then show security stamp: login, change password, show that the old token still works (until expiration) — explain that stamp checking requires custom implementation.

**Key points to emphasize (say this):**
> \"Lockout is automatic — CheckPasswordSignInAsync increments AccessFailedCount and sets LockoutEnd when the threshold is reached. You don't need to implement lockout logic. But you DO need endpoints for admins to manually lock/unlock users.\"

> \"The default lockout is 5 minutes after 5 failed attempts. This is a good default — short enough to not frustrate legitimate users who mistyped, long enough to stop brute force. You can configure both values in Program.cs.\"

> \"Security stamps are automatic too — Identity generates a new stamp when the password changes, when roles change, when claims change. But the stamp is just a value in the database. To use it for token invalidation, you need to check it on each request — that's custom code.\"

> \"'Sign out everywhere' = change the security stamp. All tokens with the old stamp are invalidated (if you check stamps). Without stamp checking, 'sign out everywhere' is just a client-side logout — delete the token and you're done.\"

> \"The SecurityStamp is NOT automatically checked by the JWT middleware. The middleware validates the signature, expiration, issuer, audience — but not the stamp. Stamp checking is a custom authorization step.\"

**Analogy (say this):**
> \"Lockout is like a bank card that gets swallowed after 3 wrong PIN attempts. You can't use it for 5 minutes. After 5 minutes, it comes back out and you can try again. This stops someone from trying thousands of PINs.\"

> \"The security stamp is like a security seal on a document. If anyone changes the document (password, roles), the seal is broken and a new one is applied. Old copies of the document with the old seal are no longer valid. But someone has to check the seal — the document doesn't self-destruct.\"

**Common viewer question:**
> \"Does lockout reset after a successful login?\" — Yes. CheckPasswordSignInAsync resets AccessFailedCount to 0 on successful login. The failed attempt counter is cleared.

> \"Can I lock out by IP address instead of by user?\" — Not with Identity's built-in lockout. Identity locks out by user (AccessFailedCount per user). IP-based lockout requires custom middleware or rate limiting (Video 19 touches on this).

> \"How do I check the security stamp on every request?\" — You'd implement a custom IAuthorizationFilter or an IClaimsTransformation that loads the user from the database and compares the stamp. This is a database hit on every request — tradeoffs between security and performance.

**What to show:**
- Lockout configuration in Program.cs
- Lockout status endpoint (GET)
- Manual lockout endpoint (POST — admin)
- Manual unlock endpoint (POST — admin)
- Demonstration: fail 5 logins → lockout → unlock → login
- Security stamp explanation (show the stamp value in the database)
- "Sign out everywhere" concept (change stamp → tokens invalidated)

**What to skip:**
- Custom stamp checking middleware (complex, mention as advanced)
- IP-based lockout (different topic)
- Progressive lockout (increasing lockout duration per failure) — advanced

---

## Complete Implementation

### File: DTOs/LockoutDtos.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: DTOs/LockoutDtos.cs
// Video 14 — Lockout management DTOs
// ─────────────────────────────────────────────────────────────────────────────
namespace IdentityApiTutorial.DTOs
{
    public class LockoutStatusResponse
    {
        public bool IsLockedOut { get; set; }
        public bool LockoutEnabled { get; set; }
        public int AccessFailedCount { get; set; }
        public DateTime? LockoutEnd { get; set; }
        public int MaxFailedAttempts { get; set; } = 5;
        public TimeSpan LockoutDuration { get; set; }
    }

    public class LockoutRequest
    {
        public string UserId { get; set; } = string.Empty;
    }

    public class UnlockRequest
    {
        public string UserId { get; set; } = string.Empty;
    }
}
```

### File: Controllers/LockoutController.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Controllers/LockoutController.cs
// Video 14 — Lockout Management Endpoints
// ─────────────────────────────────────────────────────────────────────────────
// Endpoints:
//   - GET /api/lockout/status?userId={userId} — check lockout status
//   - POST /api/lockout/lock — manually lock out a user (admin)
//   - POST /api/lockout/unlock — manually unlock a user (admin)
//
// ALL endpoints require Admin role.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Create this controller
//   - Show each endpoint
//   - Demonstrate lockout by failing logins
//   - Show manual lockout and unlock
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.DTOs;
using IdentityApiTutorial.Models;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "Admin")]
    public class LockoutController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<LockoutController> _logger;

        public LockoutController(UserManager<ApplicationUser> userManager, ILogger<LockoutController> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // GetStatus — returns the lockout status for a user.
        //
        // GET /api/lockout/status?userId={userId}
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("status")]
        public async Task<IActionResult> GetLockoutStatus([FromQuery] string userId)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User ID is required.",
                    Errors = new List<string> { "Please provide userId query parameter." }
                });
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User not found.",
                    Errors = new List<string> { $"No user found with ID '{userId}'." }
                });
            }

            var isLockedOut = await _userManager.IsLockedOutAsync(user);
            var lockoutEnabled = await _userManager.GetLockoutEnabledAsync(user);
            var accessFailedCount = await _userManager.GetAccessFailedCountAsync(user);
            var lockoutEnd = user.LockoutEnd;

            // Calculate remaining lockout time
            TimeSpan? remainingLockout = null;
            if (isLockedOut && lockoutEnd.HasValue)
            {
                remainingLockout = lockoutEnd.Value - DateTime.UtcNow;
                if (remainingLockout.Value.TotalSeconds < 0)
                    remainingLockout = TimeSpan.Zero;
            }

            return Ok(new ApiResponse<LockoutStatusResponse>
            {
                Success = true,
                Message = "Lockout status retrieved.",
                Data = new LockoutStatusResponse
                {
                    IsLockedOut = isLockedOut,
                    LockoutEnabled = lockoutEnabled,
                    AccessFailedCount = accessFailedCount,
                    LockoutEnd = lockoutEnd,
                    MaxFailedAttempts = 5,
                    LockoutDuration = remainingLockout ?? TimeSpan.Zero
                }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // Lock — manually locks out a user.
        //
        // POST /api/lockout/lock
        // Body: LockoutRequest (userId)
        //
        // Sets LockoutEnd to 30 days from now (effectively permanent lockout
        // until manually unlocked). Admin can use this for suspending users.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("lock")]
        public async Task<IActionResult> LockUser([FromBody] LockoutRequest request)
        {
            if (string.IsNullOrEmpty(request.UserId))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User ID is required.",
                    Errors = new List<string> { "userId is required in the request body." }
                });
            }

            var user = await _userManager.FindByIdAsync(request.UserId);
            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User not found.",
                    Errors = new List<string> { $"No user found with ID '{request.UserId}'." }
                });
            }

            // Set lockout end to 30 days from now
            var lockoutEnd = DateTime.UtcNow.AddDays(30);
            var result = await _userManager.SetLockoutEndAsync(user, lockoutEnd);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Failed to lock user.",
                    Errors = errors
                });
            }

            _logger.LogWarning("User {UserId} manually locked out by admin", request.UserId);

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "User has been locked out.",
                Data = new { UserId = request.UserId, LockoutEnd = lockoutEnd }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // Unlock — manually unlocks a user.
        //
        // POST /api/lockout/unlock
        // Body: UnlockRequest (userId)
        //
        // Resets AccessFailedCount to 0 and sets LockoutEnd to null.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("unlock")]
        public async Task<IActionResult> UnlockUser([FromBody] UnlockRequest request)
        {
            if (string.IsNullOrEmpty(request.UserId))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User ID is required.",
                    Errors = new List<string> { "userId is required in the request body." }
                });
            }

            var user = await _userManager.FindByIdAsync(request.UserId);
            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User not found.",
                    Errors = new List<string> { $"No user found with ID '{request.UserId}'." }
                });
            }

            // Reset access failed count and clear lockout
            await _userManager.ResetAccessFailedCountAsync(user);
            var result = await _userManager.SetLockoutEndAsync(user, null);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Failed to unlock user.",
                    Errors = errors
                });
            }

            _logger.LogInformation("User {UserId} manually unlocked by admin", request.UserId);

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "User has been unlocked.",
                Data = new { UserId = request.UserId }
            });
        }
    }
}
```

### Security Stamp Explanation (Video Section)

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// Security Stamp — How It Works (Explanation for Video 14)
// ─────────────────────────────────────────────────────────────────────────────
//
// The SecurityStamp is a random GUID stored on the user.
// It changes automatically when:
//   - Password is changed (via UserManager.PasswordHasher)
//   - Roles are added/removed (UserManager.AddToRoleAsync, RemoveFromRoleAsync)
//   - Claims are added/removed (UserManager.AddClaimAsync, RemoveClaimAsync)
//   - Email is confirmed/unconfirmed
//
// Identity calls userManager.UpdateSecurityStampAsync() internally when these
// events occur. The stamp is updated in the database.
//
// To use the stamp for JWT token invalidation:
//
//   1. Add the stamp as a claim in the JWT (in GenerateJwtToken):
//      claims.Add(new Claim("security_stamp", user.SecurityStamp));
//
//   2. On each authenticated request, check the stamp:
//      [Authorize]
//      public class StampCheckingController : ControllerBase
//      {
//          public async Task<IActionResult> ProtectedAction()
//          {
//              var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
//              var user = await _userManager.FindByIdAsync(userId);
//              var stampFromToken = User.FindFirst("security_stamp")?.Value;
//
//              if (user == null || user.SecurityStamp != stampFromToken)
//              {
//                  // Token is stale — user's security has changed
//                  return Unauthorized(new { message = "Session expired. Please re-login." });
//              }
//
//              // Stamp matches — continue
//          }
//      }
//
//   3. For "Sign Out Everywhere":
//      await _userManager.UpdateSecurityStampAsync(user);
//      // All tokens with the old stamp are now invalid (if checked)
//
// IMPORTANT: Stamp checking requires a database lookup on every request.
// This adds latency. For high-traffic APIs, consider:
//   - Short-lived tokens (15-30 minutes) — tokens expire quickly anyway
//   - Refresh tokens — shorter access tokens + longer refresh tokens
//   - Stamp checking only on sensitive endpoints (not every request)
//
// ─────────────────────────────────────────────────────────────────────────────
```

---

## Postman / Swagger Tests

**Test 1 — Check Lockout Status (Normal User):**

```
ENDPOINT: GET https://localhost:7001/api/lockout/status?userId={userId}

AUTH: Bearer token (Admin)

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Lockout status retrieved.",
  "data": {
    "isLockedOut": false,
    "lockoutEnabled": true,
    "accessFailedCount": 0,
    "lockoutEnd": null,
    "maxFailedAttempts": 5,
    "lockoutDuration": "00:00:00"
  },
  "errors": []
}

WHAT THIS MEANS:
- User is not locked out
- Lockout is enabled for this user
- 0 failed attempts so far
```

**Test 2 — Trigger Lockout (5 Failed Logins):**

```
1. Attempt login with wrong password 5 times:
   POST /api/account/login
   { "email": "testuser@example.com", "password": "WrongPassword1" }
   ... repeat 5 times with different wrong passwords

2. After 5th failure, check lockout status:
   GET /api/lockout/status?userId={userId}

EXPECTED:
{
  "isLockedOut": true,
  "accessFailedCount": 5,
  "lockoutEnd": "2024-01-15T10:35:00Z"  // 5 minutes from now
}

3. Try to login with correct password:
   POST /api/account/login
   { "email": "testuser@example.com", "password": "Test@123456" }

EXPECTED: 400 — "Account is locked due to too many failed login attempts."

4. Wait 5 minutes (or use unlock endpoint) and try again:
   Expected: Login succeeds
```

**Test 3 — Manual Lockout (Admin):**

```
ENDPOINT: POST https://localhost:7001/api/lockout/lock

AUTH: Bearer token (Admin)

BODY:
{
  "userId": "{userId}"
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "User has been locked out.",
  "data": {
    "userId": "{userId}",
    "lockoutEnd": "2024-02-14T10:00:00Z"  // 30 days from now
  },
  "errors": []
}

WHAT THIS MEANS:
- Admin manually locked out the user for 30 days
- User cannot login until unlocked or lockout expires
```

**Test 4 — Manual Unlock (Admin):**

```
ENDPOINT: POST https://localhost:7001/api/lockout/unlock

AUTH: Bearer token (Admin)

BODY:
{
  "userId": "{userId}"
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "User has been unlocked.",
  "data": { "userId": "{userId}" },
  "errors": []
}

WHAT THIS MEANS:
- Admin unlocked the user
- AccessFailedCount reset to 0
- LockoutEnd set to null
- User can login immediately
```

**Test 5 — Security Stamp Observation:**

```
1. Login as a user and get a JWT token
2. Decode the token — note the security_stamp claim (if added)
3. Change the user's password (via a password change endpoint — not shown in this tutorial)
4. Identity automatically updates SecurityStamp in the database
5. Try to use the old JWT token:
   - If stamp checking is implemented: 401 "Session expired"
   - If stamp checking is NOT implemented: token still works until expiration

DEMONSTRATION: Show that without stamp checking, the old token still works.
Explain that stamp checking is custom code that must be added separately.
```

---

# Video 15 — Two-Factor Authentication (2FA) API: TOTP, Recovery Codes

## Theory & Definitions

### What Is Two-Factor Authentication (2FA)?

2FA adds a second layer of security beyond the password. Even if an attacker steals the password, they can't login without the second factor — typically a time-based one-time password (TOTP) from an authenticator app (Google Authenticator, Microsoft Authenticator, Authy).

Identity supports 2FA through:
- **TOTP (Time-Based One-Time Password)** — generates a 6-digit code that changes every 30 seconds
- **Recovery codes** — one-time-use codes for when the user loses their authenticator device

### How TOTP Works

TOTP is defined in RFC 6238. It works like this:

1. A shared secret key is generated (base32-encoded string)
2. The secret is entered into an authenticator app (via QR code or manual entry)
3. Both the server and the app use the secret + current time to generate a 6-digit code
4. The codes are synchronized — both sides generate the same code at the same time
5. When the user logs in, they provide the current code from their app
6. The server generates its code from the secret and compares — if they match, 2FA passes

### 2FA Flow in an API

```
Registration (optional — can enable 2FA later):
  1. User registers (Video 07)
  2. User enables 2FA:
     a. Generate 2FA secret (UserManager.GenerateTwoFactorRecoveryCodesAsync or custom)
     b. Return secret to client (display as QR code URI)
     c. Client enters secret in authenticator app
     d. Client provides first TOTP code to verify
     e. Server verifies code (UserManager.VerifyTwoFactorTokenAsync)
     f. If verified, mark 2FA as enabled (set TwoFactorEnabled = true)

Login with 2FA:
  1. User provides email + password
  2. Server validates password (CheckPasswordSignInAsync)
  3. Server checks if user has 2FA enabled (TwoFactorEnabled)
  4. If 2FA enabled: return "2FA required" response with a temp token
  5. Client provides TOTP code
  6. Server verifies TOTP (UserManager.VerifyTwoFactorTokenAsync)
  7. If verified, issue JWT token
  8. If not verified, return error

Recovery Codes:
  - Generated when 2FA is enabled
  - Each code can be used once
  - Stored hashed (like passwords) in the database
  - Used when the user loses access to their authenticator app
```

### Identity's 2FA Support

Identity provides:
- `TwoFactorEnabled` property on IdentityUser — boolean flag
- `GenerateTwoFactorTokenAsync(user, "Email")` / `GenerateTwoFactorTokenAsync(user, "Phone")` — generates a token for email/phone 2FA
- `VerifyTwoFactorTokenAsync(user, "Email", token)` — verifies a token
- `GenerateTwoFactorRecoveryCodesAsync(user)` — generates recovery codes
- `ConsumeTwoFactorRecoveryCodeAsync(user, code)` — consumes a recovery code

**Note:** Identity's built-in 2FA is designed for email/phone delivery. For TOTP (authenticator app), you need to implement it yourself or use a library like `Otp.NET`.

### Implementing TOTP with Otp.NET

The `Otp.NET` library (NuGet: `Otp.NET`) provides TOTP implementation:

```csharp
// Generate a secret
var secret = KeyGenerator.GenerateKey(20);  // 20 bytes = 160 bits
var base32Secret = Base32Encoding.Encode(secret);

// Generate a QR code URI (for the authenticator app)
var qrUri = $"otpauth://totp/IdentityApiTutorial:{user.Email}?secret={base32Secret}&issuer=IdentityApiTutorial";

// Verify a code
var totp = new Totp(base32Secret);
bool valid = totp.VerifyTotp(code, out long timeStepMatched, new VerificationWindow(3, 0));
```

### Recovery Codes

Recovery codes are one-time-use codes that bypass 2FA. They're generated when 2FA is enabled and stored hashed in the database.

```csharp
// Generate recovery codes
var recoveryCodes = _userManager.GenerateTwoFactorRecoveryCodesAsync(user).Result;

// Consume a recovery code
var result = await _userManager.ConsumeTwoFactorRecoveryCodeAsync(user, code);
// Result.Succeeded = true if code was valid and not used before
```

### "When to Use vs When Not to Use" — 2FA

| Decision | Use it | Don't use it |
|----------|--------|--------------|
| TOTP (authenticator app) | For security-conscious apps (email, finance, admin panels) | For low-security apps (blog comments, public forums) |
| Email-based 2FA | When users don't have smartphones | When email access is less secure than the account itself |
| Recovery codes | Always — users lose devices, need backup | If you have other recovery mechanisms (admin reset, etc.) |
| 2FA on every login | For high-security apps | For convenience-focused apps (2FA on sensitive actions only) |
| 2FA on registration | Optional — let users enable it after registration | Force 2FA at registration (too much friction for new users) |
| SMS-based 2FA | When users don't have authenticator apps | SMS is less secure (SIM swapping, interception) |

### Key Insight: 2FA Is About Defense in Depth

2FA protects against password theft. If an attacker gets the password (phishing, breach, brute force), 2FA stops them. It's not a replacement for good passwords — it's an additional layer. For APIs, 2FA is especially important for admin accounts and sensitive operations.

---

## 🎬 Video Recording Notes

**Opening (say this):**
> \"Two-factor authentication — the second layer of security. Even if someone steals a password, they can't login without the second factor. Today we implement TOTP-based 2FA using an authenticator app, generate and verify recovery codes, and build the 2FA login flow. This is one of the most important security features for any API that handles sensitive data.\"

**Show on screen (do this):**
> Show the 2FA enable endpoint: generate secret, return QR code URI. Show the QR code (use a QR code generator tool). Show the verify endpoint. Show the 2FA login flow: login → 2FA required → provide code → get JWT. Show recovery codes generation and consumption.

**Key points to emphasize (say this):**
> \"TOTP uses a shared secret between the server and the authenticator app. The secret is generated once and stored (hashed) in the database. The app generates 6-digit codes that change every 30 seconds. The server generates the same code and compares.\"

> \"The QR code is just a convenient way to enter the secret into the authenticator app. The URI format is otpauth://totp/Issuer:Email?secret=SECRET&issuer=ISSUER. Any authenticator app can scan this and start generating codes.\"

> \"Recovery codes are critical. If a user loses their phone or deletes the authenticator app, they're locked out forever unless they have recovery codes. Generate them when 2FA is enabled and tell users to save them somewhere safe.\"

> \"2FA login is a two-step process: first validate the password, then validate the TOTP code. Don't issue the JWT until both steps pass. The intermediate state (password valid, waiting for 2FA code) needs to be tracked — typically with a short-lived temporary token.\"

> \"Identity's built-in 2FA is for email/phone delivery. For TOTP (authenticator apps), we use Otp.NET. The pattern is the same — generate secret, verify code — but the implementation is different.\"

**Analogy (say this):**
> \"Think of 2FA like a safe with two locks. The password is the first key. The TOTP code is the second key. You need both to open the safe. If someone steals your first key (password), they still can't open the safe without the second key (your phone).\"

> \"Recovery codes are like spare keys. If you lose your second key (phone), you can use a spare key (recovery code) to open the safe. But each spare key can only be used once — use it or lose it.\"

**Common viewer question:**
> \"Is 2FA necessary for an API?\" — For admin accounts and sensitive operations, yes. For regular user accounts, it depends on the sensitivity of the data. If the API handles personal data, financial data, or administrative functions, 2FA is recommended.

> \"Can I use SMS instead of TOTP?\" — Yes, but SMS is less secure (SIM swapping, interception). TOTP with an authenticator app is more secure. Use SMS only as a fallback, not as the primary 2FA method.

> \"What happens if the user's clock is wrong?\" — TOTP uses time windows. The VerificationWindow parameter allows a few time steps of drift (default ±1 step = ±30 seconds). If the user's clock is off by more than that, codes won't validate. Tell users to set their phone clock to automatic.

**What to show:**
- 2FA enable endpoint (generate secret, return QR URI)
- QR code display (use a QR code tool to show the code)
- 2FA verify endpoint (verify TOTP code)
- 2FA login flow (two-step login)
- Recovery codes generation
- Recovery code consumption (one-time use)
- Postman tests for each endpoint

**What to skip:**
- SMS-based 2FA implementation (different infrastructure)
- Hardware security keys (WebAuthn/FIDO2) — different technology
- Push notifications for 2FA — different mechanism

---

## Complete Implementation

### File: DTOs/TwoFactorDtos.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: DTOs/TwoFactorDtos.cs
// Video 15 — Two-Factor Authentication DTOs
// ─────────────────────────────────────────────────────────────────────────────
namespace IdentityApiTutorial.DTOs
{
    public class Enable2FARequest
    {
        public string UserId { get; set; } = string.Empty;
    }

    public class Enable2FAResponse
    {
        public bool Success { get; set; }
        public string Secret { get; set; } = string.Empty;  // Base32 secret
        public string QrCodeUri { get; set; } = string.Empty;  // otpauth:// URI
        public string Message { get; set; } = string.Empty;
    }

    public class Verify2FARequest
    {
        public string Code { get; set; } = string.Empty;  // 6-digit TOTP code
        public string TempToken { get; set; } = string.Empty;  // Temporary token from login step
    }

    public class Verify2FAResponse
    {
        public bool Success { get; set; }
        public string? Token { get; set; }  // JWT token (if 2FA verified)
        public string? Message { get; set; }
        public List<string>? RecoveryCodes { get; set; }  // First-time enable: show recovery codes
    }

    public class RecoveryCodesResponse
    {
        public List<string> Codes { get; set; } = new List<string>();
        public string Message { get; set; } = "Save these codes in a safe place. Each code can be used once.";
    }

    public class ConsumeRecoveryCodeRequest
    {
        public string Code { get; set; } = string.Empty;
    }

    public class ConsumeRecoveryCodeResponse
    {
        public bool Success { get; set; }
        public string? Token { get; set; }  // JWT token if recovery code valid
        public string? Message { get; set; }
    }
}
```

### File: Controllers/TwoFactorController.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Controllers/TwoFactorController.cs
// Video 15 — Two-Factor Authentication Endpoints
// ─────────────────────────────────────────────────────────────────────────────
// Endpoints:
//   - POST /api/2fa/enable — enable 2FA for a user (generate secret)
//   - POST /api/2fa/verify — verify 2FA setup (verify first TOTP code)
//   - POST /api/2fa/login — 2FA login step 1 (password validated, 2FA required)
//   - POST /api/2fa/login-verify — 2FA login step 2 (verify TOTP, issue JWT)
//   - GET /api/2fa/recovery-codes — get recovery codes
//   - POST /api/2fa/recover — login with recovery code
//   - POST /api/2fa/disable — disable 2FA for a user
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Create this controller
//   - Explain the 2FA flow (enable → verify → login)
//   - Show the QR code URI and how to use it with an authenticator app
//   - Demonstrate the full 2FA login flow with Postman
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.DTOs;
using IdentityApiTutorial.Models;
using Microsoft.Extensions.Logging;
using OtpNet;  // Otp.NET library for TOTP
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TwoFactorController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly ILogger<TwoFactorController> _logger;

        // Temporary token store for 2FA login flow
        // In production, use a distributed cache (Redis) or database
        private static readonly Dictionary<string, string> _tempTokens = new();

        public TwoFactorController(
            UserManager<ApplicationUser> userManager,
            IConfiguration configuration,
            ILogger<TwoFactorController> logger)
        {
            _userManager = userManager;
            _configuration = configuration;
            _logger = logger;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // Enable — generates a 2FA secret for the user.
        //
        // POST /api/2fa/enable
        // Body: Enable2FARequest (userId)
        // Response: Enable2FAResponse (secret, QR code URI)
        //
        // Flow:
        //   1. Find user by ID
        //   2. Check if 2FA is already enabled
        //   3. Generate a new TOTP secret
        //   4. Create the QR code URI
        //   5. Return secret and URI to the client
        //   6. Client enters secret in authenticator app
        //   7. Client calls Verify endpoint with first TOTP code
        //
        // IMPORTANT: The secret is returned in plain text. The client should
        // display it once and store it securely. In production, you might
        // encrypt the secret before storing it, or use a more secure delivery
        // mechanism.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("enable")]
        [Authorize(Roles = "Admin")]  // Or the user themselves (with ownership check)
        public async Task<IActionResult> Enable2FA([FromBody] Enable2FARequest request)
        {
            if (string.IsNullOrEmpty(request.UserId))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User ID is required.",
                    Errors = new List<string> { "userId is required." }
                });
            }

            var user = await _userManager.FindByIdAsync(request.UserId);
            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User not found.",
                    Errors = new List<string> { $"No user found with ID '{request.UserId}'." }
                });
            }

            if (user.TwoFactorEnabled)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "2FA is already enabled for this user.",
                    Errors = new List<string> { "Two-factor authentication is already active." }
                });
            }

            // Generate a TOTP secret (20 bytes = 160 bits)
            var secret = KeyGenerator.GenerateKey(20);
            var base32Secret = Base32Encoding.Encode(secret);

            // Create the QR code URI
            // Format: otpauth://totp/Issuer:Email?secret=SECRET&issuer=ISSUER
            var issuer = _configuration["Jwt:Issuer"] ?? "IdentityApiTutorial";
            var qrCodeUri = $"otpauth://totp/{issuer}:{user.Email}?secret={base32Secret}&issuer={issuer}";

            // Store the secret temporarily (in production, store in database, hashed)
            // We store it in a temporary field — in a real app, add a TOTPSecret property
            // to ApplicationUser or store it in a separate table
            user.TwoFactorSecret = base32Secret;  // Custom property on ApplicationUser

            await _userManager.UpdateAsync(user);

            _logger.LogInformation("2FA secret generated for user {UserId}", request.UserId);

            return Ok(new ApiResponse<Enable2FAResponse>
            {
                Success = true,
                Message = "2FA secret generated. Scan the QR code with your authenticator app, then verify.",
                Data = new Enable2FAResponse
                {
                    Success = true,
                    Secret = base32Secret,
                    QrCodeUri = qrCodeUri,
                    Message = "Scan this QR code with Google Authenticator, Microsoft Authenticator, or Authy."
                }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // Verify — verifies the 2FA setup.
        //
        // POST /api/2fa/verify
        // Body: Verify2FARequest (code, tempToken — unused in enable flow)
        // Response: Verify2FAResponse (success, recovery codes)
        //
        // Flow:
        //   1. Find user
        //   2. Get the stored TOTP secret
        //   3. Verify the provided code against the secret
        //   4. If valid, enable 2FA (TwoFactorEnabled = true)
        //   5. Generate recovery codes
        //   6. Return success + recovery codes
        //
        // The user must provide the first TOTP code from their authenticator app
        // to confirm that the secret was entered correctly.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("verify")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Verify2FA([FromBody] Verify2FARequest request)
        {
            if (string.IsNullOrEmpty(request.Code) || request.Code.Length != 6)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Invalid code.",
                    Errors = new List<string> { "Please provide a valid 6-digit TOTP code." }
                });
            }

            // For this example, we verify for the currently admin user's managed user
            // In a real API, you'd identify the user differently
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User not found."
                });
            }

            if (string.IsNullOrEmpty(user.TwoFactorSecret))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "2FA secret not found. Enable 2FA first.",
                    Errors = new List<string> { "No 2FA secret found. Call /api/2fa/enable first." }
                });
            }

            // Verify the TOTP code
            var totp = new Totp(user.TwoFactorSecret);
            var isValid = totp.VerifyTotp(request.Code, out long timeStepMatched, new VerificationWindow(3, 0));

            if (!isValid)
            {
                _logger.LogWarning("Invalid 2FA code for user {UserId}", userId);

                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Invalid 2FA code.",
                    Errors = new List<string> { "The provided code does not match. Check your authenticator app and try again." }
                });
            }

            // Enable 2FA
            user.TwoFactorEnabled = true;
            var updateResult = await _userManager.UpdateAsync(user);

            if (!updateResult.Succeeded)
            {
                var errors = updateResult.Errors.Select(e => e.Description).ToList();
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Failed to enable 2FA.",
                    Errors = errors
                });
            }

            // Generate recovery codes
            var recoveryCodesTask = _userManager.GenerateTwoFactorRecoveryCodesAsync(user);
            recoveryCodesTask.Wait();
            var recoveryCodes = recoveryCodesTask.Result;

            _logger.LogInformation("2FA enabled for user {UserId}", userId);

            return Ok(new ApiResponse<Verify2FAResponse>
            {
                Success = true,
                Message = "2FA enabled successfully.",
                Data = new Verify2FAResponse
                {
                    Success = true,
                    Message = "Two-factor authentication is now enabled.",
                    RecoveryCodes = recoveryCodes.ToList()  // Show recovery codes once
                }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // LoginStep1 — first step of 2FA login (password validated, 2FA required).
        //
        // POST /api/2fa/login
        // Body: LoginRequest (email, password)
        // Response: { requires2FA: true, tempToken: "..." } or { requires2FA: false, token: "..." }
        //
        // Flow:
        //   1. Validate email and password (same as regular login)
        //   2. If password valid AND 2FA enabled:
        //      a. Generate a temporary token (short-lived, e.g., 2 minutes)
        //      b. Return { requires2FA: true, tempToken: "..." }
        //   3. If password valid AND 2FA NOT enabled:
        //      a. Generate JWT token (regular login)
        //      b. Return { requires2FA: false, token: "..." }
        //   4. If password invalid: return error (same as regular login)
        //
        // The temporary token is used in the VerifyLogin endpoint to link
        // the 2FA code to the specific login attempt.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> TwoFactorLogin([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Validation failed.",
                    Errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList()
                });
            }

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Invalid email or password.",
                    Errors = new List<string> { "Invalid email or password." }
                });
            }

            var signInResult = await _userManager.CheckPasswordSignInAsync(user, request.Password, true);

            if (signInResult.IsLockedOut)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Account is locked.",
                    Errors = new List<string> { "Account is locked due to too many failed attempts." }
                });
            }

            if (signInResult.PasswordIncorrect)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Invalid email or password.",
                    Errors = new List<string> { "Invalid email or password." }
                });
            }

            if (signInResult.IsNotAllowed)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Login not allowed.",
                    Errors = new List<string> { "Email not confirmed or account not allowed to login." }
                });
            }

            // Password is valid — check if 2FA is enabled
            if (user.TwoFactorEnabled)
            {
                // Generate a temporary token for the 2FA step
                var tempToken = Guid.NewGuid().ToString("N");
                var tempExpiry = DateTime.UtcNow.AddMinutes(2);

                _tempTokens[tempToken] = $"{user.Id}:{tempExpiry.ToString("O")}";

                _logger.LogInformation("2FA login step 1: temp token generated for {UserId}", user.Id);

                return Ok(new ApiResponse<object>
                {
                    Success = true,
                    Message = "Two-factor authentication required.",
                    Data = new
                    {
                        Requires2FA = true,
                        TempToken = tempToken,
                        Message = "Enter the 6-digit code from your authenticator app."
                    }
                });
            }

            // 2FA not enabled — issue JWT directly
            var token = GenerateJwtToken(user);
            var roles = await _userManager.GetRolesAsync(user);

            user.LastLoginDate = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("User logged in (no 2FA): {UserId}", user.Id);

            return Ok(new ApiResponse<LoginResponse>
            {
                Success = true,
                Message = "Login successful.",
                Data = new LoginResponse
                {
                    Token = token,
                    ExpirationMinutes = 60,
                    Roles = roles.ToList(),
                    Email = user.Email,
                    UserId = user.Id
                }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // LoginStep2 — second step of 2FA login (verify TOTP, issue JWT).
        //
        // POST /api/2fa/login-verify
        // Body: Verify2FARequest (code, tempToken)
        // Response: { token: "...", expiresIn: 3600 } or error
        //
        // Flow:
        //   1. Validate the temp token (exists, not expired)
        //   2. Get the user ID from the temp token
        //   3. Find the user
        //   4. Verify the TOTP code against the user's secret
        //   5. If valid, issue JWT token
        //   6. If invalid, return error
        //   7. Clean up the temp token
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("login-verify")]
        [AllowAnonymous]
        public async Task<IActionResult> TwoFactorLoginVerify([FromBody] Verify2FARequest request)
        {
            if (string.IsNullOrEmpty(request.TempToken))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Temporary token is required.",
                    Errors = new List<string> { "A temporary token is required for 2FA login." }
                });
            }

            if (string.IsNullOrEmpty(request.Code) || request.Code.Length != 6)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Invalid 2FA code.",
                    Errors = new List<string> { "Please provide a valid 6-digit code." }
                });
            }

            // Validate temp token
            if (!_tempTokens.TryGetValue(request.TempToken, out var tempData))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Invalid or expired temporary token.",
                    Errors = new List<string> { "The temporary token is invalid or has expired. Please start the login process again." }
                });
            }

            // Parse temp token data
            var parts = tempData.Split(':');
            if (parts.Length != 2)
            {
                _tempTokens.Remove(request.TempToken);
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Invalid temporary token format.",
                    Errors = new List<string> { "The temporary token is malformed." }
                });
            }

            var userId = parts[0];
            var expiryStr = parts[1];
            var expiry = DateTime.Parse(expiryStr);

            if (DateTime.UtcNow > expiry)
            {
                _tempTokens.Remove(request.TempToken);
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Temporary token has expired.",
                    Errors = new List<string> { "The temporary token has expired. Please start the login process again." }
                });
            }

            // Find user
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _tempTokens.Remove(request.TempToken);
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User not found."
                });
            }

            // Verify TOTP code
            if (string.IsNullOrEmpty(user.TwoFactorSecret))
            {
                _tempTokens.Remove(request.TempToken);
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "2FA secret not configured.",
                    Errors = new List<string> { "2FA secret is missing. Contact support." }
                });
            }

            var totp = new Totp(user.TwoFactorSecret);
            var isValid = totp.VerifyTotp(request.Code, out long timeStepMatched, new VerificationWindow(3, 0));

            if (!isValid)
            {
                _logger.LogWarning("Invalid 2FA code for user {UserId}", userId);

                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Invalid 2FA code.",
                    Errors = new List<string> { "The provided code is incorrect. Try again." }
                });
            }

            // Clean up temp token
            _tempTokens.Remove(request.TempToken);

            // Issue JWT token
            var token = GenerateJwtToken(user);
            var roles = await _userManager.GetRolesAsync(user);

            user.LastLoginDate = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("User logged in with 2FA: {UserId}", user.Id);

            return Ok(new ApiResponse<LoginResponse>
            {
                Success = true,
                Message = "Login successful with 2FA.",
                Data = new LoginResponse
                {
                    Token = token,
                    ExpirationMinutes = 60,
                    Roles = roles.ToList(),
                    Email = user.Email,
                    UserId = user.Id
                }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // GetRecoveryCodes — returns recovery codes for a user.
        //
        // GET /api/2fa/recovery-codes
        // Requires authentication (user or admin)
        //
        // Note: In a real API, you'd only return recovery codes ONCE (when 2FA
        // is enabled). After that, the codes are stored hashed and cannot be
        // retrieved. If the user loses their codes, they need to disable and
        // re-enable 2FA (with admin help if needed).
        //
        // For this tutorial, we show how recovery codes are generated and
        // the concept of one-time-use codes.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("recovery-codes")]
        [Authorize]  // User or admin
        public async Task<IActionResult> GetRecoveryCodes()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User not found."
                });
            }

            if (!user.TwoFactorEnabled)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "2FA is not enabled.",
                    Errors = new List<string> { "Recovery codes are only available when 2FA is enabled." }
                });
            }

            // Generate new recovery codes (in production, you might show existing ones
            // if they haven't been used, or force regeneration)
            var recoveryCodesTask = _userManager.GenerateTwoFactorRecoveryCodesAsync(user);
            recoveryCodesTask.Wait();
            var recoveryCodes = recoveryCodesTask.Result;

            _logger.LogInformation("Recovery codes regenerated for user {UserId}", userId);

            return Ok(new ApiResponse<RecoveryCodesResponse>
            {
                Success = true,
                Message = "New recovery codes generated. Save them immediately — they cannot be retrieved again.",
                Data = new RecoveryCodesResponse
                {
                    Codes = recoveryCodes.ToList(),
                    Message = "Save these codes in a safe place. Each code can be used once to login without your authenticator app."
                }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // Recover — login with a recovery code.
        //
        // POST /api/2fa/recover
        // Body: ConsumeRecoveryCodeRequest (code)
        // Response: JWT token (if code is valid)
        //
        // Flow:
        //   1. Find user by email (provided in request)
        //   2. Verify the recovery code (ConsumeTwoFactorRecoveryCodeAsync)
        //   3. If valid, issue JWT token
        //   4. If invalid, return error
        //
        // Recovery codes are one-time-use — after a successful login, the code
        // is consumed and cannot be used again.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("recover")]
        [AllowAnonymous]
        public async Task<IActionResult> RecoverWithCode([FromBody] ConsumeRecoveryCodeRequest request)
        {
            if (string.IsNullOrEmpty(request.Code))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Recovery code is required."
                });
            }

            // For this example, we recover for the current authenticated user
            // or require email in the request. We'll use the authenticated user.
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User must be identified.",
                    Errors = new List<string> { "Please provide email or authenticate first." }
                });
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User not found."
                });
            }

            // Consume the recovery code
            var result = await _userManager.ConsumeTwoFactorRecoveryCodeAsync(user, request.Code);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Invalid or used recovery code.",
                    Errors = errors
                });
            }

            // Issue JWT token
            var token = GenerateJwtToken(user);
            var roles = await _userManager.GetRolesAsync(user);

            user.LastLoginDate = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("User logged in with recovery code: {UserId}", user.Id);

            return Ok(new ApiResponse<LoginResponse>
            {
                Success = true,
                Message = "Login successful with recovery code.",
                Data = new LoginResponse
                {
                    Token = token,
                    ExpirationMinutes = 60,
                    Roles = roles.ToList(),
                    Email = user.Email,
                    UserId = user.Id
                }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // Disable — disables 2FA for a user.
        //
        // POST /api/2fa/disable
        // Requires Admin role (or the user themselves)
        //
        // Flow:
        //   1. Find user
        //   2. Set TwoFactorEnabled = false
        //   3. Clear the TOTP secret
        //   4. Return success
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("disable")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Disable2FA([FromBody] LockoutRequest request)
        {
            if (string.IsNullOrEmpty(request.UserId))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User ID is required."
                });
            }

            var user = await _userManager.FindByIdAsync(request.UserId);
            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User not found."
                });
            }

            if (!user.TwoFactorEnabled)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "2FA is not enabled for this user."
                });
            }

            user.TwoFactorEnabled = false;
            user.TwoFactorSecret = null;

            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Failed to disable 2FA.",
                    Errors = errors
                });
            }

            _logger.LogWarning("2FA disabled for user {UserId} by admin", request.UserId);

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Two-factor authentication has been disabled."
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // GenerateJwtToken — same as in AccountController (Video 08).
        // Included here for completeness of the 2FA flow.
        // ─────────────────────────────────────────────────────────────────────────
        private string GenerateJwtToken(ApplicationUser user)
        {
            var jwtKey = _configuration["Jwt:Key"];
            var jwtIssuer = _configuration["Jwt:Issuer"];
            var jwtAudience = _configuration["Jwt:Audience"];

            var securityKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(jwtKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.GivenName, user.FullName ?? string.Empty),
                new Claim("two_factor_enabled", "true")  // Indicator that 2FA was used
            };

            var rolesTask = _userManager.GetRolesAsync(user);
            rolesTask.Wait();
            var roles = rolesTask.Result;

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var token = new JwtSecurityToken(
                issuer: jwtIssuer,
                audience: jwtAudience,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
```

### Add TwoFactorSecret to ApplicationUser

```csharp
// Add this property to ApplicationUser in Models/ApplicationUser.cs:

// ─────────────────────────────────────────────────────────────────────────────
// TwoFactorSecret — TOTP secret for two-factor authentication.
//
// Stored as a base32 string. In production, this should be encrypted
// or hashed before storage. For this tutorial, we store it in plain text
// for simplicity.
//
// Type: string?, nullable (not all users have 2FA enabled)
// ─────────────────────────────────────────────────────────────────────────────
public string? TwoFactorSecret { get; set; }
```

---

## Postman / Swagger Tests

**Test 1 — Enable 2FA:**

```
ENDPOINT: POST https://localhost:7001/api/2fa/enable

AUTH: Bearer token (Admin)

BODY:
{
  "userId": "{userId}"
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "2FA secret generated. Scan the QR code with your authenticator app, then verify.",
  "data": {
    "success": true,
    "secret": "JBSWY3DPEHPK3PXP",
    "qrCodeUri": "otpauth://totp/IdentityApiTutorial:testuser@example.com?secret=JBSWY3DPEHPK3PXP&issuer=IdentityApiTutorial",
    "message": "Scan this QR code with Google Authenticator, Microsoft Authenticator, or Authy."
  },
  "errors": []
}

WHAT THIS MEANS:
- TOTP secret generated (base32 encoded)
- QR code URI created (can be rendered as QR code)
- Client displays the QR code or secret for the user to enter in their authenticator app
- Secret is stored (temporarily) for verification
```

**Test 2 — Verify 2FA Setup:**

```
Pre-requisite: User has entered the secret in their authenticator app
and generated the first 6-digit code.

ENDPOINT: POST https://localhost:7001/api/2fa/verify

AUTH: Bearer token (Admin)

BODY:
{
  "code": "123456"  // Current 6-digit code from authenticator app
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "2FA enabled successfully.",
  "data": {
    "success": true,
    "message": "Two-factor authentication is now enabled.",
    "recoveryCodes": ["abcd1234", "efgh5678", "ijkl9012", "..."]
  },
  "errors": []
}

WHAT THIS MEANS:
- TOTP code verified (matches server's calculation)
- 2FA enabled (TwoFactorEnabled = true)
- Recovery codes generated (show to user once)
```

**Test 3 — 2FA Login (Step 1 — Password Valid, 2FA Required):**

```
ENDPOINT: POST https://localhost:7001/api/2fa/login

BODY:
{
  "email": "testuser@example.com",
  "password": "Test@123456"
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Two-factor authentication required.",
  "data": {
    "requires2FA": true,
    "tempToken": "a1b2c3d4e5f6...",
    "message": "Enter the 6-digit code from your authenticator app."
  },
  "errors": []
}

WHAT THIS MEANS:
- Password is valid
- 2FA is enabled for this user
- Temporary token issued (valid for 2 minutes)
- Client must now call /api/2fa/login-verify with the temp token and TOTP code
```

**Test 4 — 2FA Login (Step 2 — Verify TOTP, Get JWT):**

```
ENDPOINT: POST https://localhost:7001/api/2fa/login-verify

BODY:
{
  "code": "654321",  // Current TOTP code
  "tempToken": "a1b2c3d4e5f6..."  // From step 1
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Login successful with 2FA.",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "expirationMinutes": 60,
    "roles": ["User"],
    "email": "testuser@example.com",
    "userId": "{userId}"
  },
  "errors": []
}

WHAT THIS MEANS:
- TOTP code verified
- Temporary token consumed
- JWT token issued (with "two_factor_enabled": "true" claim)
- User is fully logged in
```

**Test 5 — Login Without 2FA (Normal User):**

```
ENDPOINT: POST https://localhost:7001/api/2fa/login

BODY:
{
  "email": "userwithout2fa@example.com",
  "password": "Test@123456"
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Login successful.",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "expirationMinutes": 60,
    "roles": ["User"],
    "email": "userwithout2fa@example.com",
    "userId": "{userId}"
  },
  "errors": []
}

WHAT THIS MEANS:
- Password valid, 2FA not enabled
- JWT issued directly (no temporary token, no second step)
- Same flow as regular login (Video 08)
```

**Test 6 — Login with Recovery Code:**

```
END-POINT: POST https://localhost:7001/api/2fa/recover

BODY:
{
  "code": "abcd1234"  // One of the recovery codes
}

AUTH: Bearer token (or email in request)

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Login successful with recovery code.",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    ...
  },
  "errors": []
}

WHAT THIS MEANS:
- Recovery code consumed (one-time use — cannot be used again)
- JWT issued
- Recovery codes should be stored safely by the user
```

**Test 7 — Disable 2FA:**

```
ENDPOINT: POST https://localhost:7001/api/2fa/disable

AUTH: Bearer token (Admin)

BODY:
{
  "userId": "{userId}"
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Two-factor authentication has been disabled."
}

WHAT THIS MEANS:
- 2FA disabled (TwoFactorEnabled = false)
- TOTP secret cleared
- User can login with password only (no 2FA challenge)
```

---

# Video 16 — External Login Providers in API: Google, Facebook, Microsoft

## Theory & Definitions

### What Are External Login Providers?

External login providers (also called OAuth providers, social login, or external authentication) allow users to log in using their accounts from other services — Google, Facebook, Microsoft, GitHub, etc. Instead of creating a new password, the user authenticates with the external provider and your API receives a token or assertion that identifies the user.

### How External Login Works (OAuth 2.0 / OpenID Connect)

The general flow:

1. **User clicks "Login with Google"** on your client
2. **Client redirects to Google** (or calls Google's API directly from the client)
3. **User authenticates with Google** (username + password on Google's site)
4. **Google returns an authorization code or token** to the client
5. **Client sends the code/token to your API** (external login endpoint)
6. **Your API validates the token with Google** (or trusts the code if it was obtained securely)
7. **Your API finds or creates a local user account** linked to the external provider
8. **Your API issues a JWT token** for the local API authentication

### Two Approaches for APIs

**Approach 1: Client-side OAuth + API validation**
- The client handles the OAuth flow (redirects, callbacks)
- The client receives an access token from Google/Facebook
- The client sends the access token to your API
- Your API validates the token with the provider (calls Google's userinfo endpoint)
- Your API issues its own JWT

Pros: Simpler server-side logic, client handles OAuth redirects
Cons: API needs to validate tokens with external providers (network calls, rate limits)

**Approach 2: Server-side OAuth (Identity's external login)**
- Your API handles the OAuth flow (callback endpoints)
- Your API receives the authorization code
- Your API exchanges the code for an access token
- Your API uses the access token to get user info
- Your API issues its own JWT

Pros: API controls the OAuth flow, more secure (client never sees tokens)
Cons: More complex server-side implementation, requires callback URLs

For this tutorial, we'll show Approach 1 (client-side OAuth, API validates tokens) because it's simpler for an API and doesn't require Identity's cookie-based external login infrastructure.

### External Login with Identity

Identity supports external login through `AddExternalIdentity` or manual provider registration. The external login flow in Identity is cookie-based (MVC pattern) — it creates a cookie after external login. For an API, we bypass this and directly create the local user + issue JWT.

### Key Concepts

| Concept | Purpose |
|---------|---------|
| **External provider** | The service that authenticates the user (Google, Facebook, etc.) |
| **Client ID / Client Secret** | Credentials registered with the provider (identify your app to the provider) |
| **Redirect URI** | Where the provider sends the user after authentication (your callback URL) |
| **Authorization code** | Short-lived code returned by the provider (exchanged for access token) |
| **Access token** | Token that lets your API call the provider's API (get user info) |
| **ID token** | Token that identifies the user (OpenID Connect) — contains user claims |
| **Scope** | What permissions your app requests from the provider (profile, email, etc.) |
| **External login** | A link between a local user and an external provider (stored in AspNetUserLogins) |

### External Login Storage

When a user logs in with an external provider, Identity stores the linkage in `AspNetUserLogins`:

| Column | Purpose |
|--------|---------|
| `LoginProvider` | The provider name (Google, Facebook, etc.) |
| `ProviderKey` | The user's ID on the provider (Google's sub claim, etc.) |
| `UserId` | The local user's ID (links to AspNetUsers) |

This allows a user to link multiple external providers to one local account (Google + Facebook + Microsoft all point to the same local user).

### "When to Use vs When Not to Use" — External Login

| Decision | Use it | Don't use it |
|----------|--------|--------------|
| External login (Google, etc.) | For consumer apps (easier registration, fewer passwords to manage) | For internal enterprise apps (use corporate SSO instead) |
| Client-side OAuth | When your client is a SPA/mobile app (handles redirects) | When your API is the only interface (need server-side OAuth) |
| Server-side OAuth | When you need to call the provider's API on behalf of the user | When you just need to authenticate (client-side is simpler) |
| Multiple providers | When you want to offer choices to users | When one provider is sufficient (keep it simple) |
| Link multiple providers to one account | When users might use different providers at different times | When each provider creates a separate account (simpler but fragmented) |
| External login without local account | When you trust the provider completely | When you need local user data (profile, roles, etc.) — create a local account linked to the external login |

### Key Insight: External Login Creates or Links a Local User

External login doesn't replace your local user system — it ADDS to it. When a user logs in with Google for the first time, you create a local user account linked to their Google ID. On subsequent logins, you find the existing local user by their Google ID. The local account gives you control over roles, claims, and API-specific data.

---

## 🎬 Video Recording Notes

**Opening (say this):**
> \"External login — letting users log in with Google, Facebook, Microsoft instead of creating a new password. Today we'll implement external login in our API: the OAuth flow, validating external tokens, creating or linking local users, and issuing our own JWT. This is how most modern apps let users sign up quickly and securely.\"

**Show on screen (do this):**
> Show the OAuth flow diagram. Show the external login endpoint (receive external token, validate, find/create user, issue JWT). Show a test with a mock external token (since we can't do real Google OAuth in a tutorial). Show the AspNetUserLogins table after external login.

**Key points to emphasize (say this):**
> \"External login in an API is different from MVC. In MVC, Identity handles the OAuth callback and creates a cookie. In an API, we receive the external token from the client, validate it, find or create the local user, and issue our own JWT. We don't use Identity's cookie-based external login.\"

> \"The client handles the OAuth redirect — your API doesn't need callback URLs. The client gets the access token from Google/Facebook and sends it to your API. Your API validates it by calling the provider's userinfo endpoint (or verifying the ID token signature)."

> \"When a user logs in externally for the first time, you create a local user. You generate a username/email from the provider's data (or let the user choose). You link the external login to the local user (AspNetUserLogins table). On subsequent logins, you find the existing user by their external provider key.

> \"Users can link multiple external providers to one local account. Google + Facebook + Microsoft can all point to the same local user. This is stored in AspNetUserLogins (one row per provider per user).

> \"Always validate external tokens server-side. Don't trust the client's word that 'this is a valid Google token.' Call Google's userinfo endpoint or verify the ID token's signature. This prevents clients from forging external login requests.\"

**Analogy (say this):**
> \"External login is like showing an ID from another country. Your API is the bouncer. The user shows their Google ID (external token). You check with Google (validate the token). If Google says 'yes, this is a real person,' you give them a local pass (your JWT) that works inside your venue. You also write down that this person is linked to Google (AspNetUserLogins) so next time they show the same Google ID, you recognize them.\"

**Common viewer question:**
> \"Do I need to register my API with Google/Facebook?\" — Yes. You need a Client ID and Client Secret from each provider's developer console. These identify your app to the provider. The redirect URI must be registered too (for server-side OAuth). For client-side OAuth, the origins where your client runs must be registered (CORS/origin restrictions).

> \"Can I use external login without a local user account?\" — You can, but it's limited. Without a local account, you can't assign roles, store API-specific profile data, or manage the user independently of the external provider. Best practice: create a local account linked to the external login.

> \"What if the user's external account is deleted?\" — The user can't log in with that provider anymore. If they have no other linked providers and no password, they're locked out. Provide a recovery mechanism (recovery codes, admin reset, email login fallback).

**What to show:**
- OAuth flow diagram (client → provider → API)
- External login endpoint (receive token, validate, find/create user, issue JWT)
- Mock external token test (simulate Google response)
- AspNetUserLogins table (linkage between local user and external provider)
- Linking multiple providers to one user (conceptual)
- Postman tests

**What to skip:**
- Full OAuth implementation for each provider (too much for one video — show the pattern, mention that each provider has its own details)
- Server-side OAuth callback endpoints (complex — mention as an alternative, focus on client-side)
- OAuth 2.0 grant types (authorization code, implicit, client credentials) — too deep for this video

---

## Complete Implementation

### File: DTOs/ExternalLoginDtos.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: DTOs/ExternalLoginDtos.cs
// Video 16 — External Login DTOs
// ─────────────────────────────────────────────────────────────────────────────
namespace IdentityApiTutorial.DTOs
{
    public class ExternalLoginRequest
    {
        public string Provider { get; set; } = string.Empty;  // "Google", "Facebook", "Microsoft"
        public string ExternalToken { get; set; } = string.Empty;  // Access token or ID token from provider
        public string Email { get; set; } = string.Empty;  // Email from provider (for account linking)
    }

    public class ExternalLoginResponse
    {
        public bool Success { get; set; }
        public string? Token { get; set; }  // Our JWT token
        public string? Email { get; set; }
        public string? UserId { get; set; }
        public bool IsNewUser { get; set; }  // True if this was a new account creation
        public string? Message { get; set; }
        public List<string>? Roles { get; set; }
    }

    public class LinkExternalLoginRequest
    {
        public string Provider { get; set; } = string.Empty;
        public string ExternalToken { get; set; } = string.Empty;
    }

    public class LinkExternalLoginResponse
    {
        public bool Success { get; set; }
        public string? Message { get; set; }
    }
}
```

### File: Controllers/ExternalLoginController.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Controllers/ExternalLoginController.cs
// Video 16 — External Login Provider Endpoints
// ─────────────────────────────────────────────────────────────────────────────
// Endpoints:
//   - POST /api/external-login — login with external provider token
//   - POST /api/external-login/link — link an external provider to current user
//   - DELETE /api/external-login/unlink — unlink an external provider
//   - GET /api/external-login/providers — list supported providers
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Create this controller
//   - Explain the flow: client gets external token → sends to API → API validates → issues JWT
//   - Show the find-or-create logic
//   - Show the AspNetUserLogins linkage
//   - Demonstrate with a mock external token
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.DTOs;
using IdentityApiTutorial.Models;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ExternalLoginController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly ILogger<ExternalLoginController> _logger;

        public ExternalLoginController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IConfiguration configuration,
            ILogger<ExternalLoginController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _logger = logger;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // Login — login with an external provider token.
        //
        // POST /api/external-login
        // Body: ExternalLoginRequest (provider, externalToken, email)
        // Response: ExternalLoginResponse (JWT token, user info)
        //
        // Flow:
        //   1. Validate the request (provider, token, email)
        //   2. Validate the external token with the provider (mock in this tutorial)
        //   3. Find existing user by external provider key (AspNetUserLogins)
        //   4. If found: issue JWT
        //   5. If not found: check if email exists → link external login to existing user
        //   6. If email doesn't exist: create new user + link external login
        //   7. Issue JWT
        //
        // For this tutorial, we MOCK the external token validation.
        // In production, you'd call the provider's API (Google userinfo, etc.)
        // or verify the ID token signature.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLogin([FromBody] ExternalLoginRequest request)
        {
            if (string.IsNullOrEmpty(request.Provider))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Provider is required.",
                    Errors = new List<string> { "Please specify the login provider (Google, Facebook, etc.)." }
                });
            }

            if (string.IsNullOrEmpty(request.ExternalToken))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "External token is required.",
                    Errors = new List<string> { "Please provide the access token from the external provider." }
                });
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Step 1: Validate the external token with the provider.
            //
            // In production, this would:
            //   - Google: Call https://www.googleapis.com/oauth2/v2/userinfo with the access token
            //     → returns user profile (email, name, picture, sub)
            //   - Facebook: Call https://graph.facebook.com/me?fields=id,name,email with the access token
            //   - Microsoft: Call https://graph.microsoft.com/v1.0/me with the access token
            //
            // For this tutorial, we MOCK the validation. We trust that the token is valid
            // and use the email provided by the client (in production, the email comes from
            // the provider's response, not the client).
            //
            // STRONGER APPROACH: Verify the ID token's signature (JWT with provider's public key).
            // This proves the token came from the provider and hasn't been tampered with.
            // ─────────────────────────────────────────────────────────────────────────
            var externalUserInfo = await ValidateExternalTokenAsync(request.Provider, request.ExternalToken);

            if (externalUserInfo == null)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Invalid external token.",
                    Errors = new List<string> { $"The token from {request.Provider} is invalid or expired." }
                });
            }

            // Use the email from the provider (not from the client request)
            var email = externalUserInfo.Email;

            // ─────────────────────────────────────────────────────────────────────────
            // Step 2: Find existing user by external login.
            //
            // Check if this external provider key is already linked to a local user.
            // This handles the case where the user has logged in with this provider before.
            // ─────────────────────────────────────────────────────────────────────────
            var user = await FindUserByExternalProviderAsync(request.Provider, externalUserInfo.ProviderKey);

            if (user != null)
            {
                // User exists with this external login — issue JWT
                _logger.LogInformation("External login: existing user {UserId} logged in via {Provider}",
                    user.Id, request.Provider);

                var token = GenerateJwtToken(user);
                var roles = await _userManager.GetRolesAsync(user);

                // Update last login
                user.LastLoginDate = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);

                return Ok(new ApiResponse<ExternalLoginResponse>
                {
                    Success = true,
                    Message = "Login successful.",
                    Data = new ExternalLoginResponse
                    {
                        Success = true,
                        Token = token,
                        Email = user.Email,
                        UserId = user.Id,
                        IsNewUser = false,
                        Roles = roles.ToList()
                    }
                });
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Step 3: User not found by external provider — check by email.
            //
            // If the user has an existing account with this email (registered with password),
            // link the external provider to the existing account. This allows the user to
            // log in with either password or external provider.
            // ─────────────────────────────────────────────────────────────────────────
            var existingUserByEmail = await _userManager.FindByEmailAsync(email);

            if (existingUserByEmail != null)
            {
                // Link external provider to existing user
                var linkResult = await _userManager.AddLoginAsync(existingUserByEmail,
                    new UserLoginInfo(request.Provider, externalUserInfo.ProviderKey, request.Provider));

                if (!linkResult.Succeeded)
                {
                    // Linking failed — might already be linked to another account
                    var errors = linkResult.Errors.Select(e => e.Description).ToList();
                    return BadRequest(new ApiResponse<object>
                    {
                        Success = false,
                        Message = "Could not link external login.",
                        Errors = errors
                    });
                }

                _logger.LogInformation("External login: linked {Provider} to existing user {UserId}",
                    request.Provider, existingUserByEmail.Id);

                var token = GenerateJwtToken(existingUserByEmail);
                var roles = await _userManager.GetRolesAsync(existingUserByEmail);

                existingUserByEmail.LastLoginDate = DateTime.UtcNow;
                await _userManager.UpdateAsync(existingUserByEmail);

                return Ok(new ApiResponse<ExternalLoginResponse>
                {
                    Success = true,
                    Message = "Login successful. External account linked.",
                    Data = new ExternalLoginResponse
                    {
                        Success = true,
                        Token = token,
                        Email = existingUserByEmail.Email,
                        UserId = existingUserByEmail.Id,
                        IsNewUser = false,
                        Roles = roles.ToList()
                    }
                });
            }

            // ─────────────────────────────────────────────────────────────────────────
            // Step 4: No existing user — create a new one.
            //
            // Create a local user account linked to the external provider.
            // Use the provider's email and name for the local account.
            //
            // IMPORTANT: Some providers don't return an email (or the email is unverified).
            // In that case, you might need to ask the user to provide an email, or use
            // a placeholder email. For this tutorial, we assume the email is available.
            // ─────────────────────────────────────────────────────────────────────────
            var newUser = new ApplicationUser
            {
                UserName = email,
                NormalizedUserName = email.ToUpperInvariant(),
                Email = email,
                NormalizedEmail = email.ToUpperInvariant(),
                EmailConfirmed = true,  // External provider verified the email (typically)
                FullName = externalUserInfo.FullName,
                IsActive = true,
                DateJoined = DateTime.UtcNow
            };

            var createResult = await _userManager.CreateAsync(newUser, Guid.NewGuid().ToString("N"));
            // Note: We use a random password because the user doesn't have one.
            // The user can set a password later via a "set password" endpoint (not shown).

            if (!createResult.Succeeded)
            {
                var errors = createResult.Errors.Select(e => e.Description).ToList();
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Failed to create user.",
                    Errors = errors
                });
            }

            // Link the external provider to the new user
            var loginInfo = new UserLoginInfo(request.Provider, externalUserInfo.ProviderKey, request.Provider);
            var linkResult = await _userManager.AddLoginAsync(newUser, loginInfo);

            if (!linkResult.Succeeded)
            {
                // Clean up — delete the user we just created (rollback)
                await _userManager.DeleteAsync(newUser);

                var errors = linkResult.Errors.Select(e => e.Description).ToList();
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Failed to link external login.",
                    Errors = errors
                });
            }

            // Assign default "User" role
            await _userManager.AddToRoleAsync(newUser, "User");

            _logger.LogInformation("External login: new user {UserId} created via {Provider}",
                newUser.Id, request.Provider);

            var token = GenerateJwtToken(newUser);
            var roles = await _userManager.GetRolesAsync(newUser);

            return Ok(new ApiResponse<ExternalLoginResponse>
            {
                Success = true,
                Message = "Account created and login successful.",
                Data = new ExternalLoginResponse
                {
                    Success = true,
                    Token = token,
                    Email = newUser.Email,
                    UserId = newUser.Id,
                    IsNewUser = true,
                    Roles = roles.ToList()
                }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // Link — links an external provider to the currently authenticated user.
        //
        // POST /api/external-login/link
        // Auth: Required (authenticated user)
        // Body: LinkExternalLoginRequest (provider, externalToken)
        //
        // Use case: User wants to link their Google account to their existing local account
        // so they can log in with Google in the future.
        //
        // Flow:
        //   1. Get current user
        //   2. Validate external token
        //   3. Check if this provider is already linked (to another account?)
        //   4. Link the provider to the current user
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("link")]
        [Authorize]
        public async Task<IActionResult> LinkExternalLogin([FromBody] LinkExternalLoginRequest request)
        {
            if (string.IsNullOrEmpty(request.Provider) || string.IsNullOrEmpty(request.ExternalToken))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Provider and external token are required."
                });
            }

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return Unauthorized(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User not authenticated."
                });
            }

            // Validate external token
            var externalUserInfo = await ValidateExternalTokenAsync(request.Provider, request.ExternalToken);
            if (externalUserInfo == null)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Invalid external token."
                });
            }

            // Check if this external login is already linked to ANOTHER user
            var existingUser = await FindUserByExternalProviderAsync(request.Provider, externalUserInfo.ProviderKey);
            if (existingUser != null && existingUser.Id != userId)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "This external account is already linked to another user.",
                    Errors = new List<string> { "This external login is associated with a different account. Unlink it from that account first, or use a different external account." }
                });
            }

            // Check if already linked to this user
            var existingLink = await _userManager.FindLoginAsync(user, request.Provider, externalUserInfo.ProviderKey);
            if (existingLink != null)
            {
                return Ok(new ApiResponse<LinkExternalLoginResponse>
                {
                    Success = true,
                    Message = "This external account is already linked to your account."
                });
            }

            // Link the external provider
            var result = await _userManager.AddLoginAsync(user,
                new UserLoginInfo(request.Provider, externalUserInfo.ProviderKey, request.Provider));

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Failed to link external account.",
                    Errors = errors
                });
            }

            _logger.LogInformation("External account {Provider} linked to user {UserId}",
                request.Provider, userId);

            return Ok(new ApiResponse<LinkExternalLoginResponse>
            {
                Success = true,
                Message = $"Your {request.Provider} account has been linked."
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // Unlink — removes an external provider link from the current user.
        //
        // DELETE /api/external-login/unlink?provider={provider}
        // Auth: Required (authenticated user)
        //
        // Use case: User wants to remove their Google link (switch to a different Google
        // account, or no longer want to use Google login).
        // ─────────────────────────────────────────────────────────────────────────
        [HttpDelete("unlink")]
        [Authorize]
        public async Task<IActionResult> UnlinkExternalLogin([FromQuery] string provider)
        {
            if (string.IsNullOrEmpty(provider))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Provider is required."
                });
            }

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return Unauthorized(new ApiResponse<object>
                {
                    Success = false,
                    Message = "User not authenticated."
                });
            }

            // Get the user's external logins
            var logins = await _userManager.GetLoginsAsync(user);
            var externalLogin = logins.FirstOrDefault(l => l.LoginProvider == provider);

            if (externalLogin == null)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = $"No {provider} account is linked to this user."
                });
            }

            // Cannot unlink the last login method (user would be locked out)
            var hasPassword = await _userManager.HasPasswordAsync(user);
            if (!hasPassword && logins.Count <= 1)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Cannot unlink the last login method. Add a password or another external account first."
                });
            }

            // Remove the external login
            var result = await _userManager.RemoveLoginAsync(user, provider, externalLogin.ProviderKey);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Failed to unlink external account.",
                    Errors = errors
                });
            }

            _logger.LogInformation("External account {Provider} unlinked from user {UserId}",
                provider, userId);

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = $"Your {provider} account has been unlinked."
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // GetProviders — returns the list of supported external providers.
        //
        // GET /api/external-login/providers
        // Public endpoint — clients need to know which providers are available.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("providers")]
        [AllowAnonymous]
        public IActionResult GetSupportedProviders()
        {
            var providers = new List<object>
            {
                new { Name = "Google", DisplayName = "Continue with Google", Icon = "google" },
                new { Name = "Facebook", DisplayName = "Continue with Facebook", Icon = "facebook" },
                new { Name = "Microsoft", DisplayName = "Continue with Microsoft", Icon = "microsoft" }
            };

            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "Supported external login providers.",
                Data = providers
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // ValidateExternalTokenAsync — MOCK implementation.
        //
        // In production, this would call the provider's API to validate the token
        // and get user information. For this tutorial, we return mock data.
        //
        // This method demonstrates the pattern. Replace with real provider calls
        // in a production implementation.
        // ─────────────────────────────────────────────────────────────────────────
        private async Task<ExternalUserInfo> ValidateExternalTokenAsync(string provider, string token)
        {
            // MOCK: In production, call the provider's API
            // Examples:
            //   - Google: HttpClient.GetAsync("https://www.googleapis.com/oauth2/v2/userinfo",
            //       headers: { Authorization = "Bearer " + token })
            //   - Facebook: HttpClient.GetAsync("https://graph.facebook.com/me?fields=id,name,email",
            //       headers: { Authorization = "Bearer " + token })
            //   - Microsoft: HttpClient.GetAsync("https://graph.microsoft.com/v1.0/me",
            //       headers: { Authorization = "Bearer " + token })

            // Simulate async delay
            await Task.Delay(10);

            // Mock validation: accept any non-empty token
            if (string.IsNullOrEmpty(token))
            {
                return null;
            }

            // Generate a mock provider key (in production, this comes from the provider)
            var providerKey = $"{provider}_{Guid.NewGuid().ToString("N")}";

            // Mock user info — in production, parse the provider's response
            return new ExternalUserInfo
            {
                ProviderKey = providerKey,
                Email = $"user_{provider.ToLower()}@example.com",  // Mock email
                FullName = $"Mock User from {provider}"  // Mock name
            };
        }

        // ─────────────────────────────────────────────────────────────────────────
        // FindUserByExternalProviderAsync — finds a user by their external login.
        //
        // Checks AspNetUserLogins for a matching LoginProvider + ProviderKey.
        // ─────────────────────────────────────────────────────────────────────────
        private async Task<ApplicationUser?> FindUserByExternalProviderAsync(string provider, string providerKey)
        {
            // Identity doesn't have a direct "find by external login" method.
            // We need to query all users and check their logins, or use a custom query.
            //
            // For a small user base, we can iterate. For large user bases, use a
            // direct SQL query on AspNetUserLogins.
            var users = _userManager.Users.ToList();
            foreach (var user in users)
            {
                var logins = await _userManager.GetLoginsAsync(user);
                var match = logins.FirstOrDefault(l =>
                    l.LoginProvider == provider && l.ProviderKey == providerKey);
                if (match != null)
                {
                    return user;
                }
            }

            return null;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // GenerateJwtToken — same as in AccountController (Video 08).
        // ─────────────────────────────────────────────────────────────────────────
        private string GenerateJwtToken(ApplicationUser user)
        {
            var jwtKey = _configuration["Jwt:Key"];
            var jwtIssuer = _configuration["Jwt:Issuer"];
            var jwtAudience = _configuration["Jwt:Audience"];

            var securityKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(jwtKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.GivenName, user.FullName ?? string.Empty),
                new Claim("external_login", "true")  // Indicator that this was an external login
            };

            var rolesTask = _userManager.GetRolesAsync(user);
            rolesTask.Wait();
            var roles = rolesTask.Result;

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var token = new JwtSecurityToken(
                issuer: jwtIssuer,
                audience: jwtAudience,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ExternalUserInfo — mock external provider user information.
    // In production, this would come from the provider's API response.
    // ─────────────────────────────────────────────────────────────────────────────
    public class ExternalUserInfo
    {
        public string ProviderKey { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
    }
}
```

---

## Postman / Swagger Tests

**Test 1 — Get Supported Providers:**

```
ENDPOINT: GET https://localhost:7001/api/external-login/providers

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Supported external login providers.",
  "data": [
    { "name": "Google", "displayName": "Continue with Google", "icon": "google" },
    { "name": "Facebook", "displayName": "Continue with Facebook", "icon": "facebook" },
    { "name": "Microsoft", "displayName": "Continue with Microsoft", "icon": "microsoft" }
  ],
  "errors": []
}

WHAT THIS MEANS:
- Client can fetch the list of available providers
- Display "Login with Google" buttons, etc.
```

**Test 2 — External Login (New User — Create Account):**

```
ENDPOINT: POST https://localhost:7001/api/external-login

BODY:
{
  "provider": "Google",
  "externalToken": "mock-token-12345",
  "email": "user_google@example.com"
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Account created and login successful.",
  "data": {
    "success": true,
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "email": "user_google@example.com",
    "userId": "{new-user-id}",
    "isNewUser": true,
    "roles": ["User"]
  },
  "errors": []
}

WHAT THIS MEANS:
- New user created (no existing account with this email or provider)
- External login linked (AspNetUserLogins row created)
- JWT issued
- isNewUser = true (client can show "Welcome!" message)
```

**Test 3 — External Login (Existing User — Link to Existing Account):**

```
Pre-requisite: User registered with password (Video 07).

ENDPOINT: POST https://localhost:7001/api/external-login

BODY:
{
  "provider": "Google",
  "externalToken": "mock-token-67890",
  "email": "testuser@example.com"  // Same email as existing user
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Login successful. External account linked.",
  "data": {
    "success": true,
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "email": "testuser@example.com",
    "userId": "{existing-user-id}",
    "isNewUser": false,
    "roles": ["User"]
  },
  "errors": []
}

WHAT THIS MEANS:
- Existing user found by email
- Google account linked to existing user (AspNetUserLogins row added)
- JWT issued for existing user
- isNewUser = false
- User can now login with either password OR Google
```

**Test 4 — External Login (Returning User):**

```
Pre-requisite: User already has Google linked (Test 3).

ENDPOINT: POST https://localhost:7001/api/external-login

BODY:
{
  "provider": "Google",
  "externalToken": "mock-token-12345"  // Same provider key as before
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Login successful.",
  "data": {
    "success": true,
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "email": "testuser@example.com",
    "userId": "{existing-user-id}",
    "isNewUser": false,
    "roles": ["User"]
  },
  "errors": []
}

WHAT THIS MEANS:
- User found by external provider key (AspNetUserLogins lookup)
- No new account creation, no linking needed
- JWT issued directly
```

**Test 5 — Link External Account to Current User:**

```
ENDPOINT: POST https://localhost:7001/api/external-login/link

AUTH: Bearer token (existing user)

BODY:
{
  "provider": "Facebook",
  "externalToken": "mock-facebook-token"
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Your Facebook account has been linked."
}

WHAT THIS MEANS:
- Facebook account linked to the current user
- User can now login with Facebook in addition to their current methods
```

**Test 6 — Unlink External Account:**

```
ENDPOINT: DELETE https://localhost:7001/api/external-login/unlink?provider=Facebook

AUTH: Bearer token (user with Facebook linked)

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Your Facebook account has been unlinked."
}

WHAT THIS MEANS:
- Facebook login removed from the user's account
- User can no longer login with Facebook (unless they relink)
- AspNetUserLogins row deleted
```

**Test 7 — Database Verification:**

```
After external login, check AspNetUserLogins:

SELECT * FROM AspNetUserLogins WHERE UserId = '{userId}'

EXPECTED:
LoginProvider    ProviderKey              UserId
Google           google_abc123...         {userId}
Facebook         facebook_def456...       {userId}

This shows:
- User has two external logins (Google, Facebook)
- Each has a unique ProviderKey (the ID from the provider)
- Both link to the same local user
```

---

# Video 17 — Token Providers: Email Confirmation, Password Reset, Custom Providers

## Theory & Definitions

### What Are Token Providers?

Token providers generate and validate tokens for specific purposes:
- **Email confirmation** — token sent to user's email to confirm their address
- **Password reset** — token sent to user's email to reset their password
- **External login** — token for linking external accounts (less common)

Each token provider has:
- A generator (creates the token)
- A validator (checks if the token is valid)
- A lifetime (how long the token is valid)
- A storage mechanism (how the token is stored — usually in AspNetUserTokens)

### Email Confirmation Flow

1. **User registers** → `EmailConfirmed = false`
2. **Generate email confirmation token** → `UserManager.GenerateEmailConfirmationTokenAsync(user)`
3. **Send token to user's email** → via email service (SMTP, SendGrid, etc.)
4. **User clicks link** → link contains the token (or code)
5. **API validates token** → `UserManager.ConfirmEmailAsync(user, token)`
6. **If valid** → `EmailConfirmed = true`, user can now login

### Token Generation — How It Works

Identity generates tokens using a secure random value, stored in `AspNetUserTokens`:

```csharp
// Generate a token
var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
// token is a string — typically a base64-encoded random value

// The token is stored in AspNetUserTokens:
//   UserId = user.Id
//   LoginProvider = "Email" (or "ResetPassword")
//   Name = "Confirmation" (or "ResetPassword")
//   Value = token (the generated value)
```

When the user provides the token, Identity looks it up in `AspNetUserTokens` and compares.

### Token Lifetime

Tokens have a lifetime — they expire after a certain period:

| Token Type | Default Lifetime | Configurable |
|------------|-----------------|--------------|
| Email confirmation | 24 hours (typically) | Yes, via token provider options |
| Password reset | 1 hour (typically) | Yes, via token provider options |

Configured in Program.cs:

```csharp
options.Tokens.EmailConfirmationTokenProvider = "EmailConfirmation";
options.Tokens.ChangeEmailTokenProvider = "ChangeEmail";
options.Tokens.ResetPasswordTokenProvider = "ResetPassword";
options.Tokens.ExternalLoginTokenProvider = "ExternalLogin";
options.Tokens.ErrorCodeForIncorrectToken = "InvalidToken";

// Token lifetime (in minutes) — configured per provider
// options.TokenProviders["EmailConfirmation"].TokenLifetime = 60;  // Not directly available
// Use a custom token provider to set custom lifetimes
```

### Email Confirmation Endpoint

```csharp
[HttpPost("confirm-email")]
public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailRequest request)
{
    var user = await _userManager.FindByEmailAsync(request.Email);
    if (user == null) { return NotFound(); }

    var result = await _userManager.ConfirmEmailAsync(user, request.Token);
    if (result.Succeeded)
    {
        return Ok(new { success = true, message = "Email confirmed." });
    }
    else
    {
        return BadRequest(new { success = false, errors = result.Errors });
    }
}
```

### Password Reset Flow

1. **User requests password reset** → provide email
2. **Generate reset token** → `UserManager.GeneratePasswordResetTokenAsync(user)`
3. **Send token to user's email** → via email service
4. **User submits new password + token** → `UserManager.ResetPasswordAsync(user, token, newPassword)`
5. **If valid** → password is changed, token is consumed

### Password Reset Endpoint

```csharp
// Step 1: Request reset (send email to user)
[HttpPost("forgot-password")]
public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
{
    var user = await _userManager.FindByEmailAsync(request.Email);
    if (user == null)
    {
        // Don't reveal whether email exists — return same response either way
        return Ok(new { success = true, message = "If the email exists, a reset link has been sent." });
    }

    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
    // Send email with token...

    return Ok(new { success = true, message = "If the email exists, a reset link has been sent." });
}

// Step 2: Reset password (user provides token + new password)
[HttpPost("reset-password")]
public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
{
    var user = await _userManager.FindByEmailAsync(request.Email);
    if (user == null) { return BadRequest(); }

    var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);
    if (result.Succeeded)
    {
        return Ok(new { success = true, message = "Password reset successfully." });
    }
    else
    {
        return BadRequest(new { success = false, errors = result.Errors });
    }
}
```

### Custom Token Provider

You can create a custom token provider for custom token types:

```csharp
public class CustomTokenProvider : IUserTokenProvider<ApplicationUser, string>
{
    public Task<string> GenerateAsync(string purpose, UserManager<ApplicationUser> manager, ApplicationUser user)
    {
        // Generate a token for the given purpose
        var token = GenerateToken();
        // Store it... (or return it and store it separately)
        return Task.FromResult(token);
    }

    public Task<bool> ValidateAsync(string purpose, string token, UserManager<ApplicationUser> manager, ApplicationUser user)
    {
        // Validate the token
        return Task.FromResult(ValidateToken(token));
    }

    public Task<string?> GenerateAsync(string purpose, UserManager<ApplicationUser> manager, ApplicationUser user, SecurityTokenDescriptor descriptor)
    {
        // For JWT-based tokens (more advanced)
        return Task.FromResult<string?>(null);
    }
}
```

Register in Program.cs:
```csharp
options.Tokens.AddTokenProvider("CustomToken", typeof(CustomTokenProvider));
```

### "When to Use vs When Not to Use" — Token Providers

| Decision | Use it | Don't use it |
|----------|--------|--------------|
| Email confirmation | For production APIs (verify email ownership) | For internal tools (email verification is overhead) |
| Password reset | For any user-facing API (users forget passwords) | For admin-only APIs (admin resets passwords) |
| Short token lifetime (1 hour) | For password reset (security) | For email confirmation (users might not check email quickly) |
| Long token lifetime (24-72 hours) | For email confirmation (user might not check email immediately) | For password reset (too long — security risk) |
| Custom token provider | For custom token types (approval tokens, invitation tokens) | For standard email confirmation/password reset (built-in providers work) |
| Email service integration | For production (SendGrid, SES, SMTP) | For development (console logging, local file) |
| Token in URL (email link) | For email confirmation and password reset (standard pattern) | For sensitive operations (tokens in URLs can be leaked via referer headers) |

### Key Insight: Tokens Are Temporary Credentials

Email confirmation and password reset tokens are temporary credentials. They grant a specific privilege (confirm email, reset password) for a limited time. They should be:
- **Random** — not guessable
- **Single-use** — consumed after use
- **Time-limited** — expire after a reasonable period
- **Securely transmitted** — via email (not logged, not in URLs that leak)

Treat tokens with the same care as passwords — they're secrets that grant access.

---

## 🎬 Video Recording Notes

**Opening (say this):**
> \"Token providers — the system that generates and validates tokens for email confirmation and password reset. Today we'll build the email confirmation endpoint, the password reset flow (two steps: request reset, submit new password), and understand how tokens work under the hood. These are essential features for any user-facing API.\"

**Show on screen (do this):**
> Show the email confirmation endpoint. Show the password reset endpoints (forgot-password, reset-password). Show the token in the database (AspNetUserTokens). Demonstrate the full flow: register → confirm email → login, and forgot password → reset password → login with new password.

**Key points to emphasize (say this):**
> \"Email confirmation tokens are generated when the user registers. The token is sent to their email. When they click the link (or paste the code), the API validates the token and sets EmailConfirmed = true. Until then, the user can't login (if AllowOnlyEmailConfirmedUsersToLogin = true).\"

> \"Password reset tokens work in two steps. First, the user requests a reset (provides email). The API generates a token and sends it to their email. Then, the user submits the token + new password. The API validates the token and changes the password. The token is single-use — it can only be used once.\"

> \"Tokens are stored in AspNetUserTokens. Each token has a UserId, LoginProvider (purpose), Name (type), and Value (the token string). When the token is used, it's removed from the table (or marked as used). This is how Identity prevents token reuse.\"

> \"Token lifetime matters. Email confirmation tokens should live longer (24 hours — users might not check email immediately). Password reset tokens should live shorter (1 hour — security). Configure these per provider in Program.cs.\"

> \"Never reveal whether an email exists when a user requests a password reset. Return the same response regardless: 'If the email exists, a reset link has been sent.' This prevents email enumeration attacks.\"

**Analogy (say this):**
> \"Email confirmation is like verifying your address when you move. The post office sends a letter to your new address. You have to sign for it (click the link) to prove you live there. Until you sign, your mail isn't delivered (you can't login). The letter has an expiration date — if you don't sign within 24 hours, you need a new letter.\"

> \"Password reset is like losing your keys and calling a locksmith. You prove you own the house (email access), the locksmith gives you a temporary key (reset token), and you use that key to make a new lock (new password). The temporary key works once and then breaks (single-use token).\"\"

**Common viewer question:**
> \"Can I resend the confirmation email?\" — Yes. Create an endpoint that generates a new token and sends a new email. The old token is still valid until it expires (or you invalidate it by changing the user's SecurityStamp).

> \"What if the user's email is wrong?\" — Email confirmation catches this. If the email is wrong, the confirmation email goes to the wrong address. The user can't confirm and can't login. They need to update their email (which requires a different token — change email token).

> \"How do I send confirmation emails in development?\" — Use a local SMTP server (Papercut, MailHog), a mock email service, or just log the email to the console. Don't use a real email service in development (you'll spam real addresses).

**What to show:**
- Email confirmation endpoint (POST /api/account/confirm-email)
- Forgot password endpoint (POST /api/account/forgot-password)
- Reset password endpoint (POST /api/account/reset-password)
- Token storage in AspNetUserTokens (database query)
- Full flow demonstration: register → confirm → login, forgot → reset → login
- Postman tests for each endpoint

**What to skip:**
- Custom token provider implementation (complex — mention the pattern, show the built-in providers)
- Email service integration details (SMTP configuration, SendGrid setup — mention as a separate concern)
- Email templates (HTML email design — not relevant to Identity)

---

## Complete Implementation

### File: DTOs/TokenProviderDtos.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: DTOs/TokenProviderDtos.cs
// Video 17 — Token provider endpoints DTOs
// ─────────────────────────────────────────────────────────────────────────────
using System.ComponentModel.DataAnnotations;

namespace IdentityApiTutorial.DTOs
{
    public class ConfirmEmailRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string Token { get; set; } = string.Empty;
    }

    public class ConfirmEmailResponse
    {
        public bool Success { get; set; }
        public string? Message { get; set; }
    }

    public class ForgotPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
    }

    public class ForgotPasswordResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = "If the email exists, a reset link has been sent.";
    }

    public class ResetPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string Token { get; set; } = string.Empty;

        [Required]
        [MinLength(8)]
        public string NewPassword { get; set; } = string.Empty;

        [Required]
        [Compare("NewPassword")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public class ResetPasswordResponse
    {
        public bool Success { get; set; }
        public string? Message { get; set; }
    }

    public class ResendConfirmationRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
    }

    public class ResendConfirmationResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = "If the email exists, a new confirmation link has been sent.";
    }
}
```

### File: Controllers/TokenProviderController.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Controllers/TokenProviderController.cs
// Video 17 — Email Confirmation & Password Reset Endpoints
// ─────────────────────────────────────────────────────────────────────────────
// Endpoints:
//   - POST /api/account/confirm-email — confirm email with token
//   - POST /api/account/resend-confirmation — resend confirmation email
//   - POST /api/account/forgot-password — request password reset
//   - POST /api/account/reset-password — reset password with token
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Create this controller (or add endpoints to AccountController)
//   - Show the token generation and validation
//   - Show the two-step password reset flow
//   - Demonstrate the full email confirmation flow
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.DTOs;
using IdentityApiTutorial.Models;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Controllers
{
    // ─────────────────────────────────────────────────────────────────────────────
    // TokenProviderController — handles token-based operations.
    //
    // For this tutorial, these endpoints are part of AccountController in practice.
    // We separate them here for clarity.
    //
    // All endpoints are [AllowAnonymous] — they're called by users who may not
    // be logged in (forgot password, confirm email).
    // ─────────────────────────────────────────────────────────────────────────────
    [ApiController]
    [Route("api/[controller]")]
    public class TokenProviderController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<TokenProviderController> _logger;

        public TokenProviderController(UserManager<ApplicationUser> userManager, ILogger<TokenProviderController> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // ConfirmEmail — confirms a user's email with a token.
        //
        // POST /api/account/confirm-email
        // Body: ConfirmEmailRequest (email, token)
        // Response: ConfirmEmailResponse (success/failure)
        //
        // Flow:
        //   1. Find user by email
        //   2. If user not found, return error (but don't reveal email existence)
        //   3. Call UserManager.ConfirmEmailAsync(user, token)
        //   4. If valid: EmailConfirmed = true, return success
        //   5. If invalid: return error (token expired, wrong token, etc.)
        //
        // The token is generated by GenerateEmailConfirmationTokenAsync
        // and sent to the user's email during registration.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("confirm-email")]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailRequest request)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList();
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Validation failed.",
                    Errors = errors
                });
            }

            var user = await _userManager.FindByEmailAsync(request.Email);

            if (user == null)
            {
                // Don't reveal that the email doesn't exist
                // Return a generic error
                return BadRequest(new ApiResponse<ConfirmEmailResponse>
                {
                    Success = false,
                    Message = "Email confirmation failed.",
                    Data = new ConfirmEmailResponse
                    {
                        Success = false,
                        Message = "The confirmation link is invalid or has expired."
                    }
                });
            }

            var result = await _userManager.ConfirmEmailAsync(user, request.Token);

            if (result.Succeeded)
            {
                _logger.LogInformation("Email confirmed for user {UserId}: {Email}", user.Id, user.Email);

                return Ok(new ApiResponse<ConfirmEmailResponse>
                {
                    Success = true,
                    Message = "Email confirmed successfully.",
                    Data = new ConfirmEmailResponse
                    {
                        Success = true,
                        Message = "Your email has been confirmed. You can now log in."
                    }
                });
            }

            var errors = result.Errors.Select(e => e.Description).ToList();

            _logger.LogWarning("Email confirmation failed for user {UserId}: {Errors}",
                user.Id, string.Join("; ", errors));

            return BadRequest(new ApiResponse<ConfirmEmailResponse>
            {
                Success = false,
                Message = "Email confirmation failed.",
                Data = new ConfirmEmailResponse
                {
                    Success = false,
                    Message = "The confirmation link is invalid or has expired."
                }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // ResendConfirmation — resends the email confirmation token.
        //
        // POST /api/account/resend-confirmation
        // Body: ResendConfirmationRequest (email)
        // Response: ResendConfirmationResponse
        //
        // Use case: User didn't receive the original confirmation email,
        // or the token expired before they could click it.
        //
        // Flow:
        //   1. Find user by email
        //   2. If user not found OR email already confirmed, return generic response
        //   3. Generate new confirmation token
        //   4. Send email (mock in this tutorial — log to console)
        //   5. Return success message (same whether email exists or not)
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("resend-confirmation")]
        [AllowAnonymous]
        public async Task<IActionResult> ResendConfirmation([FromBody] ResendConfirmationRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Validation failed.",
                    Errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList()
                });
            }

            var user = await _userManager.FindByEmailAsync(request.Email);

            if (user == null || user.EmailConfirmed)
            {
                // Don't reveal whether email exists or is already confirmed
                // Return the same generic response
                return Ok(new ApiResponse<ResendConfirmationResponse>
                {
                    Success = true,
                    Message = "If the email exists and is not confirmed, a new confirmation link has been sent.",
                    Data = new ResendConfirmationResponse
                    {
                        Success = true,
                        Message = "If the email exists and is not confirmed, a new confirmation link has been sent."
                    }
                });
            }

            // Generate new confirmation token
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            // Send email (MOCK — in production, use an email service)
            await SendConfirmationEmailAsync(user.Email, token);

            _logger.LogInformation("Confirmation email resent to {Email}", user.Email);

            return Ok(new ApiResponse<ResendConfirmationResponse>
            {
                Success = true,
                Message = "If the email exists and is not confirmed, a new confirmation link has been sent.",
                Data = new ResendConfirmationResponse
                {
                    Success = true,
                    Message = "If the email exists and is not confirmed, a new confirmation link has been sent."
                }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // ForgotPassword — initiates the password reset process.
        //
        // POST /api/account/forgot-password
        // Body: ForgotPasswordRequest (email)
        // Response: ForgotPasswordResponse
        //
        // IMPORTANT: Always return the same response regardless of whether the
        // email exists. This prevents email enumeration attacks.
        //
        // Flow:
        //   1. Find user by email
        //   2. If user not found: return generic response (don't reveal)
        //   3. If user found: generate reset token, send email (mock)
        //   4. Return same generic response either way
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Validation failed.",
                    Errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList()
                });
            }

            var user = await _userManager.FindByEmailAsync(request.Email);

            if (user == null || !user.EmailConfirmed)
            {
                // User not found or email not confirmed — return generic response
                // DON'T reveal that the email doesn't exist
                return Ok(new ApiResponse<ForgotPasswordResponse>
                {
                    Success = true,
                    Message = "If the email exists and is confirmed, a reset link has been sent.",
                    Data = new ForgotPasswordResponse
                    {
                        Success = true,
                        Message = "If the email exists and is confirmed, a reset link has been sent."
                    }
                });
            }

            // Generate password reset token
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            // Send reset email (MOCK — in production, use an email service)
            await SendPasswordResetEmailAsync(user.Email, token);

            _logger.LogInformation("Password reset email sent to {Email}", user.Email);

            return Ok(new ApiResponse<ForgotPasswordResponse>
            {
                Success = true,
                Message = "If the email exists and is confirmed, a reset link has been sent.",
                Data = new ForgotPasswordResponse
                {
                    Success = true,
                    Message = "If the email exists and is confirmed, a reset link has been sent."
                }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // ResetPassword — resets the user's password with a token.
        //
        // POST /api/account/reset-password
        // Body: ResetPasswordRequest (email, token, newPassword, confirmPassword)
        // Response: ResetPasswordResponse
        //
        // Flow:
        //   1. Validate ModelState (password length, confirmation match)
        //   2. Find user by email
        //   3. If user not found, return error
        //   4. Call UserManager.ResetPasswordAsync(user, token, newPassword)
        //   5. If valid: password changed, return success
        //   6. If invalid: token expired, wrong token, etc.
        //
        // The token is single-use — after a successful reset, the token is consumed
        // and cannot be used again.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList();
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "Validation failed.",
                    Errors = errors
                });
            }

            var user = await _userManager.FindByEmailAsync(request.Email);

            if (user == null)
            {
                return BadRequest(new ApiResponse<ResetPasswordResponse>
                {
                    Success = false,
                    Message = "Password reset failed.",
                    Data = new ResetPasswordResponse
                    {
                        Success = false,
                        Message = "The reset link is invalid or has expired."
                    }
                });
            }

            var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);

            if (result.Succeeded)
            {
                _logger.LogInformation("Password reset for user {UserId}: {Email}", user.Id, user.Email);

                return Ok(new ApiResponse<ResetPasswordResponse>
                {
                    Success = true,
                    Message = "Password reset successfully.",
                    Data = new ResetPasswordResponse
                    {
                        Success = true,
                        Message = "Your password has been reset. You can now log in with your new password."
                    }
                });
            }

            var errors = result.Errors.Select(e => e.Description).ToList();

            _logger.LogWarning("Password reset failed for user {UserId}: {Errors}",
                user.Id, string.Join("; ", errors));

            return BadRequest(new ApiResponse<ResetPasswordResponse>
            {
                Success = false,
                Message = "Password reset failed.",
                Data = new ResetPasswordResponse
                {
                    Success = false,
                    Message = "The reset link is invalid or has expired."
                }
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // SendConfirmationEmailAsync — MOCK email sending.
        //
        // In production, replace with an actual email service:
        //   - SMTP (System.Net.Mail.SmtpClient)
        //   - SendGrid (SendGrid.Client NuGet)
        //   - Amazon SES (AWSSDK.SES)
        //   - Other email services
        //
        // For this tutorial, we log the email to the console.
        // ─────────────────────────────────────────────────────────────────────────
        private async Task SendConfirmationEmailAsync(string email, string token)
        {
            // MOCK: Log the email instead of sending it
            _logger.LogInformation("=== MOCK EMAIL ===");
            _logger.LogInformation("To: {Email}", email);
            _logger.LogInformation("Subject: Confirm your email address");
            _logger.LogInformation("Body: Please confirm your email by visiting:");
            _logger.LogInformation("  https://localhost:7001/api/account/confirm-email");
            _logger.LogInformation("  Body: { {\"email\": \"{Email}\", \"token\": \"{Token}\"} }",
                email, token);
            _logger.LogInformation("===============");

            await Task.CompletedTask;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // SendPasswordResetEmailAsync — MOCK email sending.
        //
        // Same as above — replace with actual email service in production.
        // ─────────────────────────────────────────────────────────────────────────
        private async Task SendPasswordResetEmailAsync(string email, string token)
        {
            _logger.LogInformation("=== MOCK EMAIL ===");
            _logger.LogInformation("To: {Email}", email);
            _logger.LogInformation("Subject: Reset your password");
            _logger.LogInformation("Body: Please reset your password by visiting:");
            _logger.LogInformation("  https://localhost:7001/api/account/reset-password");
            _logger.LogInformation("  Body: { {\"email\": \"{Email}\", \"token\": \"{Token}\", \"newPassword\": \"...\", \"confirmPassword\": \"...\"} }",
                email, token);
            _logger.LogInformation("===============");

            await Task.CompletedTask;
        }
    }
}
```

---

## Postman / Swagger Tests

**Test 1 — Email Confirmation Flow:**

```
Step 1: Register a user (Video 07)
POST /api/account/register
{
  "email": "confirmuser@example.com",
  "password": "Test@123456",
  "confirmPassword": "Test@123456"
}
→ User created, EmailConfirmed = false

Step 2: Get the confirmation token (from mock email log)
The token is logged to the console when the user registers (or when you call resend).
Copy the token from the log.

Step 3: Confirm the email
POST /api/account/confirm-email
{
  "email": "confirmuser@example.com",
  "token": "Cfabbr1234567890..."  // From mock email log
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Email confirmed successfully.",
  "data": {
    "success": true,
    "message": "Your email has been confirmed. You can now log in."
  },
  "errors": []
}

WHAT THIS MEANS:
- EmailConfirmed = true in the database
- User can now login (if AllowOnlyEmailConfirmedUsersToLogin = true)

Step 4: Try to confirm again with the same token
EXPECTED: 400 Bad Request — token already used (single-use)

Step 5: Try to login (Video 08)
POST /api/account/login
{
  "email": "confirmuser@example.com",
  "password": "Test@123456"
}
EXPECTED: 200 OK — login succeeds (email is confirmed)
```

**Test 2 — Resend Confirmation Email:**

```
ENDPOINT: POST https://localhost:7001/api/account/resend-confirmation

BODY:
{
  "email": "confirmuser@example.com"
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "If the email exists and is not confirmed, a new confirmation link has been sent.",
  "data": {
    "success": true,
    "message": "If the email exists and is not confirmed, a new confirmation link has been sent."
  },
  "errors": []
}

WHAT THIS MEANS:
- New confirmation token generated
- New email sent (mock — logged to console)
- Check the console log for the new token
- The old token is NOT invalidated (both tokens work until they expire)
```

**Test 3 — Forgot Password Flow:**

```
Step 1: Request password reset
POST /api/account/forgot-password
{
  "email": "testuser@example.com"
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "If the email exists and is confirmed, a reset link has been sent.",
  "data": {
    "success": true,
    "message": "If the email exists and is confirmed, a reset link has been sent."
  },
  "errors": []
}

WHAT THIS MEANS:
- Same response whether email exists or not (prevents enumeration)
- If email exists and is confirmed: reset token generated, email sent (mock)

Step 2: Get the reset token (from mock email log)
Copy the token from the console log.

Step 3: Reset the password
POST /api/account/reset-password
{
  "email": "testuser@example.com",
  "token": "Cfabbr1234567890...",
  "newPassword": "NewPassword@123",
  "confirmPassword": "NewPassword@123"
}

EXPECTED RESPONSE (200 OK):
{
  "success": true,
  "message": "Password reset successfully.",
  "data": {
    "success": true,
    "message": "Your password has been reset. You can now log in with your new password."
  },
  "errors": []
}

WHAT THIS MEANS:
- Password changed to new password
- Token consumed (single-use — cannot be used again)
- User can login with new password

Step 4: Try to login with OLD password
POST /api/account/login
{
  "email": "testuser@example.com",
  "password": "Test@123456"  // Old password
}
EXPECTED: 400 — Invalid email or password (old password no longer works)

Step 5: Try to login with NEW password
POST /api/account/login
{
  "email": "testuser@example.com",
  "password": "NewPassword@123"  // New password
}
EXPECTED: 200 OK — login succeeds with new password
```

**Test 4 — Reset Password with Invalid Token:**

```
ENDPOINT: POST https://localhost:7001/api/account/reset-password

BODY:
{
  "email": "testuser@example.com",
  "token": "invalid-token-12345",
  "newPassword": "NewPassword@123",
  "confirmPassword": "NewPassword@123"
}

EXPECTED RESPONSE (400 Bad Request):
{
  "success": false,
  "message": "Password reset failed.",
  "data": {
    "success": false,
    "message": "The reset link is invalid or has expired."
  },
  "errors": []
}

WHAT THIS MEANS:
- Token validation failed (wrong token, expired, or already used)
- Password was NOT changed
```

**Test 5 — Database Verification (Tokens):**

```
After generating a confirmation token:

SELECT * FROM AspNetUserTokens WHERE UserId = '{userId}' AND Name = 'Confirmation'

EXPECTED:
UserId        LoginProvider  Name          Value
{userGuid}    Email          Confirmation  Cfabbr1234567890...

After confirming (token used):
SELECT * FROM AspNetUserTokens WHERE UserId = '{userId}' AND Name = 'Confirmation'
EXPECTED: No rows (token removed after use)

After generating a password reset token:

SELECT * FROM AspNetUserTokens WHERE UserId = '{userId}' AND Name = 'ResetPassword'

EXPECTED:
UserId        LoginProvider  Name          Value
{userGuid}    Email          ResetPassword Cfabbr9876543210...

After resetting (token used):
SELECT * FROM AspNetUserTokens WHERE UserId = '{userId}' AND Name = 'ResetPassword'
EXPECTED: No rows (token removed after use)
```

**Test 6 — Email Confirmation on Login:**

```
Pre-requisite: User registered but email NOT confirmed.
Set AllowOnlyEmailConfirmedUsersToLogin = true in Program.cs.

ENDPOINT: POST /api/account/login
{
  "email": "confirmuser@example.com",
  "password": "Test@123456"
}

EXPECTED RESPONSE (400 Bad Request):
{
  "success": false,
  "message": "Email not confirmed.",
  "errors": [
    "Please confirm your email address before logging in.",
    "Check your email for a confirmation link, or request a new confirmation email."
  ]
}

WHAT THIS MEANS:
- CheckPasswordSignInAsync returned IsNotAllowed = true
- EmailConfirmed = false
- User cannot login until email is confirmed

After confirming email (Test 1, Step 3):
Same login request → 200 OK (email now confirmed)
```

---

# Video 18 — Customizing Identity in API: Custom Stores, Custom SignInManager, JWT Customization

## Theory & Definitions

### Why Customize Identity?

Identity is highly customizable. The default implementation covers most scenarios, but sometimes you need:
- **Custom user store** — store users in a different database (MongoDB, DynamoDB, etc.) or add custom data access logic
- **Custom SignInManager** — customize the sign-in process (custom lockout logic, custom 2FA flow, custom token generation)
- **Custom JWT claims** — add custom claims to the JWT beyond what Identity provides by default
- **Custom password hasher** — use a different hashing algorithm (bcrypt, argon2)
- **Custom token provider** — generate tokens in a custom format or with custom lifetimes

### Custom User Store — IUserStore

Identity stores users through `IUserStore<TUser>`. The default implementation uses EF Core (`EFCoreUserStore`). To customize:

```csharp
// Implement IUserStore<ApplicationUser>
public class CustomUserStore : IUserStore<ApplicationUser>, IUserPasswordStore<ApplicationUser>, IUserEmailStore<ApplicationUser>, ...
{
    // Implement all the methods:
    //   - CreateAsync, UpdateAsync, DeleteAsync
    //   - FindByIdAsync, FindByEmailAsync, FindByNameAsync
    //   - GetPasswordHashAsync, SetPasswordHashAsync
    //   - GetEmailAsync, SetEmailAsync, GetEmailConfirmedAsync, SetEmailConfirmedAsync
    //   - GetNormalizedUserNameAsync, SetNormalizedUserNameAsync
    //   - GetUserIdAsync, GetUserNameAsync, SetUserNameAsync
    //   - ... many more methods
}
```

This is a LOT of methods to implement. For most applications, customizing the EF Core store (by overriding methods) is easier than implementing a full custom store.

### Custom SignInManager

`SignInManager<TUser>` handles the sign-in process. You can derive from it and override methods:

```csharp
public class CustomSignInManager : SignInManager<ApplicationUser>
{
    public CustomSignInManager(UserManager<ApplicationUser> userManager,
        IHttpContextAccessor contextAccessor,
        IAuthenticationSchemeProvider schemeProvider,
        IUserConfirmation<ApplicationUser> userConfirmation)
        : base(userManager, contextAccessor, schemeProvider, userConfirmation)
    {
    }

    // Override to customize sign-in logic
    public override async Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
    {
        // Custom logic before standard sign-in
        // ...

        // Call base implementation
        var result = await base.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure);

        // Custom logic after sign-in
        // ...

        return result;
    }

    // Override to customize how the authentication cookie/claim is created
    protected override async Task<ClaimsIdentity> CreateIdentityAsync(ApplicationUser user, string authenticationType)
    {
        var identity = await base.CreateIdentityAsync(user, authenticationType);

        // Add custom claims
        identity.AddClaim(new Claim("custom_claim", "custom_value"));

        return identity;
    }
}
```

For an API, we use `UserManager` + custom JWT generation instead of `SignInManager` (which is cookie-oriented). But the pattern of deriving and overriding is the same.

### Custom JWT Claims and Token Generation

The JWT generation in `GenerateJwtToken` (Video 08) can be customized:

```csharp
// Add custom claims based on business logic
claims.Add(new Claim("tenant_id", user.TenantId.ToString()));
claims.Add(new Claim("subscription_level", user.SubscriptionLevel.ToString()));
claims.Add(new Claim("feature_flag", "premium_feature", "true"));

// Custom expiration per user type
var expiration = user.IsPremium ? TimeSpan.FromHours(24) : TimeSpan.FromHours(1);
var token = new JwtSecurityToken(
    issuer: jwtIssuer,
    audience: jwtAudience,
    claims: claims,
    expires: DateTime.UtcNow.Add(expiration),
    signingCredentials: credentials
);
```

### Custom UserManager — Dependency Injection

You can register a custom `UserManager` with additional services:

```csharp
builder.Services.AddScoped<IUserStore<ApplicationUser>, CustomUserStore>();
builder.Services.AddScoped<UserManager<ApplicationUser>>(sp =>
{
    var store = sp.GetRequiredService<IUserStore<ApplicationUser>>();
    var options = sp.GetRequiredService<IOptions<IdentityOptions>>();
    var logger = sp.GetRequiredService<ILogger<UserManager<ApplicationUser>>>();
    var passwordHasher = sp.GetRequiredService<IPasswordHasher<ApplicationUser>>();
    // ... inject other dependencies

    return new UserManager<ApplicationUser>(store, options, logger, passwordHasher, ...);
});
```

### "When to Use vs When Not to Use" — Customization

| Decision | Use it | Don't use it |
|----------|--------|--------------|
| Custom user store | You're using a non-relational database (MongoDB, DynamoDB) | You're using SQL Server/PostgreSQL with EF Core (default store works) |
| Custom SignInManager | You need custom sign-in logic (custom lockout, custom 2FA, custom redirects) | Standard sign-in works (use UserManager directly for APIs) |
| Custom JWT claims | You need to add business-specific claims (tenant, subscription, features) | Default Identity claims are sufficient |
| Custom password hasher | You have compliance requirements for a specific algorithm | Default PBKDF2 is secure and well-tested |
| Custom token provider | You need custom token formats or lifetimes | Built-in token providers work for email confirmation and password reset |
| Override Identity methods | You need to change specific behavior (e.g., password validation, user lookup) | The default behavior works |

### Key Insight: Customization Is Escape Hatches, Not the Main Path

Identity is designed to work out of the box. Customization is for when the defaults don't fit. The most common customizations for APIs are:
1. **Custom JWT claims** — adding business data to tokens (most common)
2. **Custom password validation** — adding rules beyond PasswordOptions (Video 13)
3. **Custom user class** — adding columns to the user table (Video 05)

Full custom stores, custom SignInManagers, and custom token providers are rare — they're escape hatches for specific scenarios.

---

## 🎬 Video Recording Notes

**Opening (say this):**
> \"Identity is customizable. Today we'll look at the customization points: custom user stores, custom SignInManagers, custom JWT claims, and when to use each. For most APIs, the customization you need is adding custom claims to the JWT and maybe a custom user class. But it's good to know the full range of options.\"

**Show on screen (do this):**
> Show a custom SignInManager derived from SignInManager. Show custom JWT claims in GenerateJwtToken. Show a custom password hasher (conceptual). Explain when each customization is worthwhile vs overkill.

**Key points to emphasize (say this):**
> \"For APIs, you typically don't need a custom SignInManager. SignInManager is cookie-oriented (MVC pattern). In an API, you use UserManager directly and generate your own JWT. Custom SignInManager is more relevant for MVC/Razor Pages apps.\"

> \"Custom JWT claims are the most common customization for APIs. You add business-specific claims (tenant ID, subscription level, feature flags) to the token so they're available on every request without a database lookup.\"

> \"A custom user store is a big undertaking — IUserStore has dozens of methods. Only implement a custom store if you're using a non-relational database or have very specific data access requirements. For SQL Server with EF Core, the default store is fine.\"

> \"Custom password hashing is rarely needed. PBKDF2 (the default) is secure and well-tested. Only change it if you have a compliance requirement for a specific algorithm (like bcrypt or argon2).\"

**Analogy (say this):**
> \"Identity is like a car. The default configuration gets you from A to B. Customization is like modifying the car — custom paint (JWT claims), custom engine (password hasher), custom wheels (user store), custom dashboard (SignInManager). Most people just drive the car as-is. Enthusiasts modify it. Know what's available, but don't modify unless you have a reason.\"

**Common viewer question:**
> \"Can I use Identity with MongoDB?\" — Yes, but you need a custom user store (IUserStore implementation for MongoDB). There are community libraries that provide this (e.g., MongoDB.AspNetCore.Identity). Or you can implement your own.

> \"Do I need a custom SignInManager for 2FA?\" — Not necessarily. The 2FA flow we implemented in Video 15 uses UserManager directly + custom endpoints. A custom SignInManager could encapsulate the 2FA flow, but it's not required.

> \"How do I add claims dynamically based on database data?\" — In GenerateJwtToken, query the database for the additional data and add claims. This is a database hit at login time (not on every request — claims are in the token). For frequently-changing data, consider short-lived tokens or claims transformation.

**What to show:**
- Custom SignInManager class (derived from SignInManager)
- Custom JWT claims in GenerateJwtToken (add tenant, subscription, etc.)
- Custom password hasher (conceptual — show the interface)
- Custom token provider (conceptual — show the interface)
- Explanation of which customizations are common vs rare

**What to skip:**
- Full custom user store implementation (too much code — show the interface, explain the concept)
- Custom OAuth provider implementation (different topic — external login is Video 16)
- Advanced claims transformation (IClaimsTransformation) — mention briefly

---

## Complete Implementation

### File: Managers/CustomSignInManager.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Managers/CustomSignInManager.cs
// Video 18 — Custom SignInManager (conceptual example)
// ─────────────────────────────────────────────────────────────────────────────
// This shows how to derive from SignInManager to customize sign-in behavior.
//
// NOTE: For APIs, we typically use UserManager directly (not SignInManager).
// SignInManager is designed for cookie-based authentication (MVC/Razor Pages).
// In an API, we use UserManager.CheckPasswordSignInAsync + custom JWT generation.
//
// This example is for educational purposes — to show the customization pattern.
// In a real API, you might use a custom SignInManager if you need cookie-based
// authentication alongside JWT, or if you're building a hybrid app.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Write the custom SignInManager
//   - Explain which methods you can override
//   - Explain that for APIs, UserManager + custom JWT is usually sufficient
//   - Show the pattern for customization
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Managers
{
    // ─────────────────────────────────────────────────────────────────────────────
    // CustomSignInManager — custom sign-in manager for API-specific behavior.
    //
    // Derives from SignInManager<ApplicationUser> to customize:
    //   - Sign-in process (custom lockout, custom 2FA, custom redirects)
    //   - Identity creation (custom claims added to the authentication cookie/claims)
    //
    // For API usage, this is less common. But the pattern is valuable to understand.
    // ─────────────────────────────────────────────────────────────────────────────
    public class CustomSignInManager : SignInManager<ApplicationUser>
    {
        private readonly ILogger<CustomSignInManager> _logger;

        public CustomSignInManager(
            UserManager<ApplicationUser> userManager,
            IHttpContextAccessor contextAccessor,
            IAuthenticationSchemeProvider schemeProvider,
            IUserConfirmation<ApplicationUser> userConfirmation,
            ILogger<CustomSignInManager> logger)
            : base(userManager, contextAccessor, schemeProvider, userConfirmation)
        {
            _logger = logger;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // PasswordSignInAsync — override to add custom logic BEFORE and AFTER sign-in.
        //
        // This is called by the login endpoint (in MVC) to sign in a user with
        // username + password. In an API, we use UserManager.CheckPasswordSignInAsync
        // directly and don't call this method.
        //
        // But if you were using SignInManager in an API, you could override this
        // to add custom logic:
        //   - Custom logging (log every sign-in attempt)
        //   - Custom pre-checks (check if user is active, check IP, check device)
        //   - Custom post-processing (update last login, send notification)
        // ─────────────────────────────────────────────────────────────────────────
        public override async Task<SignInResult> PasswordSignInAsync(
            string userName,
            string password,
            bool isPersistent,
            bool lockoutOnFailure)
        {
            _logger.LogInformation("Sign-in attempt for user: {UserName}", userName);

            // Custom pre-check: check if user account is active
            var user = await UserManager.FindByNameAsync(userName);
            if (user != null && !user.IsActive)
            {
                _logger.LogWarning("Sign-in blocked: account deactivated for {UserName}", userName);
                return SignInResult.Failed("Account is deactivated.");
            }

            // Call the base implementation (standard Identity sign-in)
            var result = await base.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure);

            // Custom post-processing
            if (result.Succeeded)
            {
                _logger.LogInformation("Sign-in successful for user: {UserName}", userName);

                // Update last login date (custom behavior)
                if (user != null)
                {
                    user.LastLoginDate = DateTime.UtcNow;
                    await UserManager.UpdateAsync(user);
                }
            }

            return result;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // CreateIdentityAsync — override to add custom claims to the identity.
        //
        // This creates the ClaimsIdentity that goes into the authentication cookie
        // (MVC) or can be used to generate a JWT (API).
        //
        // Override this to add custom claims that should be part of the user's
        // authentication identity.
        // ─────────────────────────────────────────────────────────────────────────
        protected override async Task<ClaimsIdentity> CreateIdentityAsync(
            ApplicationUser user,
            string authenticationType)
        {
            // Call base to get the standard Identity claims
            var identity = await base.CreateIdentityAsync(user, authenticationType);

            // Add custom claims
            identity.AddClaim(new Claim("custom_claim_example", "This is a custom claim added by CustomSignInManager"));

            // Add tenant ID if the user has one (custom property on ApplicationUser)
            // if (user.TenantId != null)
            // {
            //     identity.AddClaim(new Claim("tenant_id", user.TenantId.Value.ToString()));
            // }

            // Add subscription level
            // if (!string.IsNullOrEmpty(user.SubscriptionLevel))
            // {
            //     identity.AddClaim(new Claim("subscription_level", user.SubscriptionLevel));
            // }

            return identity;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // SignInWithClaimsAsync — sign in with additional claims.
        //
        // This is useful for API scenarios where you want to add claims to the
        // JWT at sign-in time, based on runtime data.
        //
        // In our API, we do this in GenerateJwtToken (Video 08) by adding claims
        // to the JwtSecurityToken before writing it.
        // ─────────────────────────────────────────────────────────────────────────
        public async Task SignInWithCustomClaimsAsync(ApplicationUser user, params Claim[] additionalClaims)
        {
            // Create the identity with base claims + custom claims
            var identity = await CreateIdentityAsync(user, "Identity.Application");

            foreach (var claim in additionalClaims)
            {
                identity.AddClaim(claim);
            }

            // In MVC, you'd create a ClaimsPrincipal and sign in:
            // var principal = new ClaimsPrincipal(identity);
            // HttpContext.SignInAsync(principal, new AuthenticationProperties { ... });

            // In API, you'd use the identity claims to generate a JWT:
            // var claims = identity.Claims.ToList();
            // var token = GenerateJwtFromClaims(claims);
        }
    }
}
```

### File: Managers/CustomJwtService.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Managers/CustomJwtService.cs
// Video 18 — Custom JWT Service with Extended Claims
// ─────────────────────────────────────────────────────────────────────────────
// This service encapsulates JWT generation with custom claims.
//
// In Video 08, we had GenerateJwtToken as a private method in AccountController.
// Here we extract it into a separate service for reusability and testability.
//
// The service can be extended to:
//   - Add custom claims based on business logic
//   - Customize expiration per user type
//   - Add custom headers to the JWT
//   - Use a different signing key per tenant (multi-tenant scenario)
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Write the service
//   - Show how it's registered in Program.cs
//   - Show how AccountController uses it instead of the private method
//   - Demonstrate custom claims being added
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using IdentityApiTutorial.Models;

namespace IdentityApiTutorial.Managers
{
    // ─────────────────────────────────────────────────────────────────────────────
    // CustomJwtService — generates JWT tokens with custom claims.
    //
    // This service encapsulates all JWT generation logic, making it:
    //   - Reusable: any controller can generate tokens
    //   - Testable: can be unit tested independently
    //   - Configurable: token settings come from configuration
    //
    // Uses the same JWT configuration as Program.cs (key, issuer, audience).
    // ─────────────────────────────────────────────────────────────────────────────
    public class CustomJwtService
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<CustomJwtService> _logger;

        public CustomJwtService(
            IConfiguration configuration,
            UserManager<ApplicationUser> userManager,
            ILogger<CustomJwtService> logger)
        {
            _configuration = configuration;
            _userManager = userManager;
            _logger = logger;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // GenerateToken — generates a JWT token for the given user.
        //
        // Parameters:
        //   user — the authenticated user
        //   customClaims — optional additional claims to include
        //
        // Returns: string — the JWT token string
        //
        // Process:
        //   1. Create standard claims (sub, email, jti, iat, nameid, name, etc.)
        //   2. Add role claims (from UserManager.GetRolesAsync)
        //   3. Add custom claims (from customClaims parameter)
        //   4. Add business-specific claims (tenant, subscription, etc.)
        //   5. Sign the token with the JWT key
        //   6. Return the token string
        // ─────────────────────────────────────────────────────────────────────────
        public async Task<string> GenerateToken(ApplicationUser user, IEnumerable<Claim>? customClaims = null)
        {
            var jwtKey = _configuration["Jwt:Key"];
            var jwtIssuer = _configuration["Jwt:Issuer"];
            var jwtAudience = _configuration["Jwt:Audience"];

            if (string.IsNullOrEmpty(jwtKey) || string.IsNullOrEmpty(jwtIssuer) || string.IsNullOrEmpty(jwtAudience))
            {
                throw new InvalidOperationException("JWT configuration is missing. Check appsettings.json.");
            }

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            // Get user roles
            var roles = await _userManager.GetRolesAsync(user);

            // Build claims
            var claims = new List<Claim>
            {
                // Standard JWT claims
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new Claim(JwtRegisteredClaimNames.Iat,
                    DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                    ClaimValueTypes.Integer64),

                // ASP.NET Core claims
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.GivenName, user.FullName ?? string.Empty),

                // Custom claims specific to this API
                new Claim("two_factor_enabled", user.TwoFactorEnabled ? "true" : "false"),
                new Claim("email_confirmed", user.EmailConfirmed ? "true" : "false"),

                // Role claims
            };

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            // Add custom claims (from caller)
            if (customClaims != null)
            {
                claims.AddRange(customClaims);
            }

            // Add business-specific claims (examples)
            // These would come from your business logic, not from Identity
            // claims.Add(new Claim("tenant_id", user.TenantId.ToString()));
            // claims.Add(new Claim("subscription_level", user.SubscriptionLevel.ToString()));

            // Customize expiration per user type (example)
            // var expiration = user.IsPremium ? TimeSpan.FromHours(24) : TimeSpan.FromHours(1);
            var expiration = TimeSpan.FromHours(1);  // Default 1 hour

            var token = new JwtSecurityToken(
                issuer: jwtIssuer,
                audience: jwtAudience,
                claims: claims,
                expires: DateTime.UtcNow.Add(expiration),
                signingCredentials: credentials
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            _logger.LogDebug("JWT token generated for user {UserId}, expires in {Hours} hour(s)",
                user.Id, expiration.TotalHours);

            return tokenString;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // ValidateToken — validates a JWT token and returns the claims principal.
        //
        // This is used when you need to manually validate a token (not through
        // the JWT bearer middleware). For example, when processing a token from
        // an external source or when you need to extract claims from a token
        // without an HTTP request.
        //
        // In normal API operation, the JWT bearer middleware handles validation
        // automatically. This method is for special cases.
        // ─────────────────────────────────────────────────────────────────────────
        public ClaimsPrincipal? ValidateToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtKey = _configuration["Jwt:Key"];
            var jwtIssuer = _configuration["Jwt:Issuer"];
            var jwtAudience = _configuration["Jwt:Audience"];

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = jwtIssuer,
                ValidateAudience = true,
                ValidAudience = jwtAudience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(5)  // Allow 5 minutes of clock skew
            };

            try
            {
                var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
                return principal;
            }
            catch
            {
                return null;  // Token is invalid
            }
        }
    }
}
```

### Register Custom Services in Program.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// Program.cs — custom service registration
// Video 18 — Registering custom Identity services
// ─────────────────────────────────────────────────────────────────────────────
//
// Add these to your Program.cs service configuration:
//
//   // Custom JWT service
//   builder.Services.AddScoped<CustomJwtService>();
//
//   // Custom SignInManager (if needed)
//   builder.Services.AddScoped<CustomSignInManager>();
//
//   // Use custom SignInManager instead of the default
//   // (only if you're using SignInManager in your API — rare for APIs)
//
// Then in AccountController, inject CustomJwtService instead of using
// the private GenerateJwtToken method:
//
//   public class AccountController : ControllerBase
//   {
//       private readonly CustomJwtService _jwtService;
//       ...
//
//       public AccountController(..., CustomJwtService jwtService, ...)
//       {
//           _jwtService = jwtService;
//           ...
//       }
//
//       private async Task<string> GenerateJwtToken(ApplicationUser user)
//       {
//           return await _jwtService.GenerateToken(user);
//       }
//
// ─────────────────────────────────────────────────────────────────────────────
```

---

## Postman / Swagger Tests

**Test 1 — JWT with Custom Claims:**

```
1. Login as a user (Video 08)
2. Decode the JWT token (jwt.io)
3. Check for custom claims:
   - "two_factor_enabled": "true" or "false"
   - "email_confirmed": "true" or "false"
   - Any custom claims added by CustomJwtService

EXPECTED:
{
  "sub": "user-guid",
  "email": "user@example.com",
  "jti": "unique-token-id",
  "iat": 1705315800,
  "nameid": "user-guid",
  "name": "user@example.com",
  "givenname": "User Name",
  "two_factor_enabled": "false",
  "email_confirmed": "true",
  "role": ["User"],
  "exp": 1705319400,
  "iss": "IdentityApiTutorial",
  "aud": "IdentityApiTutorialUsers"
}

WHAT THIS MEANS:
- Custom claims are present in the JWT
- They're available on every request without a database lookup
- [Authorize] and custom code can read these claims
```

**Test 2 — CustomJwtService Direct Usage:**

```
If you have an endpoint that uses CustomJwtService directly:

ENDPOINT: POST /api/custom-token/generate

AUTH: Bearer token (Admin)

BODY:
{
  "userId": "{userId}",
  "customClaims": [
    { "type": "tenant_id", "value": "tenant-123" },
    { "type": "feature_premium", "value": "true" }
  ]
}

EXPECTED RESPONSE (200 OK):
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expiresIn": 3600
}

Decode the token — should include:
- "tenant_id": "tenant-123"
- "feature_premium": "true"
- All standard claims

WHAT THIS MEANS:
- CustomJwtService can generate tokens with arbitrary custom claims
- Useful for admin operations that need to issue tokens with specific claims
```

---

# Video 19 — Production-Ready API Security: Best Practices, Audit Logging, Troubleshooting

## Theory & Definitions

### Production Security Checklist

When moving from development to production, consider these security aspects:

| Area | Development | Production |
|------|------------|------------|
| JWT Key | Hardcoded in appsettings.json | Environment variable or secrets manager |
| Connection String | LocalDB, trusted connection | SQL Server with SQL auth, credentials from secrets manager |
| CORS | Allow all origins (*) | Specific allowed origins only |
| HTTPS | Optional (localhost) | Required (HSTS, redirect HTTP → HTTPS) |
| Rate Limiting | Not configured | Configure per endpoint/user/IP |
| Logging | Console, Information level | Structured logging, appropriate levels, no sensitive data |
| Error Responses | Detailed (stack traces in dev) | Generic (don't leak internal details) |
| Token Lifetime | 1 hour (default) | Consider shorter (15-30 min) + refresh tokens |
| Email Service | Console logging (mock) | Real email service (SendGrid, SES, etc.) |
| Database | LocalDB | Production SQL Server with backups, monitoring |
| Secrets | In appsettings.json (commit to source control?) | Environment variables, Azure Key Vault, AWS Secrets Manager, etc. |

### JWT Best Practices for Production

| Practice | Why |
|----------|-----|
| Short-lived access tokens (15-30 min) | Limits damage if token is stolen |
| Refresh tokens (longer-lived, stored securely) | Allows renewal without re-login |
| Store refresh tokens in database (hashed) | Can revoke refresh tokens |
| Rotate signing keys periodically | Limits exposure if a key is compromised |
| Use environment variables for keys | Keys not in source control |
| Validate token on every request (middleware) | Already done by JWT bearer middleware |
| Don't store sensitive data in JWT | JWT is signed, not encrypted — anyone can decode |
| Use HTTPS only | Tokens sent in Authorization header — must be encrypted in transit |

### Audit Logging

Audit logging records security-relevant events:
- User registration
- Login attempts (successful and failed)
- Password changes
- Role assignments
- Claim changes
- 2FA enable/disable
- External login links/unlinks
- Lockout events

Audit logs help with:
- **Security monitoring** — detect suspicious activity
- **Compliance** — prove who did what and when
- **Debugging** — trace issues back to specific events
- **Forensics** — investigate incidents

### Audit Log Implementation

```csharp
// Audit log entry
public class AuditLogEntry
{
    public string Id { get; set; }
    public string EventType { get; set; }  // "Login", "Register", "PasswordChange", etc.
    public string UserId { get; set; }
    public string UserEmail { get; set; }
    public string IpAddress { get; set; }
    public string UserAgent { get; set; }
    public string Details { get; set; }  // JSON with event-specific details
    public bool Success { get; set; }
    public DateTime Timestamp { get; set; }
}

// Audit service
public class AuditService
{
    private readonly IdentityDbContext _context;
    private readonly ILogger<AuditService> _logger;

    public async Task LogAsync(string eventType, string userId, string userEmail, bool success, string details = null)
    {
        var entry = new AuditLogEntry
        {
            Id = Guid.NewGuid().ToString("N"),
            EventType = eventType,
            UserId = userId,
            UserEmail = userEmail,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent = HttpContext.Request.Headers["User-Agent"],
            Details = details,
            Success = success,
            Timestamp = DateTime.UtcNow
        };

        _context.AuditLogs.Add(entry);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Audit: {EventType} by {UserId} - {Success}", eventType, userId, success ? "Success" : "Failure");
    }
}
```

### Rate Limiting

Rate limiting prevents abuse:
- **Login endpoint** — limit login attempts per IP/user (Identity's lockout handles per-user, but IP-based rate limiting is additional)
- **Registration endpoint** — limit new account creation per IP (prevent spam)
- **API endpoints** — limit requests per minute per user/IP

ASP.NET Core Rate Limiting (built-in in .NET 7+):

```csharp
builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = new FixedWindowRateLimiterOptions
    {
        PermitLimit = 100,
        Window = TimeSpan.FromMinutes(1),
        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
        QueueLimit = 0
    };

    options.AddPolicy("Login", context =>
        new FixedWindowRateLimiterOptions
        {
            PermitLimit = 5,
            Window = TimeSpan.FromMinutes(1)
        });

    options.AddPolicy("Registration", context =>
        new FixedWindowRateLimiterOptions
        {
            PermitLimit = 3,
            Window = TimeSpan.FromMinutes(1)
        });
});

// Apply to endpoints
app.UseRateLimiter();

// In controller:
[HttpGet("sensitive")]
[EnableRateLimiting("Login")]
public IActionResult SensitiveEndpoint() { ... }
```

### Common Issues and Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| 401 Unauthorized on every request | JWT key mismatch between generation and validation | Check that the JWT key in appsettings.json is the same in both places |
| 401 Unauthorized after login | Token not being sent in Authorization header | Check that client sends `Authorization: Bearer <token>` (not `Bearer<token>` with no space, not in a different header) |
| 403 Forbidden when user has role | Role claim missing from JWT | Check that roles are added as claims in GenerateJwtToken and that the user actually has the role |
| Login fails with "Email not confirmed" | AllowOnlyEmailConfirmedUsersToLogin = true and email not confirmed | Confirm email (Video 17) or set AllowOnlyEmailConfirmedUsersToLogin = false for development |
| Lockout after a few failed logins | Default lockout is 5 attempts, 5 minutes | Configure MaxFailedAccessAttempts and DefaultLockoutTimeSpan in Program.cs |
| User can't login after password reset | Password reset changes SecurityStamp, old tokens invalidated (if stamp checking implemented) | User must re-login with new password |
| External login fails | External token validation fails (mock in tutorial, real in production) | Implement real token validation with the provider's API |
| 2FA code doesn't work | User's clock is off, or wrong secret | Check clock synchronization, verify the secret was entered correctly |
| Claims not appearing in JWT | Claims not added in GenerateJwtToken | Add the claims to the claims list before creating the JwtSecurityToken |
| Database migration fails | Existing database with different schema | Delete and recreate (development), or create a new migration that handles the change |
| "No service for type 'UserManager' found" | Identity not configured in Program.cs | Check that AddIdentityCore, AddEntityFrameworkStores, AddRoles are all called |

### "When to Use vs When Not to Use" — Production Features

| Decision | Use it | Don't use it |
|----------|--------|--------------|
| Short-lived tokens + refresh tokens | For high-security APIs (financial, health, admin) | For low-security APIs (1-hour tokens are sufficient) |
| Rate limiting | For all public-facing endpoints | For internal-only APIs (network-level security is sufficient) |
| Audit logging | For compliance requirements, security monitoring | For throwaway prototypes (overhead without benefit) |
| HTTPS/HSTS | Always — in production | Never — HTTPS is mandatory for production APIs |
| Secrets manager | For production (keys, connection strings) | For development (appsettings.json is fine for local dev) |
| IP-based rate limiting | When you need to limit per-IP (public APIs) | When you have a trusted client base (user-based limiting is enough) |
| CORS restrictions | Always — restrict to known origins | For APIs with no browser clients (mobile apps only — CORS is browser-specific) |

### Key Insight: Security Is a Continuum

Security is not a checkbox — it's a continuum. Development is permissive (easy to debug, easy to test). Production is restrictive (harder to attack, harder to debug). The transition from development to production is about tightening each layer:
- Authentication (JWT keys, token lifetime)
- Authorization ([Authorize] attributes, policies)
- Network (HTTPS, CORS, rate limiting)
- Data (connection strings, secrets)
- Observability (logging, audit trails)

Each layer adds security. No single layer is sufficient — defense in depth.

---

## 🎬 Video Recording Notes

**Opening (say this):**
> \"We've built the full Identity API. Now let's make it production-ready. Today we cover security best practices: JWT key management, token lifetimes, rate limiting, audit logging, HTTPS, CORS, and a comprehensive troubleshooting guide. This is the final piece — taking what we've built and making it safe for real users.\"

**Show on screen (do this):**
> Show a production checklist. Show audit logging implementation. Show rate limiting configuration. Show the troubleshooting table. Demonstrate: a failed login attempt triggers audit log, rate limiting kicks in after too many requests, audit log entries in the database.

**Key points to emphasize (say this):**
> \"The JWT key must never be in source control. In development, appsettings.json is fine. In production, the key comes from an environment variable or a secrets manager (Azure Key Vault, AWS Secrets Manager, etc.). If the key leaks, anyone can forge tokens.\"

> \"Tokens should be short-lived in production. 1 hour is fine for development. For production, consider 15-30 minutes for access tokens and use refresh tokens for longer sessions. If a token is stolen, short lifetime limits the damage.\"

> \"Audit logging records security events. Login attempts (success and failure), password changes, role changes, 2FA changes. Audit logs help you detect attacks, comply with regulations, and debug issues. Log the event, the user, the IP, the result — but never log passwords or tokens.\"

> \"Rate limiting prevents abuse. Login endpoint: 5 attempts per minute per IP. Registration: 3 per minute per IP. Sensitive endpoints: 10 per minute per user. Rate limiting is your first line of defense against brute force and denial of service.\"

> \"The troubleshooting table is your friend. 90% of Identity issues fall into a few categories: JWT key mismatch, missing role claims, email confirmation required, lockout, token expiration. Check the table before debugging from scratch.\"

**Analogy (say this):**
> \"Production security is like securing a house. Development is living in the house with the doors unlocked — easy to get in and out, easy to debug. Production is locking the doors, installing an alarm, adding a security camera (audit log), and putting up a fence (rate limiting). Each layer makes it harder for an intruder. No single layer is perfect, but together they make your house safe.\"

**Common viewer question:**
> \"Do I really need all of this for a small API?\" — It depends on the sensitivity of the data. For a public API with no sensitive data, you might skip audit logging and rate limiting (but still use HTTPS and proper JWT keys). For an API with personal data, financial data, or admin functions, all of these matter.

> \"What's the most common Identity bug?\" — JWT key mismatch. The key in Program.cs (validation) doesn't match the key in AccountController (generation). Every request returns 401. Check the keys first when debugging 401 errors.

> \"How do I rotate JWT keys without invalidating all tokens?\" — You can't, easily. Key rotation invalidates all tokens signed with the old key. Options: (1) use multiple keys (validate against both old and new), (2) use short-lived tokens (they expire before rotation matters), (3) accept that rotation requires users to re-login. For most APIs, key rotation is rare (years apart) and re-login is acceptable.

**What to show:**
- Production checklist (JWT keys, HTTPS, CORS, rate limiting, logging)
- Audit logging implementation (AuditService, AuditLogEntry)
- Rate limiting configuration (AddRateLimiter, EnableRateLimiting)
- Troubleshooting table (common errors and fixes)
- Demonstration: audit log entry created on login, rate limiting blocks excessive requests

**What to skip:**
- Specific secrets manager setup (Azure Key Vault, AWS Secrets Manager — different for each cloud)
- Advanced rate limiting (sliding window, token bucket, per-user policies) — mention as advanced
- DDoS protection (cloud-level, not application-level) — beyond scope

---

## Complete Implementation

### File: Services/AuditService.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Services/AuditService.cs
// Video 19 — Audit Logging Service
// ─────────────────────────────────────────────────────────────────────────────
// This service logs security-relevant events to the database.
//
// Events logged:
//   - UserRegistration
//   - LoginSuccess, LoginFailure
//   - Logout
//   - PasswordChange
//   - EmailConfirmation
//   - RoleAssignment, RoleRemoval
//   - ClaimAddition, ClaimRemoval
//   - TwoFactorEnable, TwoFactorDisable
//   - ExternalLoginLink, ExternalLoginUnlink
//   - Lockout, Unlock
//
// Each entry includes: event type, user ID, user email, IP address,
// user agent, success/failure, and event-specific details (JSON).
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Write the AuditService
//   - Show it being called from controllers
//   - Show the audit log entries in the database
//   - Explain what events to log and what not to log (no passwords/tokens)
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.EntityFrameworkCore;
using IdentityApiTutorial.Data;
using IdentityApiTutorial.Models;
using System;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Services
{
    // ─────────────────────────────────────────────────────────────────────────────
    // AuditLogEntry — a single audit log record.
    //
    // Stored in the database (new table: AuditLogs).
    // Add this to IdentityDbContext as a DbSet.
    // ─────────────────────────────────────────────────────────────────────────────
    public class AuditLogEntry
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string EventType { get; set; } = string.Empty;
        public string? UserId { get; set; }
        public string? UserEmail { get; set; }
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }
        public string? Details { get; set; }  // JSON string with event-specific data
        public bool Success { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // AuditService — logs security events.
    //
    // This is a simplified implementation. In production, you might use:
    //   - A dedicated audit log table with indexes for querying
    //   - External logging services (Seq, ELK, Splunk)
    //   - Write-through cache for high-volume events
    //   - Async queue for non-blocking writes
    //
    // For this tutorial, we write directly to the database.
    // ─────────────────────────────────────────────────────────────────────────────
    public class AuditService
    {
        private readonly IdentityDbContext _context;
        private readonly ILogger<AuditService> _logger;

        // Optional: HTTP context for IP address and user agent
        // In a real implementation, inject IHttpContextAccessor
        private readonly IHttpContextAccessor? _httpContextAccessor;

        public AuditService(
            IdentityDbContext context,
            ILogger<AuditService> logger,
            IHttpContextAccessor? httpContextAccessor = null)
        {
            _context = context;
            _logger = logger;
            _httpContextAccessor = httpContextAccessor;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // LogAsync — logs an audit event.
        //
        // Parameters:
        //   eventType — the type of event (e.g., "LoginSuccess", "PasswordChange")
        //   userId — the user's ID (null for anonymous events)
        //   userEmail — the user's email (for display and searching)
        //   success — whether the event was successful
        //   details — optional JSON string with event-specific details
        //
        // The IP address and user agent are captured from the HTTP context
        // if available.
        // ─────────────────────────────────────────────────────────────────────────
        public async Task LogAsync(
            string eventType,
            string? userId,
            string? userEmail,
            bool success,
            string? details = null)
        {
            var entry = new AuditLogEntry
            {
                EventType = eventType,
                UserId = userId,
                UserEmail = userEmail,
                IpAddress = _httpContextAccessor?.HttpContext?.Connection?.RemoteIpAddress?.ToString(),
                UserAgent = _httpContextAccessor?.HttpContext?.Request?.Headers["User-Agent"],
                Details = details,
                Success = success,
                Timestamp = DateTime.UtcNow
            };

            _context.AuditLogs.Add(entry);
            await _context.SaveChangesAsync();

            var status = success ? "Success" : "Failure";
            _logger.LogInformation("Audit: {EventType} by {UserId} ({Email}) - {Status}",
                eventType, userId, userEmail, status);
        }

        // ─────────────────────────────────────────────────────────────────────────
        // LogLoginSuccess — convenience method for login success events.
        // ─────────────────────────────────────────────────────────────────────────
        public async Task LogLoginSuccessAsync(string userId, string email, string? ipAddress = null)
        {
            var details = $"Login successful. Roles: {await GetUserRolesAsync(userId)}";
            await LogAsync("LoginSuccess", userId, email, true, details);
        }

        // ─────────────────────────────────────────────────────────────────────────
        // LogLoginFailure — convenience method for login failure events.
        // ─────────────────────────────────────────────────────────────────────────
        public async Task LogLoginFailureAsync(string? userId, string email, string reason, string? ipAddress = null)
        {
            var details = $"Login failed. Reason: {reason}";
            await LogAsync("LoginFailure", userId, email, false, details);
        }

        // ─────────────────────────────────────────────────────────────────────────
        // GetUserRolesAsync — helper to get user's roles for audit details.
        // ─────────────────────────────────────────────────────────────────────────
        private async Task<string> GetUserRolesAsync(string userId)
        {
            // This would require a UserManager reference — simplified here
            return "N/A";
        }
    }
}
```

### File: Program.cs — Production Configuration

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// Program.cs — production security configuration
// Video 19 — Production-ready configuration
// ─────────────────────────────────────────────────────────────────────────────
//
// This shows the production-oriented additions to Program.cs.
//
// Key changes from development:
//   1. JWT key from environment variable (not hardcoded)
//   2. Connection string from environment variable
//   3. HTTPS redirection
//   4. HSTS (HTTP Strict Transport Security)
//   5. CORS restricted to specific origins
//   6. Rate limiting
//   7. Structured logging
//   8. Audit service registration
//
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// ─────────────────────────────────────────────────────────────────────────
// Services — core Identity setup (same as before, with production additions)
// ─────────────────────────────────────────────────────────────────────────

builder.Services.AddIdentityCore<ApplicationUser>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.MaxRepeatedChars = 3;

    options.Lockout.AllowedForNewUsers = true;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;

    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<IdentityDbContext>()
.AddRoles<ApplicationRole>()
.AddPasswordValidator<CustomPasswordValidator>();

builder.Services.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)),
        ClockSkew = TimeSpan.FromMinutes(5)
    };
});

builder.Services.AddAuthorization();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// ─────────────────────────────────────────────────────────────────────────
// Production additions
// ─────────────────────────────────────────────────────────────────────────

// JWT key from environment variable (production) or configuration (development)
// In production: builder.Configuration["Jwt:Key"] should come from
// environment variables, not appsettings.json
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));

// Rate limiting
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = 429;  // Too Many Requests

    options.AddFixedWindowLimiter("login", opt =>
    {
        opt.PermitLimit = 5;
        opt.Window = TimeSpan.FromMinutes(1);
        opt.QueueLimit = 0;
    });

    options.AddFixedWindowLimiter("register", opt =>
    {
        opt.PermitLimit = 3;
        opt.Window = TimeSpan.FromMinutes(1);
        opt.QueueLimit = 0;
    });

    options.AddFixedWindowLimiter("global", opt =>
    {
        opt.PermitLimit = 100;
        opt.Window = TimeSpan.FromMinutes(1);
        opt.QueueLimit = 0;
    });
});

// CORS — restrict to specific origins in production
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(
            builder.Configuration["AllowedOrigins"]?.Split(',') ?? new[] { "https://localhost:7001" })
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

// Audit service
builder.Services.AddScoped<AuditService>();
builder.Services.AddHttpContextAccessor();  // For audit service to get IP/user agent

// ─────────────────────────────────────────────────────────────────────────
// Build and configure the app
// ─────────────────────────────────────────────────────────────────────────

var app = builder.Build();

// Apply migrations (in production, this might be a separate deployment step)
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
    db.Database.Migrate();
}

// Production middleware ordering
if (app.Environment.IsProduction())
{
    app.UseHttpsRedirection();  // Redirect HTTP to HTTPS
    app.UseHsts();  // HTTP Strict Transport Security
}

app.UseRateLimiter();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// ─────────────────────────────────────────────────────────────────────────
// Custom rate limiting attributes on endpoints
// ─────────────────────────────────────────────────────────────────────────

// In controllers, apply rate limiting:
//   [EnableRateLimiting("login")]   — on login endpoint
//   [EnableRateLimiting("register")] — on registration endpoint
//   [EnableRateLimiting("global")]   — on all endpoints (default policy)
```

### File: Controllers/TroubleshootingController.cs

```csharp
// ─────────────────────────────────────────────────────────────────────────────
// File: Controllers/TroubleshootingController.cs
// Video 19 — Health Check and Diagnostic Endpoints
// ─────────────────────────────────────────────────────────────────────────────
// These endpoints help diagnose Identity issues in production.
//
// Endpoints:
//   - GET /api/debug/health — API health check
//   - GET /api/debug/auth-status — check current user's auth status
//   - GET /api/debug/jwt-claims — show current user's JWT claims
//
// These are DEBUG endpoints — disable them in production or protect them
// with admin-only access. They expose internal state that shouldn't be
// visible to regular users.
//
// HOW TO USE THIS FOR YOUR VIDEO:
//   - Create this controller
//   - Show the health check endpoint
//   - Show the auth status endpoint (what claims are in the token)
//   - Emphasize that debug endpoints should be disabled in production
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityApiTutorial.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]  // These are debug endpoints — require authentication
    public class DebugController : ControllerBase
    {
        private readonly ILogger<DebugController> _logger;

        public DebugController(ILogger<DebugController> logger)
        {
            _logger = logger;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // Health — API health check.
        //
        // GET /api/debug/health
        // Returns: basic health status
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("health")]
        public IActionResult Health()
        {
            return Ok(new
            {
                status = "healthy",
                timestamp = DateTime.UtcNow,
                version = "1.0.0"
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // AuthStatus — shows the current user's authentication status.
        //
        // GET /api/debug/auth-status
        // Returns: user ID, email, roles, authentication state
        //
        // Useful for debugging: "why am I getting 403?" — check your roles here.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("auth-status")]
        public IActionResult GetAuthStatus()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var email = User.FindFirst(JwtRegisteredClaimNames.Email)?.Value;
            var userName = User.FindFirst(ClaimTypes.Name)?.Value;

            var roles = User.FindAll(ClaimTypes.Role)
                .Select(c => c.Value)
                .ToList();

            var isAuthenticated = User.Identity?.IsAuthenticated ?? false;

            return Ok(new
            {
                isAuthenticated,
                userId,
                email,
                userName,
                roles,
                claimsCount = User.Claims.Count(),
                timestamp = DateTime.UtcNow
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // JwtClaims — shows all claims in the current JWT.
        //
        // GET /api/debug/jwt-claims
        // Returns: all claims (type + value)
        //
        // Useful for debugging: "why isn't [Authorize(Roles)] working?" —
        // check if the role claim is present and has the right value.
        // ─────────────────────────────────────────────────────────────────────────
        [HttpGet("jwt-claims")]
        public IActionResult GetJwtClaims()
        {
            var claims = User.Claims.Select(c => new
            {
                type = c.Type,
                value = c.Value
            }).ToList();

            return Ok(new
            {
                userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value,
                totalClaims = claims.Count,
                claims = claims,
                timestamp = DateTime.UtcNow
            });
        }
    }
}
```

---

## Postman / Swagger Tests

**Test 1 — Health Check:**

```
ENDPOINT: GET https://localhost:7001/api/debug/health

EXPECTED RESPONSE (200 OK):
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:00:00Z",
  "version": "1.0.0"
}

WHAT THIS MEANS:
- API is running and healthy
- Use this for monitoring and load balancer health checks
```

**Test 2 — Auth Status (Debug Your Own Token):**

```
ENDPOINT: GET https://localhost:7001/api/debug/auth-status

AUTH: Bearer token (any authenticated user)

EXPECTED RESPONSE (200 OK):
{
  "isAuthenticated": true,
  "userId": "abc123-guid-here",
  "email": "testuser@example.com",
  "userName": "testuser@example.com",
  "roles": ["User"],
  "claimsCount": 15,
  "timestamp": "2024-01-15T10:00:00Z"
}

WHAT THIS MEANS:
- User is authenticated
- Shows user's ID, email, roles
- Use this to verify your token has the expected claims
```

**Test 3 — JWT Claims (Debug Role Issues):**

```
ENDPOINT: GET https://localhost:7001/api/debug/jwt-claims

AUTH: Bearer token (Admin user)

EXPECTED RESPONSE (200 OK):
{
  "userId": "admin-guid-here",
  "totalClaims": 18,
  "claims": [
    { "type": "sub", "value": "admin-guid-here" },
    { "type": "email", "value": "admin@tutorial.local" },
    { "type": "jti", "value": "a1b2c3d4..." },
    { "type": "iat", "value": "1705315800" },
    { "type": "nameid", "value": "admin-guid-here" },
    { "type": "name", "value": "admin@tutorial.local" },
    { "type": "givenname", "value": "Tutorial Administrator" },
    { "type": "two_factor_enabled", "value": "false" },
    { "type": "email_confirmed", "value": "true" },
    { "type": "role", "value": "Admin" },
    { "type": "role", "value": "User" },
    { "type": "exp", "value": "1705319400" },
    { "type": "iss", "value": "IdentityApiTutorial" },
    { "type": "aud", "value": "IdentityApiTutorialUsers" }
  ],
  "timestamp": "2024-01-15T10:00:00Z"
}

WHAT THIS MEANS:
- All claims in the JWT are visible
- Role claims are present (for [Authorize(Roles)] to work)
- Custom claims (two_factor_enabled, email_confirmed) are present
- Use this to debug: "why am I getting 403?" — check if the role claim is here

Test with a non-Admin user:
EXPECTED: role claim = ["User"] only (no Admin)
→ Confirms why non-Admin users get 403 on Admin endpoints
```

**Test 4 — Rate Limiting (Login Endpoint):**

```
1. Send 6 login requests within 1 minute:
   POST /api/account/login
   { "email": "testuser@example.com", "password": "Test@123456" }
   ... repeat 6 times

2. First 5 requests: 200 OK (or 400 if password wrong)
3. 6th request: 429 Too Many Requests

EXPECTED RESPONSE (429):
{
  "type": "https://tools.ietf.org/html/rfc6585#section-4.1",
  "title": "Too Many Requests",
  "status": 429,
  "traceId": "..."
}

WHAT THIS MEANS:
- Rate limiter blocked the 6th request
- Login endpoint is limited to 5 requests per minute
- Prevents brute force attacks
```

**Test 5 — Audit Log Verification:**

```
After performing various operations (login, register, role assignment, etc.),
check the audit logs in the database:

SELECT TOP 20 * FROM AuditLogs ORDER BY Timestamp DESC

EXPECTED (example rows):
Id          EventType      UserId        UserEmail              Success  Timestamp
abc123      LoginSuccess   admin-guid    admin@tutorial.local   true     2024-01-15 10:00:00
def456      LoginFailure   null          testuser@example.com   false    2024-01-15 09:55:00
ghi789      UserRegistration user-guid   newuser@example.com    true     2024-01-15 09:50:00

WHAT THIS MEANS:
- Login success and failure are logged
- User registration is logged
- Each entry has the user, IP, timestamp, and result
- Use for security monitoring and debugging
```

**Test 6 — Production Troubleshooting Scenarios:**

```
Scenario 1: 401 on every request
- Check: JWT key in appsettings.json matches between generation and validation
- Check: Authorization header is "Bearer <token>" (with space)
- Check: Token hasn't expired (decode on jwt.io, check exp claim)
- Check: Issuer and Audience match between generation and validation

Scenario 2: 403 on Admin endpoint with Admin user
- Check: JWT has "role" claim with value "Admin" (use /api/debug/jwt-claims)
- Check: [Authorize(Roles="Admin")] is on the endpoint
- Check: Role was assigned to the user (check AspNetUserRoles)
- Check: User logged in AFTER the role was assigned (old tokens don't have new roles)

Scenario 3: Login fails with "Email not confirmed"
- Check: AllowOnlyEmailConfirmedUsersToLogin in Program.cs
- If true: user must confirm email first (Video 17)
- If false: email confirmation is not required, login should succeed

Scenario 4: User locked out after 5 failed logins
- Check: Lockout status at /api/lockout/status
- Check: LockoutEnd time — when will the user be able to login again?
- Fix: Admin can unlock via /api/lockout/unlock, or wait for lockout to expire

Scenario 5: 2FA code doesn't work
- Check: User's clock is synchronized (TOTP uses time)
- Check: The correct secret was entered in the authenticator app
- Check: The code is 6 digits (not 4 or 8)
- Check: The code hasn't changed (codes change every 30 seconds)
```

---

## Final Summary: The Complete API Identity Tutorial

### What We've Built

This tutorial covers the complete ASP.NET Core Identity API, from zero to hero:

| Video | Topic | Key Deliverables |
|-------|-------|------------------|
| 01 | Concept | What Identity is, API vs MVC, when to use Identity |
| 02 | Architecture | Users, Roles, Claims, Managers, Stores, Schemes |
| 03 | Project Setup | dotnet new webapi, NuGet packages, project structure |
| 04 | Configuration | AddIdentityCore, JWT, Program.cs end-to-end |
| 05 | Models | IdentityUser, IdentityRole, custom classes, string vs int keys |
| 06 | Database | IdentityDbContext, connection strings, migrations, seeding |
| 07 | Registration | POST /api/account/register, DTO validation, CreateAsync |
| 08 | Login + JWT | POST /api/account/login, CheckPasswordSignInAsync, GenerateJwtToken |
| 09 | Role Management | CRUD roles, assign/remove users, RoleManager, UserManager |
| 10 | RBAC | [Authorize(Roles)], multiple roles, permission system |
| 11 | Claims | Add/remove claims, claim policies, reading claims from JWT |
| 12 | Policy-Based Auth | Custom requirements, handlers, resource-based authorization |
| 13 | Password Policies | PasswordOptions, custom validators, strength check endpoint |
| 14 | Lockout + Security Stamp | Lockout config, lock/unlock endpoints, security stamp, sign out everywhere |
| 15 | 2FA | TOTP, recovery codes, 2FA login flow, enable/verify/disable |
| 16 | External Login | OAuth flow, external token validation, find-or-create, link/unlink |
| 17 | Token Providers | Email confirmation, password reset, token lifecycle, custom providers |
| 18 | Customization | Custom SignInManager, custom JWT claims, custom stores (conceptual) |
| 19 | Production | Security checklist, audit logging, rate limiting, troubleshooting |

### How to Use This Tutorial

1. **For YouTube creation:** Each video section has 🎬 Recording Notes with opening hooks, analogies, "say this" phrases, and common viewer questions. Use these to script your videos.

2. **For study:** The Theory & Definitions sections explain what each concept means, when to use it, and how it works under the hood. Read these to understand the system.

3. **For implementation:** The Complete Implementation sections provide full, copy-paste-ready code with every line commented. Use these to build your API.

4. **For testing:** The Postman / Swagger Tests sections provide request bodies, expected responses, and what each response means. Use these to verify your implementation.

5. **For future reference:** This is a single document. When you forget how to implement something, search for the video number and find the complete reference.
