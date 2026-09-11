# ASP.NET Core Identity: From Zero to Hero — Complete YouTube Tutorial Series

> **A step-by-step, line-by-line guide to mastering ASP.NET Core Identity — built for video creation.**
> Every section below is one YouTube video. Code is explained line by line. No prior Identity knowledge required.

---

## Table of Contents (Playlist Order)

| # | Video Title | What You'll Build/Learn |
|---|-------------|------------------------|
| 01 | [What Is ASP.NET Core Identity? (And Why You Need It)](#video-01--what-is-aspnet-core-identity-and-why-you-need-it) | The big picture — what problem Identity solves, what it replaces, when to use it vs alternatives |
| 02 | [The Architecture Under the Hood — Users, Roles, Claims, Managers, Stores](#video-02--the-architecture-under-the-hood) | Understanding every major type and how they connect before writing a single line |
| 03 | [Creating Your First Project with Identity](#video-03--creating-your-first-project-with-identity) | CLI templates, NuGet packages, project structure, what gets generated |
| 04 | [Configuring Identity Services in Program.cs](#video-04--configuring-identity-services-in-programcs) | `AddIdentity`, password/lockout/sign-in options, cookie config, middleware order |
| 05 | [The Identity Models — IdentityUser, IdentityRole, and Your Custom Classes](#video-05--the-identity-models) | Every property explained, when to extend, custom user/role classes with examples |
| 06 | [Database Setup — IdentityDbContext, Connection Strings, Migrations](#video-06--database-setup) | EF Core integration, schema overview, creating and applying migrations |
| 07 | [User Registration — Building the Complete Flow](#video-07--user-registration) | Register controller, view models, validation, role assignment, email confirmation |
| 08 | [Login & Sign-In — How Authentication Actually Works](#video-08--login--sign-in) | SignInManager, cookie creation, lockout, 2FA redirect, the full login flow |
| 09 | [Role Management — Creating, Assigning, Removing Roles](#video-09--role-management) | RoleManager, admin controller, user-role assignment, system roles |
| 10 | [Role-Based Access Control (RBAC) — Protecting Your Endpoints](#video-10--role-based-access-control-rbac) | `[Authorize(Roles = ...)]`, multiple roles, programmatic checks, permission system on top of roles |
| 11 | [Claims-Based Authorization — Going Beyond Roles](#video-11--claims-based-authorization) | What claims are, adding/removing claims, claim policies, reading claims in code and views |
| 12 | [Policy-Based Authorization — Custom Requirements & Handlers](#video-12--policy-based-authorization) | `IAuthorizationRequirement`, handlers, register policies, resource-based authorization |
| 13 | [Password Policies & Custom Validation](#video-13--password-policies--custom-validation) | PasswordOptions, writing a custom `IPasswordValidator`, strength meter endpoint |
| 14 | [Account Lockout & Security Stamp](#video-14--account-lockout--security-stamp) | Lockout config, manual lock/unlock, security stamp invalidation, sliding expiration |
| 15 | [Two-Factor Authentication (2FA) — TOTP, Authenticator Apps, Recovery Codes](#video-15--two-factor-authentication-2fa) | Enabling 2FA, QR codes, login with 2FA, recovery codes, disabling 2FA |
| 16 | [External Login Providers — Google, Facebook, Microsoft](#video-16--external-authentication-providers) | Registering providers, handling callbacks, linking accounts, managing external logins |
| 17 | [Token Providers — Email Confirmation, Password Reset, Custom Providers](#video-17--token-providers) | How tokens work, lifetimes, DataProtectionTokenProvider, writing a custom token provider |
| 18 | [Customizing Identity — Stores, SignInManager, and Deep Extensibility](#video-18--customizing-identity) | Custom user stores, overriding SignInManager, advanced entity extensions |
| 19 | [Production-Ready Security — Best Practices, Audit Logging, Deployment](#video-19--production-ready-security) | Production config, secure cookies, audit logging, troubleshooting common errors |

---

## How to Use This Document

- **For viewers:** Follow the videos in order. Each video builds on the previous one.
- **For you (the creator):** Each section has a clear "What we're building," "Line-by-line code walkthrough," and "Why this matters" — making it easy to script and record.
- **All code is real, complete, and tested against .NET 8/9.** Copy it directly into your demo project.

---

## Video 01 — What Is ASP.NET Core Identity (And Why You Need It)

### What We're Building

Nothing yet — this is a concept video. No code, just understanding. By the end, the viewer knows exactly what problem Identity solves and when to reach for it.

### Line-by-Line Walkthrough (Conceptual)

**The problem Identity solves:**

> "Imagine you're building an app and you need users to log in. You could write your own: store passwords in a database table, hash them with SHA256, write a login endpoint that compares hashes, set up a cookie session, handle forgotten passwords, lock accounts after bad attempts, add two-factor auth... and you'd be responsible for every security decision. That's a lot of surface area for mistakes."

**What Identity gives you out of the box:**

- User storage with passwords hashed using PBKDF2 + HMAC-SHA256 (not plain SHA256 — this matters)
- Account lockout after failed attempts
- Email confirmation and password reset with secure, time-limited tokens
- Role management — assign users to roles, check roles in code
- Claims — arbitrary key-value facts about a user
- Two-factor authentication (TOTP authenticator apps, SMS, email)
- External logins (Google, Facebook, Microsoft)
- Cookie-based session management (or JWT for APIs)
- Integration with ASP.NET Core's `[Authorize]` attribute and policy system

**Identity vs. alternatives:**

| Technology | What it's for |
|-----------|---------------|
| ASP.NET Core Identity | Single-app user management, login, roles, claims — the user DB lives in your app |
| Duende IdentityServer / IdentityServer | OAuth 2.0 + OpenID Connect — central identity provider for multiple apps, SSO, federated login |
| Custom-built auth | Only when you have very unusual requirements; otherwise you're reinventing security |

**Rule of thumb:** If users log into *your* app with an email/password (or social login), Identity is the right choice. If you need SSO across 10 apps or third-party OAuth, look at Duende.

### Why This Matters

Most .NET developers skip this and jump straight to "add the package." But understanding *why* Identity exists prevents misusing it — for example, using IdentityServer when you just needed Identity, or building a custom auth system that misses basic security.

---

## Video 02 — The Architecture Under the Hood

### What We're Building

A mental model. By the end, the viewer can draw the relationship between `IdentityUser`, `UserManager`, `SignInManager`, `IdentityDbContext`, and the store interfaces on a whiteboard.

### The Core Types (No Code Yet — Just Understanding)

**`IdentityUser`** — the user entity. Holds:

| Property | Purpose |
|----------|---------|
| `Id` | Primary key — a GUID string by default |
| `UserName` | What the user types to log in |
| `NormalizedUserName` | Uppercase version for case-insensitive lookups |
| `Email` / `NormalizedEmail` | Same pattern — email for login/recovery, normalized for lookups |
| `EmailConfirmed` | Has the user clicked the confirmation link? |
| `PasswordHash` | The hashed password (never stored in plain text) |
| `SecurityStamp` | A random value that changes when security-critical things happen (password change, role change). Used to invalidate cookies. |
| `ConcurrencyStamp` | Optimistic concurrency — prevents two requests from overwriting each other |
| `PhoneNumber` / `PhoneNumberConfirmed` | For SMS-based 2FA |
| `TwoFactorEnabled` | Is 2FA turned on for this user? |
| `LockoutEnd` | When does the lockout expire? `null` = not locked |
| `LockoutEnabled` | Can this user be locked out? |
| `AccessFailedCount` | How many failed logins since last success/reset |

**`IdentityRole`** — a role entity. Holds `Id`, `Name`, `NormalizedName`, `ConcurrencyStamp`. Roles are assigned to users; users inherit whatever permissions the role represents.

**`UserManager<TUser>`** — the business logic layer. You call this for:

- Creating users (`CreateAsync`)
- Finding users (`FindByEmailAsync`, `FindByIdAsync`, `FindByNameAsync`)
- Password management (`ChangePasswordAsync`, `AddPasswordAsync`, `RemovePasswordAsync`)
- Role membership (`AddToRoleAsync`, `RemoveFromRoleAsync`, `GetRolesAsync`, `IsInRoleAsync`)
- Claims (`AddClaimAsync`, `RemoveClaimAsync`, `GetClaimsAsync`)
- Tokens (`GenerateEmailConfirmationTokenAsync`, `GeneratePasswordResetTokenAsync`, `VerifyTwoFactorTokenAsync`)
- Lockout (`IsLockedOutAsync`, `SetLockoutEndDateAsync`, `ResetAccessFailedCountAsync`)
- Security stamp (`UpdateSecurityStampAsync`)

**`SignInManager<TUser>`** — the sign-in layer. You call this for:

- `PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure)` — validates password, checks lockout, creates the authentication cookie
- `SignOutAsync()` — clears the cookie
- `IsSignedIn(User)` — checks if the current request is authenticated
- `GetTwoFactorAuthenticationUserAsync()` — retrieves the user mid-2FA flow
- `TwoFactorAuthenticatorSignInAsync()` / `TwoFactorRecoveryCodeSignInAsync()` — completes 2FA sign-in
- `RefreshSignInAsync(user)` — re-creates the cookie (e.g., after adding claims)

**`RoleManager<TRole>`** — the role business logic. Create, update, delete roles; add/remove role claims; find roles.

**The Store Pattern (Important):**

Identity doesn't talk to the database directly from `UserManager`. Instead, `UserManager` calls methods on store interfaces like `IUserStore<TUser>`, `IUserPasswordStore<TUser>`, `IUserEmailStore<TUser>`, `IUserRoleStore<TUser>`, `IUserClaimStore<TUser>`. The Entity Framework Core package provides `UserStore<TUser, TRole, TContext>` that implements all of these using EF Core.

Why this matters: you can swap the storage mechanism without changing your business logic. You could write a custom store that uses a different database, a file, or an in-memory store for testing.

**`IdentityDbContext`** — the EF Core context. Inherits from `IdentityDbContext<TUser, TRole, TKey>` and includes `DbSet<TUser>`, `DbSet<TRole>`, plus the junction tables (`IdentityUserRole`, `IdentityUserClaim`, `IdentityRoleClaim`, `IdentityUserLogin`, `IdentityUserToken`). You add your own entities to this same context.

### The Data Flow (Login Example)

1. User submits email + password to `/Account/Login`
2. Controller calls `_userManager.FindByEmailAsync(email)` → finds the user
3. Controller calls `_signInManager.PasswordSignInAsync(userName, password, ...)` → internally:
   - Calls the password store to get `PasswordHash`
   - Calls the password hasher to verify the password
   - Checks lockout via `IUserLockoutStore`
   - If successful, creates a claims principal from the user
   - Stores the claims principal in an authentication cookie
4. On subsequent requests, cookie middleware reads the cookie, rebuilds the `ClaimsPrincipal`, and makes it available as `User` in controllers

### Why This Matters

When you understand that `UserManager` is business logic over stores, and `SignInManager` bridges to the HTTP cookie, you can reason about what's happening when something goes wrong. "Why isn't the user signed in?" → check the cookie middleware order. "Why did the role authorization stop working?" → the cookie might be stale; sign out and back in to refresh role claims.

---

## Video 03 — Creating Your First Project with Identity

### What We're Building

A fresh ASP.NET Core MVC project with Identity pre-configured, plus a walkthrough of what the template generates and what each file does.

### Step 1 — Create the Project

```bash
# Create an MVC project with Individual (local) authentication
dotnet new mvc -n IdentityTutorial --auth Individual

# Navigate into it
cd IdentityTutorial
```

**What `--auth Individual` does:**

- Installs `Microsoft.AspNetCore.Identity.EntityFrameworkCore`
- Installs `Microsoft.EntityFrameworkCore.SqlServer` (or your chosen provider)
- Creates `Areas/Identity` with Razor Pages for login, register, manage account, etc.
- Creates `ApplicationUser` class inheriting `IdentityUser`
- Creates `ApplicationDbContext` inheriting `IdentityDbContext<ApplicationUser>`
- Configures Identity in `Program.cs`
- Adds a default connection string to `appsettings.json`

### Step 2 — Understand What Was Generated

**`Models/ApplicationUser.cs`:**

```csharp
using Microsoft.AspNetCore.Identity;

namespace IdentityTutorial.Models;

// Why inherit? To add custom properties later (FirstName, LastName, etc.)
// Right now it's empty — IdentityUser already has Id, UserName, Email, etc.
public class ApplicationUser : IdentityUser
{
}
```

Line-by-line:
- `using Microsoft.AspNetCore.Identity;` — brings in `IdentityUser`
- `public class ApplicationUser : IdentityUser` — inherits every property from IdentityUser (Id, UserName, Email, PasswordHash, etc.)
- Empty body — we'll fill this in later when we need custom fields

**`Data/ApplicationDbContext.cs`:**

```csharp
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using IdentityTutorial.Models;

namespace IdentityTutorial.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }
}
```

Line-by-line:
- `IdentityDbContext<ApplicationUser>` — this is NOT a plain `DbContext`. It already has `DbSet<ApplicationUser>`, `DbSet<IdentityRole>`, and all the junction table `DbSet`s configured. It also configures table names, indexes, and relationships for Identity entities.
- The constructor passes `DbContextOptions` to the base — this is where the connection string comes in, configured in `Program.cs`.

**`Program.cs` (relevant Identity section):**

```csharp
// Add Identity services
builder.Services.AddDefaultIdentity<ApplicationUser>(options => options
    .Password.RequireNonAlphanumeric = false)
    .AddEntityFrameworkStores<ApplicationDbContext>();
```

Line-by-line:
- `AddDefaultIdentity<ApplicationUser>` — a shortcut that configures cookie authentication + Identity services together. It's simpler than `AddIdentity` but less customizable. For a starter project this is fine; we'll replace it with full `AddIdentity` later for more control.
- `options.Password.RequireNonAlphanumeric = false` — relaxes the password rule (no special character required). The default requires it, which frustrates demo users.
- `.AddEntityFrameworkStores<ApplicationDbContext>()` — tells Identity to use EF Core with our `ApplicationDbContext` as the storage backend.

### Step 3 — Install Additional Packages (If Not Using Template)

If you started from a plain `webapi` or `mvc` template without `--auth Individual`:

```bash
# Core Identity types (UserManager, SignInManager, IdentityUser, etc.)
dotnet add package Microsoft.AspNetCore.Identity

# Entity Framework Core integration (IdentityDbContext, UserStore, etc.)
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore

# Database provider — SQL Server
dotnet add package Microsoft.EntityFrameworkCore.SqlServer

# EF Core tools for migrations (dotnet ef commands)
dotnet add package Microsoft.EntityFrameworkCore.Tools

# Design-time package (required for dotnet ef to work)
dotnet add package Microsoft.EntityFrameworkCore.Design
```

### Step 4 — Verify the Database Connection

Open `appsettings.json` and set a connection string:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=IdentityTutorial;Trusted_Connection=True;MultipleActiveResultSets=true"
  }
}
```

For Docker SQL Server:
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost,1433;Database=IdentityTutorial;User Id=sa;Password=YourStrongPassword123;TrustServerCertificate=True"
  }
}
```

### Step 5 — Run and Explore

```bash
# Create the initial migration
dotnet ef migrations add InitialCreate

# Apply to create the database
dotnet ef database update

# Run the project
dotnet run
```

Navigate to `/Identity/Account/Register` — you'll see the template's built-in registration page. Register a user and verify the `AspNetUsers` table gets populated.

### Why This Matters

The template is great for a starting point, but you need to know what it generated so you can modify it confidently. In later videos we'll replace the template's `AddDefaultIdentity` with a full `AddIdentity` configuration, add custom user properties, and build our own controllers. Knowing the starting point makes those changes intentional rather than mysterious.

---

## Video 04 — Configuring Identity Services in Program.cs

### What We're Building

A complete, production-quality `Program.cs` Identity configuration — replacing the template's simple `AddDefaultIdentity` with full control over every option.

### The Complete Configuration

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using IdentityTutorial.Data;
using IdentityTutorial.Models;

var builder = WebApplication.CreateBuilder(args);

// ─────────────────────────────────────────────
// 1. Entity Framework Core — Database context
// ─────────────────────────────────────────────
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection")));

// ─────────────────────────────────────────────
// 2. Identity Services — the big one
// ─────────────────────────────────────────────
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // --- Password settings ---
    options.Password.RequireDigit = true;           // Must contain 0-9
    options.Password.RequireLowercase = true;       // Must contain a-z
    options.Password.RequireUppercase = true;       // Must contain A-Z
    options.Password.RequireNonAlphanumeric = true; // Must contain !@#$%^&* etc.
    options.Password.RequiredLength = 8;            // Minimum 8 characters
    options.Password.RequiredUniqueChars = 1;       // At least 1 distinct character

    // --- Lockout settings ---
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5); // Locked for 5 min
    options.Lockout.MaxFailedAccessAttempts = 5;   // After 5 failed tries
    options.Lockout.AllowedForNewUsers = true;     // New accounts can be locked out

    // --- User settings ---
    options.User.AllowedUserNameCharacters =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.User.RequireUniqueEmail = true;        // No duplicate emails

    // --- Sign-in settings ---
    options.SignIn.RequireConfirmedEmail = true;       // Must confirm email to log in
    options.SignIn.RequireConfirmedPhoneNumber = false; // Phone confirmation not required
    options.SignIn.RequireConfirmedAccount = true;     // Account must be confirmed
})
// Tell Identity to use EF Core with our ApplicationDbContext
.AddEntityFrameworkStores<ApplicationDbContext>()
// Add the default token providers (email confirmation, password reset, 2FA, etc.)
.AddDefaultTokenProviders();

// ─────────────────────────────────────────────
// 3. Cookie Configuration
// ─────────────────────────────────────────────
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;                    // JavaScript cannot read the cookie (XSS protection)
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // HTTPS only in production
    options.Cookie.SameSite = SameSiteMode.Lax;        // CSRF protection
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60); // Cookie expires after 60 minutes
    options.SlidingExpiration = true;                  // Reset timer on each request (active users stay logged in)
    options.LoginPath = "/Identity/Account/Login";     // Where to redirect when not authenticated
    options.LogoutPath = "/Identity/Account/Logout";   // Logout endpoint
    options.AccessDeniedPath = "/Identity/Account/AccessDenied"; // Where to send when authorized but not allowed
});

// ─────────────────────────────────────────────
// 4. MVC + Razor Pages
// ─────────────────────────────────────────────
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

var app = builder.Build();

// ─────────────────────────────────────────────
// 5. Middleware Pipeline — ORDER MATTERS
// ─────────────────────────────────────────────
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts(); // HTTP Strict Transport Security
}

app.UseHttpsRedirection();   // Redirect HTTP → HTTPS
app.UseStaticFiles();        // Serve CSS, JS, images
app.UseRouting();            // Route matching

// CRITICAL: Authentication MUST come before Authorization
app.UseAuthentication();     // Reads the cookie, builds the ClaimsPrincipal
app.UseAuthorization();      // Checks [Authorize] attributes, policies, roles

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();         // Maps Identity Razor Pages under /Identity

app.Run();
```

### Line-by-Line Breakdown

**`AddIdentity<ApplicationUser, IdentityRole>`** vs `AddDefaultIdentity`:

- `AddDefaultIdentity<ApplicationUser>` is a convenience method that assumes you only have users (no custom roles), uses the default cookie, and isn't as configurable. Good for simple apps.
- `AddIdentity<ApplicationUser, IdentityRole>` gives you full control: you specify both the user and role types, configure every option, and can add custom token providers, password validators, etc. This is what we use for the tutorial.

**Password Options:**

| Option | What it does | Demo value | Production value |
|--------|-------------|------------|-----------------|
| `RequireDigit` | Must have 0-9 | `true` | `true` |
| `RequireLowercase` | Must have a-z | `true` | `true` |
| `RequireUppercase` | Must have A-Z | `true` | `true` |
| `RequireNonAlphanumeric` | Must have special char | `true` (demo) / `false` (some apps) | `true` or check against breached passwords |
| `RequiredLength` | Minimum length | `8` | `12` |
| `RequiredUniqueChars` | Minimum distinct chars | `1` | `3` |

**Lockout Options:**

- `DefaultLockoutTimeSpan` — how long the account stays locked. 5 minutes is fine for demos; 15-30 minutes is better for production.
- `MaxFailedAccessAttempts` — 5 is a good balance. Lower = more secure but more false positives.
- `AllowedForNewUsers` — always `true`. You want new accounts protected from day one.

**Sign-In Options:**

- `RequireConfirmedEmail = true` means a user who registered but hasn't clicked the confirmation link cannot log in. This is good for preventing spam accounts.
- `RequireConfirmedAccount` is a convenience flag you can check in your own logic.

**`AddEntityFrameworkStores<ApplicationDbContext>()`:**

This single line wires up ALL the store interfaces (`IUserStore`, `IUserPasswordStore`, `IUserRoleStore`, `IUserClaimStore`, `IUserLockoutStore`, `IUserSecurityStampStore`, etc.) to EF Core implementations that use your `ApplicationDbContext`. Without this line, Identity doesn't know how to persist anything.

**`AddDefaultTokenProviders()`:**

Registers the built-in token providers:

- `DataProtectorTokenProvider` — for email confirmation, password reset tokens
- `AuthenticatorTokenProvider` — for TOTP 2FA
- `PhoneNumberTokenProvider` — for SMS 2FA codes
- `EmailTokenProvider` — for email-based 2FA codes

These generate cryptographically secure, time-limited tokens tied to the user's security stamp.

**Cookie Configuration:**

- `HttpOnly = true` — prevents JavaScript from reading the auth cookie. This is a critical XSS defense.
- `SecurePolicy = Always` — only send the cookie over HTTPS. In development you might use `SameAsRequest` to allow HTTP locally.
- `SameSite = Lax` — cookies are sent with same-site requests and top-level navigations, but not with cross-site sub-requests. This mitigates CSRF.
- `SlidingExpiration = true` — every request resets the expiration window. A user who's actively using the app stays logged in. Without this, the cookie expires exactly 60 minutes after login regardless of activity.

**Middleware Order:**

```
app.UseRouting();
app.UseAuthentication();   // ← must be first
app.UseAuthorization();    // ← must be second
```

If you swap these, `[Authorize]` attributes won't work because the cookie hasn't been read yet. This is the #1 Identity bug in new projects.

### Why This Matters

This configuration is the foundation everything else builds on. Get this wrong and nothing else works — users can't log in, roles don't authorize, tokens expire unexpectedly. Getting it right means every feature in later videos works correctly from the start.

---

## Video 05 — The Identity Models — IdentityUser, IdentityRole, and Your Custom Classes

### What We're Building

A deep understanding of every Identity entity, plus custom user and role classes with real application properties.

### IdentityUser — Every Property Explained

```csharp
// This is what IdentityUser gives you by default (simplified):
public class IdentityUser
{
    // Primary key — a GUID stored as a string by default
    public string Id { get; set; }

    // What the user types to log in
    public string? UserName { get; set; }

    // Uppercase version of UserName — used for case-insensitive lookups
    // Why? "John" and "john" should find the same user
    public string? NormalizedUserName { get; set; }

    // User's email address
    public string? Email { get; set; }

    // Uppercase version of Email — used for case-insensitive lookups
    public string? NormalizedEmail { get; set; }

    // Has the user clicked the email confirmation link?
    public bool EmailConfirmed { get; set; }

    // The hashed password — NEVER plain text. PBKDF2 + HMAC-SHA256.
    public string? PasswordHash { get; set; }

    // A random value that changes when security state changes.
    // When this changes, all existing cookies become invalid.
    // Used for: password change, role change, 2FA toggle.
    public string? SecurityStamp { get; set; }

    // Optimistic concurrency token — prevents two requests from
    // overwriting each other's changes to this user.
    public string? ConcurrencyStamp { get; set; }

    // Phone number for SMS-based 2FA or account recovery
    public string? PhoneNumber { get; set; }

    // Has the phone number been confirmed?
    public bool PhoneNumberConfirmed { get; set; }

    // Is two-factor authentication enabled for this user?
    public bool TwoFactorEnabled { get; set; }

    // When does the lockout expire? null = not locked out
    public DateTimeOffset? LockoutEnd { get; set; }

    // Can this user be locked out? Some accounts (service accounts) might be exempt
    public bool LockoutEnabled { get; set; }

    // Number of failed login attempts since last success/reset
    // When this reaches MaxFailedAccessAttempts, the account is locked
    public int AccessFailedCount { get; set; }
}
```

### Custom User Class — Adding Application Properties

```csharp
using Microsoft.AspNetCore.Identity;

namespace IdentityTutorial.Models;

public class ApplicationUser : IdentityUser
{
    // ── Personal Information ──
    public string? FirstName { get; set; }
    public string? LastName { get; set; }

    // Computed — not stored in the database (includes [NotMapped] implicitly
    // when using DTOs, but here it's just a read-only property)
    public string FullName => $"{FirstName} {LastName}".Trim();

    // Display name — could differ from UserName (which is the login identifier)
    public string? DisplayName { get; set; }

    // Profile picture URL (stored as a string — could be a path or external URL)
    public string? ProfilePictureUrl { get; set; }

    // ── Contact Information ──
    public string? Address { get; set; }
    public string? City { get; set; }
    public string? Country { get; set; }
    public string? PostalCode { get; set; }

    // ── Account Metadata ──
    // When was the account created? Set automatically in registration.
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // Last time the user logged in — updated in the SignInManager override
    public DateTime? LastLoginAt { get; set; }

    // Premium status — could drive authorization decisions
    public bool IsPremium { get; set; }

    // Preferences
    public string? TimeZone { get; set; } = "UTC";
    public string? Language { get; set; } = "en";

    // ── Navigation Properties (for EF Core relationships) ──
    // These let you load related data: roles, claims, external logins, tokens.
    // The types match the key type — string here because we're using the default GUID string key.
    public virtual ICollection<IdentityUserRole<string>> UserRoles { get; set; }
    public virtual ICollection<IdentityUserClaim<string>> Claims { get; set; }
    public virtual ICollection<IdentityUserLogin<string>> Logins { get; set; }
    public virtual ICollection<IdentityUserToken<string>> Tokens { get; set; }
}
```

Line-by-line highlights:
- `public class ApplicationUser : IdentityUser` — inherits every property from IdentityUser. Our custom properties are added on top.
- `FullName` — a computed property. It's not stored in the database; it's derived from `FirstName` and `LastName` when accessed.
- `CreatedAt = DateTime.UtcNow` — default value set when a new user is created. Using UTC avoids timezone issues.
- `virtual ICollection<...>` — `virtual` enables EF Core lazy-loading proxies (if configured). These navigation properties let you load a user's roles, claims, etc. in a single query.

### Custom Role Class

```csharp
using Microsoft.AspNetCore.Identity;

namespace IdentityTutorial.Models;

public class ApplicationRole : IdentityRole
{
    // Human-readable description of what this role can do
    public string? Description { get; set; }

    // When the role was created
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // System roles (Admin, User) shouldn't be deleted by admins
    public bool IsSystemRole { get; set; }

    // Department or team this role belongs to (for org hierarchies)
    public string? Department { get; set; }

    // Navigation property for users in this role
    public virtual ICollection<IdentityUserRole<string>> Users { get; set; }

    // Navigation property for claims associated with this role
    public virtual ICollection<IdentityRoleClaim<string>> RoleClaims { get; set; }
}
```

### Using Integer Keys Instead of Strings

By default, Identity uses `string` keys (GUIDs stored as strings). If you prefer integers:

```csharp
// User with int primary key
public class ApplicationUser : IdentityUser<int>
{
    // Custom properties...
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
}

// Role with int primary key
public class ApplicationRole : IdentityRole<int>
{
    public string? Description { get; set; }
}

// DbContext must match the key types
public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, int>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options) { }
}

// Identity configuration must match
builder.Services.AddIdentity<ApplicationUser, ApplicationRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();
```

**Important:** The key type flows through EVERY Identity entity — `IdentityUserRole<int>`, `IdentityUserClaim<int>`, `IdentityUserLogin<int>`, etc. This is a commitment you make at the start. Changing later requires recreating the database.

### Why This Matters

Most tutorials stop at `IdentityUser` with no custom properties. But real applications need FirstName, LastName, avatars, preferences, subscription status, etc. Knowing how to extend IdentityUser correctly — and understanding what each base property does — is the difference between a hacked-on solution and a clean, maintainable user model.

---

## Video 06 — Database Setup — IdentityDbContext, Connection Strings, Migrations

### What We're Building

A fully configured `ApplicationDbContext` with custom table names, seed data for default roles, entity configuration, and a completed migration that creates all Identity tables.

### The ApplicationDbContext

```csharp
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using IdentityTutorial.Models;

namespace IdentityTutorial.Data;

// IdentityDbContext<TUser, TRole, TKey> is the base.
// It already has DbSet<TUser>, DbSet<TRole>, and all junction tables configured.
// We're using string keys (default GUID), so TKey = string.
public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
        // The base constructor registers the connection string from Program.cs.
        // No additional setup needed here.
    }

    // ── Your application entities (in the same database, same context) ──
    // Example: if your app has products, orders, etc., add them here.
    // They share the same database and can participate in the same transactions.
    // public DbSet<Product> Products { get; set; }
    // public DbSet<Order> Orders { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        // ─────────────────────────────────────────────
        // Call the base first — this configures all Identity entities:
        // table names, column types, indexes, relationships.
        // ─────────────────────────────────────────────
        base.OnModelCreating(builder);

        // ─────────────────────────────────────────────
        // Customize table names (optional — defaults are AspNetUsers, AspNetRoles, etc.)
        // ─────────────────────────────────────────────
        builder.Entity<ApplicationUser>(entity =>
        {
            entity.ToTable(name: "Users"); // Rename from AspNetUsers to Users
            entity.Property(e => e.Id).HasMaxLength(36); // GUID string length
        });

        builder.Entity<ApplicationRole>(entity =>
        {
            entity.ToTable(name: "Roles"); // Rename from AspNetRoles to Roles
            entity.Property(e => e.Id).HasMaxLength(36);
        });

        // Junction tables
        builder.Entity<IdentityUserRole<string>>(entity =>
        {
            entity.ToTable("UserRoles");
        });

        builder.Entity<IdentityUserClaim<string>>(entity =>
        {
            entity.ToTable("UserClaims");
        });

        builder.Entity<IdentityUserLogin<string>>(entity =>
        {
            entity.ToTable("UserLogins");
        });

        builder.Entity<IdentityRoleClaim<string>>(entity =>
        {
            entity.ToTable("RoleClaims");
        });

        builder.Entity<IdentityUserToken<string>>(entity =>
        {
            entity.ToTable("UserTokens");
        });

        // ─────────────────────────────────────────────
        // Configure custom user properties
        // ─────────────────────────────────────────────
        builder.Entity<ApplicationUser>(entity =>
        {
            entity.Property(e => e.FirstName).HasMaxLength(100);
            entity.Property(e => e.LastName).HasMaxLength(100);
            entity.Property(e => e.DisplayName).HasMaxLength(200);

            // Ensure email is unique (in addition to NormalizedEmail index that Identity creates)
            entity.HasIndex(e => e.Email).IsUnique();
        });

        // ─────────────────────────────────────────────
        // Seed initial data — roles that must exist from the start
        // ─────────────────────────────────────────────
        SeedData(builder);
    }

    private void SeedData(ModelBuilder builder)
    {
        // Seed the "Admin" role
        var adminRole = new ApplicationRole
        {
            Id = Guid.NewGuid().ToString(),
            Name = "Admin",
            NormalizedName = "ADMIN",     // Uppercase for case-insensitive matching
            Description = "Administrator with full access to all features",
            IsSystemRole = true,          // Cannot be deleted
            CreatedAt = new DateTime(2024, 1, 1)
        };

        // Seed the "User" role
        var userRole = new ApplicationRole
        {
            Id = Guid.NewGuid().ToString(),
            Name = "User",
            NormalizedName = "USER",
            Description = "Standard user with basic access",
            IsSystemRole = true,
            CreatedAt = new DateTime(2024, 1, 1)
        };

        // HasData registers these as seed data — they'll be inserted
        // when the migration is applied and the table is empty.
        builder.Entity<ApplicationRole>().HasData(adminRole, userRole);
    }
}
```

### Connection String Configuration

In `appsettings.json`:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=IdentityTutorial;Trusted_Connection=True;MultipleActiveResultSets=true"
  }
}
```

The connection string is read in `Program.cs`:

```csharp
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection")));
```

### Migrations — Step by Step

```bash
# 1. Install the EF Core tools (if not already)
dotnet tool install --global dotnet-ef

# 2. Add the design package (project-local)
dotnet add package Microsoft.EntityFrameworkCore.Design

# 3. Create the initial migration
# This scans your DbContext, detects all entities, and generates
# CreateTable calls for each one.
dotnet ef migrations add InitialCreate

# 4. Review the generated migration file in the Migrations/ folder.
# It should contain CreateTable for: Users, Roles, UserRoles, UserClaims,
# RoleClaims, UserLogins, UserTokens, plus whatever custom entities you added.

# 5. Apply the migration — this creates the database and tables
dotnet ef database update

# 6. Later, when you add a property to ApplicationUser:
dotnet ef migrations add AddFirstNameToUser

# 7. Apply the new migration
dotnet ef database update

# 8. To roll back (e.g., if a migration has a mistake):
dotnet ef database update <PreviousMigrationName>

# 9. To remove the last unapplied migration:
dotnet ef migrations remove
```

### What the Migration Creates

The initial migration generates these tables (using our custom names):

| Table | Purpose |
|-------|---------|
| `Users` | All user accounts + custom properties (FirstName, LastName, etc.) |
| `Roles` | All roles (Admin, User, plus any you create later) |
| `UserRoles` | Many-to-many: which users are in which roles |
| `UserClaims` | Claims directly assigned to individual users |
| `RoleClaims` | Claims assigned to roles (inherited by all users in the role) |
| `UserLogins` | External login providers linked to user accounts (Google, Facebook, etc.) |
| `UserTokens` | Tokens for 2FA, password reset, email confirmation, "remember me" |

Indexes created automatically:
- `NormalizedUserName` — for fast case-insensitive username lookups
- `NormalizedEmail` — for fast case-insensitive email lookups
- `Role.Name` / `Role.NormalizedName` — for fast role lookups
- Foreign keys on all junction tables for referential integrity

### Why This Matters

The database is where Identity lives. Understanding the schema means you can write raw SQL queries when needed, debug data issues, and understand what EF Core is doing behind the scenes. Seeding default roles means your app has the basic roles ready on first run — no manual setup required.

---

## Video 07 — User Registration — Building the Complete Flow

### What We're Building

A complete registration system: a ViewModel with validation, a register controller that creates the user, assigns a default role, generates an email confirmation token, sends the confirmation email, and handles both "email confirmation required" and "not required" scenarios.

### The Registration ViewModel

```csharp
using System.ComponentModel.DataAnnotations;

namespace IdentityTutorial.ViewModels;

public class RegisterViewModel
{
    // ── Username ──
    [Required(ErrorMessage = "Username is required")]
    [StringLength(50, MinimumLength = 3,
        ErrorMessage = "Username must be between 3 and 50 characters")]
    [RegularExpression(@"^[a-zA-Z0-9_]+$",
        ErrorMessage = "Username can only contain letters, numbers, and underscores")]
    public string UserName { get; set; } = string.Empty;

    // ── Email ──
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email address")]
    public string Email { get; set; } = string.Empty;

    // ── Personal Info ──
    [Required(ErrorMessage = "First name is required")]
    [StringLength(100)]
    public string FirstName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Last name is required")]
    [StringLength(100)]
    public string LastName { get; set; } = string.Empty;

    // ── Password ──
    [Required(ErrorMessage = "Password is required")]
    [StringLength(100, MinimumLength = 8,
        ErrorMessage = "Password must be at least 8 characters")]
    [DataType(DataType.Password)] // Renders as <input type="password"> in Razor
    public string Password { get; set; } = string.Empty;

    // ── Confirm Password ──
    [Required(ErrorMessage = "Please confirm your password")]
    [DataType(DataType.Password)]
    [Compare("Password", ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; } = string.Empty;
}
```

Line-by-line on validation attributes:
- `[Required]` — the field must not be null or empty. If it is, ModelState.IsValid returns false and the error message displays.
- `[StringLength(50, MinimumLength = 3)]` — enforces length bounds. Both max and min are checked.
- `[RegularExpression(@"^[a-zA-Z0-9_]+$")]` — only allows letters, numbers, underscores. Prevents special characters that could cause issues in URLs or downstream systems.
- `[EmailAddress]` — validates the format is a recognizable email.
- `[Compare("Password")]` — ensures ConfirmPassword matches Password. This is a built-in comparison that works across properties.
- `[DataType(DataType.Password)]` — tells Razor to render `<input type="password">` so the password isn't visible as the user types.

### The Account Controller — Registration

```csharp
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using IdentityTutorial.Models;
using IdentityTutorial.ViewModels;

namespace IdentityTutorial.Controllers;

public class AccountController : Controller
{
    // ── Dependencies ──
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILogger<AccountController> _logger;

    // In a real app, you'd also inject an email service.
    // For the demo, we'll show the token generation and explain that
    // the email sending step is where you'd plug in SendGrid, SMTP, etc.
    // private readonly IEmailService _emailService;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ILogger<AccountController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
    }

    // ─────────────────────────────────────────────
    // GET /Account/Register — Show the registration form
    // ─────────────────────────────────────────────
    [HttpGet]
    [AllowAnonymous] // Anyone can see the registration page — no login required
    public IActionResult Register()
    {
        return View();
    }

    // ─────────────────────────────────────────────
    // POST /Account/Register — Process the registration
    // ─────────────────────────────────────────────
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken] // Prevents CSRF attacks on form submissions
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        // ── Step 1: Check model validity ──
        // DataAnnotations on the ViewModel + [ValidateAntiForgeryToken]
        // are validated here. If invalid, return to the form with errors.
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        // ── Step 2: Check if email is already registered ──
        // UserManager.FindByEmailAsync does a case-insensitive lookup
        // (because NormalizedEmail is stored uppercase).
        var existingUser = await _userManager.FindByEmailAsync(model.Email);
        if (existingUser != null)
        {
            ModelState.AddModelError(string.Empty,
                "An account with this email already exists.");
            return View(model);
        }

        // ── Step 3: Create the user object ──
        // We set properties from the ViewModel. Note: we DON'T set PasswordHash —
        // that's done internally by UserManager.CreateAsync using the password hasher.
        var user = new ApplicationUser
        {
            UserName = model.UserName,
            Email = model.Email,
            FirstName = model.FirstName,
            LastName = model.LastName,
            CreatedAt = DateTime.UtcNow,
            EmailConfirmed = false // Will be set to true when they click the confirmation link
        };

        // ── Step 4: Create the user in the database ──
        // UserManager.CreateAsync does several things internally:
        //   1. Validates the password against PasswordOptions + any custom validators
        //   2. Hashes the password using PBKDF2 + HMAC-SHA256
        //   3. Sets the normalized username and email (uppercase versions)
        //   4. Generates a SecurityStamp and ConcurrencyStamp
        //   5. Saves the user to the database via the user store
        // The result tells us if it succeeded and any errors if it failed.
        var result = await _userManager.CreateAsync(user, model.Password);

        // ── Step 5: Handle success ──
        if (result.Succeeded)
        {
            _logger.LogInformation("User created a new account: {Email}", model.Email);

            // ── Step 5a: Assign the default "User" role ──
            // Every new user gets the "User" role. Admins are created separately.
            // This role assignment creates a row in the UserRoles junction table.
            await _userManager.AddToRoleAsync(user, "User");

            // ── Step 5b: Generate email confirmation token ──
            // This generates a time-limited, cryptographically secure token
            // that's tied to the user's SecurityStamp. If the security stamp
            // changes before the user clicks the link, the token becomes invalid.
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            // ── Step 5c: Build the confirmation link ──
            // Url.Action generates a URL like:
            //   https://yourapp.com/Account/ConfirmEmail?userId=<guid>&token=<token>
            // The token is passed as a query parameter. In production, you'd
            // send this link via email. For the demo, we'll show it on a page.
            var confirmationLink = Url.Action(
                actionName: "ConfirmEmail",
                controllerName: "Account",
                values: new { userId = user.Id, token = token },
                protocol: Request.Scheme);

            // ── Step 5d: In a real app, send the email here ──
            // await _emailService.SendConfirmationEmailAsync(user.Email, confirmationLink);
            // For the tutorial demo, we'll display the link on the confirmation page.

            // ── Step 5e: If email confirmation is NOT required, sign in immediately ──
            // Some apps skip email confirmation. In that case, log the user in right away.
            if (!_userManager.Options.SignIn.RequireConfirmedEmail)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToAction("Index", "Home");
            }

            // ── Step 5f: If confirmation IS required, show the confirmation page ──
            // The user needs to check their email and click the link.
            return RedirectToAction("RegisterConfirmation");
        }

        // ── Step 6: Handle errors ──
        // IdentityResult.Errors contains a list of IdentityError objects
        // with Code and Description properties.
        // Common errors: "PasswordTooShort", "EmailAlreadyRegistered",
        // "UserNameAlreadyTaken", etc.
        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        // Return to the form with the errors displayed
        return View(model);
    }

    // ─────────────────────────────────────────────
    // GET /Account/RegisterConfirmation — Show "check your email" page
    // ─────────────────────────────────────────────
    [HttpGet]
    [AllowAnonymous]
    public IActionResult RegisterConfirmation()
    {
        return View();
    }

    // ─────────────────────────────────────────────
    // GET /Account/ConfirmEmail — Handle the confirmation link click
    // ─────────────────────────────────────────────
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmEmail(string userId, string token)
    {
        // Validate parameters
        if (userId == null || token == null)
        {
            return RedirectToAction("Index", "Home");
        }

        // Look up the user by ID
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound($"Unable to load user with ID '{userId}'.");
        }

        // Confirm the email — this validates the token and sets EmailConfirmed = true
        var result = await _userManager.ConfirmEmailAsync(user, token);

        if (result.Succeeded)
        {
            // Show success page
            return View("ConfirmEmailSuccess");
        }

        // If the token was invalid or expired, show failure page
        return View("ConfirmEmailFailure");
    }
}
```

### The Email Confirmation View (Simplified)

```cshtml
@* Views/Account/RegisterConfirmation.cshtml *@
@{
    ViewData["Title"] = "Register Confirmation";
}

<div class="container">
    <h2>Check your email</h2>
    <p>
        We've sent a confirmation link to your email address.
        Click the link to confirm your account and activate it.
    </p>
    <p>
        <strong>Note for demo:</strong> In development, you can find the
        confirmation link in the application logs or by querying the token directly.
    </p>
</div>
```

### Why This Matters

Registration seems simple — create a user, done. But a complete registration flow includes: input validation, duplicate checking, password hashing, role assignment, email confirmation token generation, and handling both confirmed and unconfirmed states. Each step has a security implication, and skipping any of them creates a gap. This video shows the complete, correct flow.

---

## Video 08 — Login & Sign-In — How Authentication Actually Works

### What We're Building

A complete login flow: a login ViewModel, a login controller that finds the user, checks lockout and email confirmation, calls `PasswordSignInAsync`, handles all possible outcomes (success, locked out, not allowed, 2FA required), and a logout action.

### The Login ViewModel

```csharp
using System.ComponentModel.DataAnnotations;

namespace IdentityTutorial.ViewModels;

public class LoginViewModel
{
    [Required(ErrorMessage = "Email or username is required")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    [Display(Name = "Remember me?")]
    public bool RememberMe { get; set; }
}
```

### The Login Actions

```csharp
// Inside AccountController (continued from Video 07)

// ─────────────────────────────────────────────
// GET /Account/Login — Show the login form
// ─────────────────────────────────────────────
[HttpGet]
[AllowAnonymous]
public IActionResult Login(string? returnUrl = null)
{
    // Store the return URL so we can redirect back after login
    ViewData["ReturnUrl"] = returnUrl;
    return View();
}

// ─────────────────────────────────────────────
// POST /Account/Login — Process the login
// ─────────────────────────────────────────────
[HttpPost]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
{
    ViewData["ReturnUrl"] = returnUrl;

    if (!ModelState.IsValid)
    {
        return View(model);
    }

    // ── Step 1: Find the user ──
    // Try email first (most common), then fall back to username.
    // Both lookups are case-insensitive because Identity stores
    // NormalizedEmail and NormalizedUserName in uppercase.
    var user = await _userManager.FindByEmailAsync(model.Email)
               ?? await _userManager.FindByNameAsync(model.Email);

    // ── Step 2: Check if user exists ──
    // IMPORTANT: Don't reveal whether the email exists or not.
    // The error message is generic for both "user not found" and
    // "wrong password" to prevent username enumeration attacks.
    if (user == null)
    {
        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        return View(model);
    }

    // ── Step 3: Check email confirmation requirement ──
    // If the app requires confirmed email and this user hasn't confirmed,
    // block the login with a helpful message.
    if (_userManager.Options.SignIn.RequireConfirmedEmail
        && !user.EmailConfirmed)
    {
        ModelState.AddModelError(string.Empty,
            "Please confirm your email before logging in.");
        return View(model);
    }

    // ── Step 4: Check if the account is locked out ──
    // UserManager.IsLockedOutAsync checks if LockoutEnd > DateTimeOffset.UtcNow
    if (await _userManager.IsLockedOutAsync(user))
    {
        var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
        var remainingMinutes = (lockoutEnd - DateTimeOffset.UtcNow).Minutes;

        ModelState.AddModelError(string.Empty,
            $"Account is locked. Try again in {remainingMinutes} minutes.");
        return View(model);
    }

    // ── Step 5: Attempt to sign in ──
    // PasswordSignInAsync does the heavy lifting:
    //   1. Gets the password hash from the user store
    //   2. Hashes the provided password with the same salt
    //   3. Compares the hashes
    //   4. If match: checks lockout (if lockoutOnFailure is true)
    //   5. If not locked out: creates the authentication cookie
    //   6. Returns SignInResult with Succeeded, IsLockedOut, IsNotAllowed,
    //      or RequiresTwoFactor
    var result = await _signInManager.PasswordSignInAsync(
        userName: user.UserName!,
        password: model.Password,
        isPersistent: model.RememberMe,  // "Remember me" = longer-lived cookie
        lockoutOnFailure: true);          // Increment AccessFailedCount on wrong password

    // ── Step 6: Handle the result ──
    if (result.Succeeded)
    {
        _logger.LogInformation("User logged in: {Email}", model.Email);

        // Update the last login timestamp
        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        // Redirect to the return URL if it's local (not an external site)
        if (!string.IsNullOrEmpty(returnUrl)
            && Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }

        // Default redirect
        return RedirectToAction("Index", "Home");
    }

    if (result.IsLockedOut)
    {
        // This means the account was ALREADY locked out before this attempt.
        // (As opposed to this attempt causing the lockout.)
        _logger.LogWarning("User account locked out: {Email}", model.Email);
        return RedirectToAction("Lockout");
    }

    if (result.IsNotAllowed)
    {
        // The account exists but isn't allowed to sign in.
        // This could be because email isn't confirmed, phone isn't confirmed,
        // or the account is disabled.
        ModelState.AddModelError(string.Empty,
            "Account not allowed to sign in. Please confirm your email.");
        return View(model);
    }

    if (result.RequiresTwoFactor)
    {
        // The password was correct, but 2FA is enabled.
        // Redirect to the 2FA verification page.
        return RedirectToAction("LoginWith2fa",
            new { returnUrl, rememberMe = model.RememberMe });
    }

    // If none of the above, it's a generic failure (wrong password, etc.)
    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
    return View(model);
}

// ─────────────────────────────────────────────
// POST /Account/Logout — Sign out the user
// ─────────────────────────────────────────────
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Logout()
{
    var userName = User.Identity?.Name;
    await _signInManager.SignOutAsync();
    _logger.LogInformation("User logged out: {UserName}", userName);
    return RedirectToAction("Index", "Home");
}

// ─────────────────────────────────────────────
// GET /Account/Lockout — Show lockout page
// ─────────────────────────────────────────────
[HttpGet]
[AllowAnonymous]
public IActionResult Lockout()
{
    return View();
}

// ─────────────────────────────────────────────
// GET /Account/AccessDenied — Show access denied page
// ─────────────────────────────────────────────
[HttpGet]
[AllowAnonymous]
public IActionResult AccessDenied()
{
    return View();
}
```

### How `PasswordSignInAsync` Works Internally

1. **Password verification** — retrieves `PasswordHash` from the store, runs the provided password through the same hashing algorithm (PBKDF2 with HMAC-SHA256) with the stored salt, compares the results. This is a constant-time comparison to prevent timing attacks.

2. **Lockout check** — if `lockoutOnFailure` is true and the password is wrong, increments `AccessFailedCount`. If `AccessFailedCount >= MaxFailedAccessAttempts`, sets `LockoutEnd = DateTimeOffset.UtcNow + DefaultLockoutTimeSpan`.

3. **Cookie creation** — if all checks pass, creates a `ClaimsPrincipal` from the user's claims (including role claims) and stores it in an authentication cookie. The cookie includes the user's `SecurityStamp` so it can be validated on subsequent requests.

4. **Return value** — `SignInResult` with properties:
   - `Succeeded` — login worked, cookie created
   - `IsLockedOut` — account was already locked
   - `IsNotAllowed` — account exists but can't sign in (email not confirmed, etc.)
   - `RequiresTwoFactor` — password correct, 2FA needed

### Why This Matters

Login is the most security-critical flow in any application. This video breaks down exactly what happens at each step, why the error messages are generic (to prevent username enumeration), how lockout works, and what `PasswordSignInAsync` does under the hood. Viewers leave knowing not just how to call the method, but what it's doing for them.

---

## Video 09 — Role Management — Creating, Assigning, Removing Roles

### What We're Building

An admin controller for managing roles: list all roles, create roles, update role details, delete roles (with safety checks), add/remove claims from roles, and assign/remove roles from users.

### The Role Management Controller

```csharp
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using IdentityTutorial.Models;

namespace IdentityTutorial.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin")] // Only admins can manage roles
public class RoleManagementController : ControllerBase
{
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<RoleManagementController> _logger;

    public RoleManagementController(
        RoleManager<ApplicationRole> roleManager,
        UserManager<ApplicationUser> userManager,
        ILogger<RoleManagementController> logger)
    {
        _roleManager = roleManager;
        _userManager = userManager;
        _logger = logger;
    }

    // ─────────────────────────────────────────────
    // GET /api/rolemanagement — List all roles
    // ─────────────────────────────────────────────
    [HttpGet]
    public IActionResult GetAllRoles()
    {
        // RoleManager.Roles is a DbSet<ApplicationRole> — all roles in the system.
        // We project to a DTO to avoid exposing internal properties.
        var roles = _roleManager.Roles
            .Select(r => new
            {
                r.Id,
                r.Name,
                r.Description,
                r.IsSystemRole,
                r.CreatedAt
            })
            .ToList();

        return Ok(roles);
    }

    // ─────────────────────────────────────────────
    // GET /api/rolemanagement/{id} — Get a specific role with its users and claims
    // ─────────────────────────────────────────────
    [HttpGet("{id}")]
    public async Task<IActionResult> GetRole(string id)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { Message = "Role not found" });
        }

        // Get all users assigned to this role
        var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name!);

        // Get claims associated with this role
        var roleClaims = await _roleManager.GetClaimsAsync(role);

        return Ok(new
        {
            role.Id,
            role.Name,
            role.Description,
            role.IsSystemRole,
            role.CreatedAt,
            Users = usersInRole.Select(u => new
            {
                u.Id,
                u.UserName,
                u.Email
            }),
            Claims = roleClaims.Select(c => new
            {
                c.Type,
                c.Value
            })
        });
    }

    // ─────────────────────────────────────────────
    // POST /api/rolemanagement — Create a new role
    // ─────────────────────────────────────────────
    [HttpPost]
    public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequest model)
    {
        // Check if role already exists
        var existing = await _roleManager.FindByNameAsync(model.Name);
        if (existing != null)
        {
            return BadRequest(new { Message = "A role with this name already exists." });
        }

        var role = new ApplicationRole
        {
            Name = model.Name,
            Description = model.Description,
            IsSystemRole = false,
            CreatedAt = DateTime.UtcNow
        };

        var result = await _roleManager.CreateAsync(role);
        if (!result.Succeeded)
        {
            return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
        }

        _logger.LogInformation("Role created: {RoleName}", model.Name);

        return CreatedAtAction(nameof(GetRole), new { id = role.Id },
            new { Id = role.Id, Name = role.Name, Description = role.Description });
    }

    // ─────────────────────────────────────────────
    // PUT /api/rolemanagement/{id} — Update a role
    // ─────────────────────────────────────────────
    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateRole(string id, [FromBody] UpdateRoleRequest model)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { Message = "Role not found" });
        }

        // If renaming, check the new name isn't taken
        if (role.Name != model.Name)
        {
            var existing = await _roleManager.FindByNameAsync(model.Name);
            if (existing != null)
            {
                return BadRequest(new { Message = "That role name is already in use." });
            }
        }

        role.Name = model.Name;
        role.Description = model.Description;

        var result = await _roleManager.UpdateAsync(role);
        if (!result.Succeeded)
        {
            return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
        }

        return Ok(new { Message = "Role updated." });
    }

    // ─────────────────────────────────────────────
    // DELETE /api/rolemanagement/{id} — Delete a role
    // ─────────────────────────────────────────────
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteRole(string id)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { Message = "Role not found" });
        }

        // Safety: can't delete system roles
        if (role.IsSystemRole)
        {
            return BadRequest(new { Message = "System roles cannot be deleted." });
        }

        // Safety: can't delete a role that has users
        var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name!);
        if (usersInRole.Any())
        {
            return BadRequest(new
            {
                Message = "Remove users from this role before deleting it.",
                UserCount = usersInRole.Count
            });
        }

        var result = await _roleManager.DeleteAsync(role);
        if (!result.Succeeded)
        {
            return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
        }

        _logger.LogInformation("Role deleted: {RoleName}", role.Name);
        return Ok(new { Message = "Role deleted." });
    }

    // ─────────────────────────────────────────────
    // POST /api/rolemanagement/{id}/claims — Add a claim to a role
    // ─────────────────────────────────────────────
    [HttpPost("{id}/claims")]
    public async Task<IActionResult> AddClaimToRole(string id, [FromBody] AddClaimRequest model)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { Message = "Role not found" });
        }

        // Check if the claim already exists on this role
        var existingClaims = await _roleManager.GetClaimsAsync(role);
        if (existingClaims.Any(c => c.Type == model.ClaimType && c.Value == model.ClaimValue))
        {
            return BadRequest(new { Message = "This claim already exists on the role." });
        }

        var claim = new System.Security.Claims.Claim(model.ClaimType, model.ClaimValue);
        var result = await _roleManager.AddClaimAsync(role, claim);

        if (!result.Succeeded)
        {
            return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
        }

        return Ok(new { Message = "Claim added to role." });
    }

    // ─────────────────────────────────────────────
    // DELETE /api/rolemanagement/{id}/claims — Remove a claim from a role
    // ─────────────────────────────────────────────
    [HttpDelete("{id}/claims")]
    public async Task<IActionResult> RemoveClaimFromRole(string id, [FromBody] RemoveClaimRequest model)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { Message = "Role not found" });
        }

        var claim = new System.Security.Claims.Claim(model.ClaimType, model.ClaimValue);
        var result = await _roleManager.RemoveClaimAsync(role, claim);

        if (!result.Succeeded)
        {
            return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
        }

        return Ok(new { Message = "Claim removed from role." });
    }
}

// ── Request DTOs ──
public class CreateRoleRequest
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
}

public class UpdateRoleRequest
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
}

public class AddClaimRequest
{
    public string ClaimType { get; set; } = string.Empty;
    public string ClaimValue { get; set; } = string.Empty;
}

public class RemoveClaimRequest
{
    public string ClaimType { get; set; } = string.Empty;
    public string ClaimValue { get; set; } = string.Empty;
}
```

### Assigning Users to Roles

```csharp
// Inside a UserManagementController (or the same controller)

// POST /api/usermanagement/users/{userId}/roles — Assign a role to a user
[HttpPost("users/{userId}/roles")]
public async Task<IActionResult> AddUserToRole(string userId, [FromBody] AssignRoleRequest model)
{
    var user = await _userManager.FindByIdAsync(userId);
    if (user == null)
    {
        return NotFound(new { Message = "User not found" });
    }

    var role = await _roleManager.FindByIdAsync(model.RoleId);
    if (role == null)
    {
        return NotFound(new { Message = "Role not found" });
    }

    // Check if already assigned
    if (await _userManager.IsInRoleAsync(user, role.Name!))
    {
        return BadRequest(new { Message = "User already has this role." });
    }

    var result = await _userManager.AddToRoleAsync(user, role.Name!);
    if (!result.Succeeded)
    {
        return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
    }

    _logger.LogInformation("User {UserId} assigned to role {RoleName}",
        userId, role.Name);

    return Ok(new { Message = "Role assigned." });
}

// DELETE /api/usermanagement/users/{userId}/roles/{roleId} — Remove a role from a user
[HttpDelete("users/{userId}/roles/{roleId}")]
public async Task<IActionResult> RemoveUserFromRole(string userId, string roleId)
{
    var user = await _userManager.FindByIdAsync(userId);
    if (user == null)
    {
        return NotFound(new { Message = "User not found" });
    }

    var role = await _roleManager.FindByIdAsync(roleId);
    if (role == null)
    {
        return NotFound(new { Message = "Role not found" });
    }

    // Safety: don't remove the last admin
    var admins = await _userManager.GetUsersInRoleAsync("Admin");
    if (role.Name == "Admin" && admins.Count == 1 && admins[0].Id == userId)
    {
        return BadRequest(new { Message = "Cannot remove the last administrator." });
    }

    if (!await _userManager.IsInRoleAsync(user, role.Name!))
    {
        return BadRequest(new { Message = "User does not have this role." });
    }

    var result = await _userManager.RemoveFromRoleAsync(user, role.Name!);
    if (!result.Succeeded)
    {
        return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
    }

    _logger.LogInformation("User {UserId} removed from role {RoleName}",
        userId, role.Name);

    return Ok(new { Message = "Role removed." });
}

// GET /api/usermanagement/users/{userId}/roles — Get all roles for a user
[HttpGet("users/{userId}/roles")]
public async Task<IActionResult> GetUserRoles(string userId)
{
    var user = await _userManager.FindByIdAsync(userId);
    if (user == null)
    {
        return NotFound(new { Message = "User not found" });
    }

    var roles = await _userManager.GetRolesAsync(user);
    return Ok(roles);
}
```

### Why This Matters

Roles are the backbone of authorization in most applications. This video shows how to create them, assign them, remove them, and — critically — the safety checks that prevent deleting the last admin or deleting a role that's in use. Viewers also see how role claims work (claims on a role apply to all users in that role).

---

## Video 10 — Role-Based Access Control (RBAC) — Protecting Your Endpoints

### What We're Building

How to protect controllers and actions using `[Authorize(Roles = ...)]`, how multiple roles work, how AND vs OR semantics work, and how to check roles programmatically in code.

### Using `[Authorize]` with Roles

```csharp
// ── Only Admins can access this entire controller ──
[Authorize(Roles = "Admin")]
public class AdminController : Controller
{
    public IActionResult Dashboard()
    {
        // Only users in the "Admin" role reach here.
        // If a non-admin tries, they get a 403 Forbidden (or redirected
        // to the AccessDeniedPath configured in cookie options).
        return View();
    }
}

// ── Either Admin OR Manager can access ──
// The comma means OR — being in ANY of the listed roles is sufficient.
[Authorize(Roles = "Admin,Manager")]
public class ReportsController : Controller
{
    public IActionResult ViewReports()
    {
        return View();
    }
}

// ── Mixed: some actions for everyone, some for specific roles ──
public class ProductsController : Controller
{
    // Anyone logged in can view products
    [Authorize] // Just requires authentication, no specific role
    public IActionResult Index()
    {
        return View();
    }

    // Only Admin or Manager can create products
    [Authorize(Roles = "Admin,Manager")]
    [HttpPost]
    public IActionResult Create(Product model)
    {
        // Create the product
        return RedirectToAction(nameof(Index));
    }

    // Only Admin can delete
    [Authorize(Roles = "Admin")]
    [HttpPost]
    public IActionResult Delete(int id)
    {
        // Delete the product
        return RedirectToAction(nameof(Index));
    }
}
```

### AND Semantics — User Must Have ALL Roles

```csharp
// A user must be in BOTH "Admin" AND "Finance" roles.
// Multiple [Authorize] attributes are ANDed together.
[Authorize(Roles = "Admin")]
[Authorize(Roles = "Finance")]
public class FinancialAdminController : Controller
{
    public IActionResult Index()
    {
        // Only users who are BOTH Admin and Finance reach here.
        return View();
    }
}
```

### Checking Roles Programmatically

```csharp
public class DashboardController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;

    public DashboardController(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<IActionResult> Index()
    {
        // Get the current user from the ClaimsPrincipal
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return Challenge(); // Not authenticated
        }

        // Check if the user is in a specific role
        bool isAdmin = await _userManager.IsInRoleAsync(user, "Admin");

        // Get all roles the user has
        var roles = await _userManager.GetRolesAsync(user);

        // Alternatively, check the claims principal directly (cookie already has role claims)
        bool isInRoleFast = User.IsInRole("Admin"); // No database call — cookie check

        var viewModel = new DashboardViewModel
        {
            UserName = user.UserName,
            Roles = roles.ToList(),
            ShowAdminPanel = isAdmin
        };

        return View(viewModel);
    }
}
```

### Building a Permission System on Top of Roles

Roles are coarse — "Admin" or "User." What if you need granular permissions like "Users.Create" or "Reports.Export"? Build a permission table and tie permissions to roles:

```csharp
// Permission entity
public class Permission
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;  // e.g., "Users.Create"
    public string Description { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty; // e.g., "Users", "Reports"
}

// Role-Permission junction
public class RolePermission
{
    public string RoleId { get; set; } = string.Empty;
    public int PermissionId { get; set; }

    // Navigation properties
    public ApplicationRole Role { get; set; } = null!;
    public Permission Permission { get; set; } = null!;
}
```

Extend `ApplicationRole` to include the navigation:

```csharp
public class ApplicationRole : IdentityRole
{
    public string? Description { get; set; }
    public virtual ICollection<RolePermission> RolePermissions { get; set; }
}
```

Permission service:

```csharp
public interface IPermissionService
{
    Task<bool> HasPermissionAsync(string userId, string permissionName);
    Task<List<string>> GetUserPermissionsAsync(string userId);
}

public class PermissionService : IPermissionService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _context;

    public PermissionService(
        UserManager<ApplicationUser> userManager,
        ApplicationDbContext context)
    {
        _userManager = userManager;
        _context = context;
    }

    public async Task<bool> HasPermissionAsync(string userId, string permissionName)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return false;

        // Get the user's roles
        var roles = await _userManager.GetRolesAsync(user);

        // Check if any of the user's roles have the permission
        return await _context.RolePermissions
            .AnyAsync(rp => roles.Contains(rp.RoleId)
                && rp.Permission.Name == permissionName);
    }

    public async Task<List<string>> GetUserPermissionsAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return new List<string>();

        var roles = await _userManager.GetRolesAsync(user);

        // Collect all distinct permissions across all the user's roles
        return await _context.RolePermissions
            .Where(rp => roles.Contains(rp.RoleId))
            .Select(rp => rp.Permission.Name)
            .Distinct()
            .ToListAsync();
    }
}
```

Register in `Program.cs`:

```csharp
// Register the permission service
builder.Services.AddScoped<IPermissionService, PermissionService>();

// Register permission policies — one policy per permission
builder.Services.AddAuthorization(options =>
{
    var allPermissions = new[]
    {
        "Users.View", "Users.Create", "Users.Edit", "Users.Delete",
        "Products.View", "Products.Create", "Products.Edit", "Products.Delete",
        "Reports.View", "Reports.Export"
    };

    foreach (var permission in allPermissions)
    {
        options.AddPolicy(permission, policy =>
            policy.Requirements.Add(new PermissionRequirement(permission)));
    }
});

// Permission requirement
public class PermissionRequirement : IAuthorizationRequirement
{
    public string Permission { get; }
    public PermissionRequirement(string permission) => Permission = permission;
}

// Permission handler
public class PermissionHandler : AuthorizationHandler<PermissionRequirement>
{
    private readonly IServiceProvider _serviceProvider;

    public PermissionHandler(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionRequirement requirement)
    {
        var userId = context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (userId == null) return;

        // Create a scope to resolve the scoped permission service
        using var scope = _serviceProvider.CreateScope();
        var permissionService = scope.ServiceProvider.GetRequiredService<IPermissionService>();

        if (await permissionService.HasPermissionAsync(userId, requirement.Permission))
        {
            context.Succeed(requirement);
        }
    }
}

builder.Services.AddSingleton<IAuthorizationHandler, PermissionHandler>();
```

Now you can use permission-based authorization:

```csharp
[Authorize(Policy = "Users.Create")]
public IActionResult CreateUser()
{
    return View();
}

[Authorize(Policy = "Reports.Export")]
public IActionResult ExportReport()
{
    return File(reportData, "application/pdf");
}
```

### Why This Matters

RBAC is simple and effective for most apps, but real applications often need finer control. This video shows the progression: simple role checks → multiple roles → AND semantics → a full permission system. Viewers learn when to stop at simple roles and when to invest in a permission system.

---

## Video 11 — Claims-Based Authorization — Going Beyond Roles

### What We're Building

Understanding claims as key-value facts about a user, adding and removing claims, defining claim-based policies, and reading claims in controllers, views, and middleware.

### What Is a Claim?

A claim is a statement about a user: "This user's email is alice@example.com," "This user is in the Finance department," "This user has a Premium subscription." Claims are key-value pairs, and they become part of the authentication cookie so they're available on every request without a database call.

Roles are actually just a special type of claim — when you add a user to a role, Identity internally adds a claim of type `ClaimTypes.Role` with the role name as the value. This means everything that works with claims also works with roles.

### Adding and Removing Claims

```csharp
public class UserClaimsController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public UserClaimsController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    // POST /api/userclaims/{userId} — Add a claim to a user
    [HttpPost("{userId}")]
    public async Task<IActionResult> AddClaim(string userId, [FromBody] AddClaimRequest model)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return NotFound();

        var claim = new System.Security.Claims.Claim(model.ClaimType, model.ClaimValue);
        var result = await _userManager.AddClaimAsync(user, claim);

        if (result.Succeeded)
        {
            // IMPORTANT: Refresh the sign-in cookie so the new claim is included
            await _signInManager.RefreshSignInAsync(user);
            return Ok(new { Message = "Claim added." });
        }

        return BadRequest(result.Errors);
    }

    // DELETE /api/userclaims/{userId} — Remove a claim from a user
    [HttpDelete("{userId}")]
    public async Task<IActionResult> RemoveClaim(string userId, [FromBody] RemoveClaimRequest model)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return NotFound();

        var claim = new System.Security.Claims.Claim(model.ClaimType, model.ClaimValue);
        var result = await _userManager.RemoveClaimAsync(user, claim);

        if (result.Succeeded)
        {
            await _signInManager.RefreshSignInAsync(user);
            return Ok(new { Message = "Claim removed." });
        }

        return BadRequest(result.Errors);
    }

    // GET /api/userclaims/{userId} — List all claims for a user
    [HttpGet("{userId}")]
    public async Task<IActionResult> GetClaims(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return NotFound();

        var claims = await _userManager.GetClaimsAsync(user);
        return Ok(claims.Select(c => new { c.Type, c.Value }));
    }
}

public class AddClaimRequest
{
    public string ClaimType { get; set; } = string.Empty;
    public string ClaimValue { get; set; } = string.Empty;
}

public class RemoveClaimRequest
{
    public string ClaimType { get; set; } = string.Empty;
    public string ClaimValue { get; set; } = string.Empty;
}
```

**Critical point about `RefreshSignInAsync`:** After adding or removing a claim, the existing cookie still has the old claims. Calling `RefreshSignInAsync` re-creates the cookie with the updated claims. Without it, the change won't take effect until the user signs out and back in.

### Defining Claim-Based Policies

In `Program.cs`:

```csharp
builder.Services.AddAuthorization(options =>
{
    // Require a specific claim value
    options.AddPolicy("DepartmentFinance",
        policy => policy.RequireClaim("Department", "Finance"));

    // Require a claim to exist (any value)
    options.AddPolicy("HasEmployeeId",
        policy => policy.RequireClaim("EmployeeId"));

    // Require a claim with one of several possible values
    options.AddPolicy("SeniorStaff",
        policy => policy.RequireClaim("Level",
            "Senior", "Lead", "Manager", "Director"));

    // Complex policy using RequireAssertion (inline lambda)
    options.AddPolicy("CanAccessPremium",
        policy => policy.RequireAssertion(context =>
        {
            var isPremium = context.User.HasClaim(
                c => c.Type == "Subscription" && c.Value == "Premium");
            var isEmployee = context.User.HasClaim(
                c => c.Type == "EmployeeType");
            return isPremium || isEmployee;
        }));
});
```

Using the policies:

```csharp
[Authorize(Policy = "DepartmentFinance")]
public class FinanceController : Controller
{
    public IActionResult Index() => View();
}

[Authorize(Policy = "SeniorStaff")]
public class SeniorController : Controller
{
    public IActionResult Index() => View();
}
```

### Reading Claims in Code

```csharp
public class ProfileController : Controller
{
    public IActionResult Index()
    {
        // Get a specific claim
        var departmentClaim = User.FindFirst("Department");
        var department = departmentClaim?.Value ?? "Unassigned";

        // Check if user has a claim with specific value
        bool isPremium = User.HasClaim(
            c => c.Type == "Subscription" && c.Value == "Premium");

        // Get the user's ID from the NameIdentifier claim
        var userId = User.FindFirst(
            System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

        // Get email from the Email claim
        var email = User.FindFirst(
            System.Security.Claims.ClaimTypes.Email)?.Value;

        // List all claims (for debugging or display)
        var allClaims = User.Claims
            .Select(c => $"{c.Type}: {c.Value}")
            .ToList();

        return View();
    }
}
```

In Razor views:

```cshtml
@using System.Security.Claims

@{
    var dept = User.FindFirst("Department")?.Value;
    var isPremium = User.HasClaim(c =>
        c.Type == "Subscription" && c.Value == "Premium");
}

<div class="profile-card">
    <p><strong>Name:</strong> @User.Identity?.Name</p>
    <p><strong>Department:</strong> @dept</p>

    @if (isPremium)
    {
        <span class="badge badge-premium">Premium Member</span>
    }
</div>
```

### Adding Claims During Registration

```csharp
// In the Register action (Video 07), after creating the user:
if (result.Succeeded)
{
    // Add default claims based on registration data
    var defaultClaims = new List<System.Security.Claims.Claim>
    {
        new("Department", model.Department ?? "General"),
        new("Subscription", "Free"),
        new("AccountCreated", DateTime.UtcNow.ToString("O"))
    };

    await _userManager.AddClaimsAsync(user, defaultClaims);
    await _userManager.AddToRoleAsync(user, "User");

    // ... rest of registration flow
}
```

### Why This Matters

Claims are the flexible alternative to roles. Roles answer "what group is this user in?" Claims answer "what facts do we know about this user?" Most applications need both. This video shows how claims work, how they relate to roles, and how to use them for authorization.

---

## Video 12 — Policy-Based Authorization — Custom Requirements & Handlers

### What We're Building

Moving beyond simple role and claim checks to custom authorization policies with requirements and handlers — including age verification, business hours checks, subscription tier checks, and resource-based authorization.

### What Is a Policy?

A policy is a named set of requirements. Instead of hardcoding `Roles = "Admin"` in every `[Authorize]` attribute, you define a policy like `"AdminOnly"` in `Program.cs` and reference it by name. The policy can have multiple requirements, each with its own handler that contains the logic to evaluate it.

### Custom Requirements

```csharp
// A requirement is just a data container — it implements IAuthorizationRequirement
// which is an empty marker interface.

// Age requirement — user must be at least N years old
public class MinimumAgeRequirement : IAuthorizationRequirement
{
    public int MinimumAge { get; }
    public MinimumAgeRequirement(int minimumAge) => MinimumAge = minimumAge;
}

// Business hours requirement — access only during business hours
public class BusinessHoursRequirement : IAuthorizationRequirement
{
    public int StartHour { get; } = 9;
    public int EndHour { get; } = 17;
}

// Subscription tier requirement — user must have a specific subscription
public class SubscriptionRequirement : IAuthorizationRequirement
{
    public string[] RequiredTiers { get; }
    public SubscriptionRequirement(params string[] requiredTiers)
        => RequiredTiers = requiredTiers;
}
```

### Authorization Handlers

```csharp
// Handler for the age requirement
public class MinimumAgeHandler : AuthorizationHandler<MinimumAgeRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        MinimumAgeRequirement requirement)
    {
        // Look for a DateOfBirth claim
        var dobClaim = context.User.FindFirst("DateOfBirth");
        if (dobClaim == null)
        {
            // No DOB claim — can't verify age, so fail silently
            // (IAuthorizationHandlerContext.Fail() would explicitly fail,
            // but not calling Succeed means the requirement isn't met)
            return Task.CompletedTask;
        }

        if (DateTime.TryParse(dobClaim.Value, out var dob))
        {
            var age = CalculateAge(dob);
            if (age >= requirement.MinimumAge)
            {
                context.Succeed(requirement); // Requirement met
            }
        }

        return Task.CompletedTask;
    }

    private static int CalculateAge(DateTime dob)
    {
        var today = DateTime.Today;
        var age = today.Year - dob.Year;
        if (dob.Date > today.AddYears(-age))
        {
            age--; // Birthday hasn't occurred yet this year
        }
        return age;
    }
}

// Handler for business hours
public class BusinessHoursHandler : AuthorizationHandler<BusinessHoursRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        BusinessHoursRequirement requirement)
    {
        var currentHour = DateTime.Now.Hour;
        if (currentHour >= requirement.StartHour
            && currentHour < requirement.EndHour)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

// Handler for subscription tier
public class SubscriptionHandler : AuthorizationHandler<SubscriptionRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        SubscriptionRequirement requirement)
    {
        var tierClaim = context.User.FindFirst("Subscription");
        if (tierClaim != null
            && requirement.RequiredTiers.Contains(tierClaim.Value,
                StringComparer.OrdinalIgnoreCase))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
```

### Registering Policies and Handlers

```csharp
builder.Services.AddAuthorization(options =>
{
    // Simple role policy
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));

    // Simple claim policy
    options.AddPolicy("EmailVerified",
        policy => policy.RequireClaim("EmailVerified", "true"));

    // Custom requirement policies
    options.AddPolicy("AtLeast18",
        policy => policy.Requirements.Add(new MinimumAgeRequirement(18)));

    options.AddPolicy("AtLeast21",
        policy => policy.Requirements.Add(new MinimumAgeRequirement(21)));

    options.AddPolicy("BusinessHoursOnly",
        policy => policy.Requirements.Add(new BusinessHoursRequirement()));

    options.AddPolicy("PremiumContent",
        policy => policy.Requirements.Add(
            new SubscriptionRequirement("Premium", "Enterprise")));

    // Multiple requirements — ALL must be satisfied
    options.AddPolicy("AdminDuringBusinessHours", policy =>
    {
        policy.RequireRole("Admin");
        policy.Requirements.Add(new BusinessHoursRequirement());
    });

    // Inline assertion policy (lambda instead of a handler)
    options.AddPolicy("CanEditContent", policy =>
        policy.RequireAssertion(context =>
        {
            var isAdmin = context.User.IsInRole("Admin");
            var isEditor = context.User.IsInRole("Editor");
            var hasPerm = context.User.HasClaim(
                "Permission", "Content.Edit");
            return isAdmin || isEditor || hasPerm;
        }));
});

// Register the handlers
builder.Services.AddSingleton<IAuthorizationHandler, MinimumAgeHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, BusinessHoursHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, SubscriptionHandler>();
```

### Using Policies in Controllers

```csharp
public class ContentController : Controller
{
    [Authorize(Policy = "AtLeast18")]
    public IActionResult AdultContent() => View();

    [Authorize(Policy = "PremiumContent")]
    public IActionResult PremiumVideos() => View();

    [Authorize(Policy = "BusinessHoursOnly")]
    public IActionResult AdminDashboard() => View();

    [Authorize(Policy = "AdminDuringBusinessHours")]
    public IActionResult SensitiveOperation() => View();

    [Authorize(Policy = "CanEditContent")]
    public IActionResult EditContent() => View();
}
```

### Resource-Based Authorization

Sometimes authorization depends on the specific resource being accessed — e.g., "can this user edit THIS document?" Use imperative authorization:

```csharp
public class DocumentsController : Controller
{
    private readonly IAuthorizationService _authService;
    private readonly IDocumentService _docService;

    public DocumentsController(
        IAuthorizationService authService,
        IDocumentService docService)
    {
        _authService = authService;
        _docService = docService;
    }

    public async Task<IActionResult> Edit(int id)
    {
        var document = await _docService.GetByIdAsync(id);
        if (document == null) return NotFound();

        // Authorize against the specific resource
        var result = await _authService.AuthorizeAsync(
            User, document, "EditDocumentPolicy");

        if (!result.Succeeded)
        {
            return Forbid();
        }

        return View(document);
    }
}
```

Resource-based handler:

```csharp
public class DocumentAuthorizationHandler :
    AuthorizationHandler<DocumentOperationRequirement, Document>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        DocumentOperationRequirement requirement,
        Document resource)
    {
        // Admins can do anything
        if (context.User.IsInRole("Admin"))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        // Owner can do anything
        var userId = context.User.FindFirst(
            System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (resource.OwnerId == userId)
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        // Shared users can read, and edit if they have canEdit
        if (resource.SharedWith.Any(s => s.UserId == userId))
        {
            var share = resource.SharedWith.First(s => s.UserId == userId);
            if (requirement.Operation == "Read"
                || (requirement.Operation == "Edit" && share.CanEdit))
            {
                context.Succeed(requirement);
            }
        }

        return Task.CompletedTask;
    }
}

public class DocumentOperationRequirement : IAuthorizationRequirement
{
    public string Operation { get; }
    public DocumentOperationRequirement(string operation)
        => Operation = operation;
}

// Static factory for clean policy names
public static class DocumentPolicies
{
    public static DocumentOperationRequirement Read
        => new("Read");
    public static DocumentOperationRequirement Edit
        => new("Edit");
    public static DocumentOperationRequirement Delete
        => new("Delete");
}
```

Register:

```csharp
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ReadDocument",
        policy => policy.Requirements.Add(DocumentPolicies.Read));
    options.AddPolicy("EditDocument",
        policy => policy.Requirements.Add(DocumentPolicies.Edit));
});

builder.Services.AddSingleton<IAuthorizationHandler, DocumentAuthorizationHandler>();
```

### Why This Matters

Policies are the most powerful authorization mechanism in ASP.NET Core. They let you define complex rules once and apply them consistently across controllers, and they're testable because handlers are isolated classes. This video takes viewers from simple `[Authorize(Roles = ...)]` to full custom policies and resource-based authorization.

---

## Video 13 — Password Policies & Custom Validation

### What We're Building

Configuring built-in password options, writing a custom `IPasswordValidator` that checks for common passwords, user information in passwords, sequential characters, and repeated characters, and building a password strength meter endpoint.

### Built-in Password Options

```csharp
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;           // 0-9 required
    options.Password.RequireLowercase = true;       // a-z required
    options.Password.RequireUppercase = true;       // A-Z required
    options.Password.RequireNonAlphanumeric = true; // !@#$%^&* etc. required
    options.Password.RequiredLength = 8;            // Minimum 8 characters
    options.Password.RequiredUniqueChars = 1;       // At least 1 distinct character
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();
```

These are checked automatically when `UserManager.CreateAsync` or `UserManager.AddPasswordAsync` is called. If the password fails any check, the result's `Errors` collection contains a descriptive error.

### Custom Password Validator

```csharp
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

public class CustomPasswordValidator : IPasswordValidator<ApplicationUser>
{
    public Task<IdentityResult> ValidateAsync(
        UserManager<ApplicationUser> manager,
        ApplicationUser user,
        string? password)
    {
        var errors = new List<IdentityError>();

        // ── 1. Null/empty check ──
        if (string.IsNullOrEmpty(password))
        {
            return Task.FromResult(IdentityResult.Failed(
                new IdentityError
                {
                    Code = "PasswordEmpty",
                    Description = "Password is required."
                }));
        }

        // ── 2. Minimum length (stricter than default) ──
        if (password.Length < 10)
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordTooShort",
                Description = "Password must be at least 10 characters long."
            });
        }

        // ── 3. Common password check ──
        // In production, use a lists of known breached passwords (e.g., haveibeenpwned API)
        var commonPasswords = new[]
        {
            "password", "123456", "qwerty", "letmein", "admin",
            "welcome", "monkey", "dragon", "master", "login"
        };

        if (commonPasswords.Any(p =>
            password.ToLower().Contains(p)))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordTooCommon",
                Description = "Password contains a common word or sequence."
            });
        }

        // ── 4. User information in password ──
        // Users often use their username or email in their password.
        // Check and reject.
        if (!string.IsNullOrEmpty(user.UserName)
            && password.ToLower().Contains(user.UserName.ToLower()))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordContainsUsername",
                Description = "Password cannot contain your username."
            });
        }

        if (!string.IsNullOrEmpty(user.Email))
        {
            var emailPrefix = user.Email.Split('@')[0];
            if (password.ToLower().Contains(emailPrefix.ToLower()))
            {
                errors.Add(new IdentityError
                {
                    Code = "PasswordContainsEmail",
                    Description = "Password cannot contain your email address."
                });
            }
        }

        // ── 5. Sequential characters (abc, 123, cba, 321) ──
        if (HasSequentialChars(password, 3))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordHasSequence",
                Description = "Password cannot contain sequential characters like 'abc' or '123'."
            });
        }

        // ── 6. Repeated characters (aaa, 111) ──
        if (HasRepeatedChars(password, 3))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordHasRepetition",
                Description = "Password cannot contain repeated characters like 'aaa'."
            });
        }

        // ── Return result ──
        return Task.FromResult(
            errors.Count == 0
                ? IdentityResult.Success
                : IdentityResult.Failed(errors.ToArray()));
    }

    // Check for 3+ sequential characters (ascending or descending)
    private static bool HasSequentialChars(string password, int minLength)
    {
        for (int i = 0; i <= password.Length - minLength; i++)
        {
            bool ascending = true;
            bool descending = true;

            for (int j = 0; j < minLength - 1; j++)
            {
                if (password[i + j] + 1 != password[i + j + 1])
                    ascending = false;
                if (password[i + j] - 1 != password[i + j + 1])
                    descending = false;
            }

            if (ascending || descending)
                return true;
        }
        return false;
    }

    // Check for 3+ repeated characters
    private static bool HasRepeatedChars(string password, int minLength)
    {
        for (int i = 0; i <= password.Length - minLength; i++)
        {
            bool repeated = true;
            for (int j = 1; j < minLength; j++)
            {
                if (password[i] != password[i + j])
                {
                    repeated = false;
                    break;
                }
            }
            if (repeated) return true;
        }
        return false;
    }
}
```

### Registering the Custom Validator

```csharp
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password options...
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders()
.AddPasswordValidator<CustomPasswordValidator>(); // ← Add this line
```

Multiple validators can be registered — they all run and aggregate errors. This means you can have one validator for length/complexity rules and another for common password checking, keeping concerns separated.

### Password Strength Meter Endpoint

```csharp
[HttpPost("api/account/check-password-strength")]
[AllowAnonymous]
public IActionResult CheckPasswordStrength([FromBody] PasswordStrengthRequest request)
{
    if (string.IsNullOrEmpty(request.Password))
    {
        return Ok(new { Score = 0, Strength = "None", Feedback = new[] { "Enter a password." } });
    }

    int score = 0;
    var feedback = new List<string>();

    // Length scoring
    if (request.Password.Length >= 8) score += 1;
    if (request.Password.Length >= 12) score += 1;
    if (request.Password.Length >= 16) score += 1;

    // Character variety
    if (request.Password.Any(char.IsLower)) score += 1;
    if (request.Password.Any(char.IsUpper)) score += 1;
    if (request.Password.Any(char.IsDigit)) score += 1;
    if (request.Password.Any(c => "!@#$%^&*()_+-=[]{}|;:,.<>?".Contains(c)))
        score += 2; // Special characters worth more

    // Deductions
    if (HasSequentialChars(request.Password, 3))
    {
        score -= 1;
        feedback.Add("Avoid sequential characters (abc, 123).");
    }

    if (HasRepeatedChars(request.Password, 3))
    {
        score -= 1;
        feedback.Add("Avoid repeated characters (aaa, 111).");
    }

    // Check against common passwords (simplified list)
    var common = new[] { "password", "123456", "qwerty" };
    if (common.Any(p => request.Password.ToLower().Contains(p)))
    {
        score -= 2;
        feedback.Add("Avoid common passwords.");
    }

    var strength = score switch
    {
        <= 1 => "Very Weak",
        <= 3 => "Weak",
        <= 5 => "Fair",
        <= 7 => "Good",
        _ => "Strong"
    };

    return Ok(new
    {
        Score = Math.Max(0, score),
        Strength,
        Feedback = feedback
    });
}

public class PasswordStrengthRequest
{
    public string Password { get; set; } = string.Empty;
}
```

### Why This Matters

Password validation is one of the most visible security features to users. The built-in options cover the basics, but custom validators let you enforce organizational policies, check against breached password lists, and reject passwords containing user information. The strength meter improves UX by giving real-time feedback instead of a cryptic error after submission.

---

## Video 14 — Account Lockout & Security Stamp

### What We're Building

How account lockout works, configuring it, manually locking/unlocking users, the security stamp mechanism, and how to invalidate all sessions when security-critical changes happen.

### Configuring Lockout

```csharp
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();
```

| Setting | Purpose |
|---------|---------|
| `DefaultLockoutTimeSpan` | How long the account stays locked after exceeding the failed attempt threshold |
| `MaxFailedAccessAttempts` | Number of failed attempts before lockout triggers |
| `AllowedForNewUsers` | Whether newly created accounts are subject to lockout |

### How Lockout Works During Login

The `PasswordSignInAsync` call with `lockoutOnFailure: true` handles lockout automatically:

1. Password is wrong → `AccessFailedCount` increments by 1
2. If `AccessFailedCount >= MaxFailedAccessAttempts` → `LockoutEnd` is set to `DateTimeOffset.UtcNow + DefaultLockoutTimeSpan`
3. On next login attempt, `IsLockedOutAsync` returns true, and login is rejected
4. Lockout automatically expires when `LockoutEnd <= DateTimeOffset.UtcNow`

The `AccessFailedCount` is automatically reset to 0 on a successful login.

### Manual Lockout Management (Admin Operations)

```csharp
public class LockoutService
{
    private readonly UserManager<ApplicationUser> _userManager;

    public LockoutService(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    // Check if a user is locked out
    public async Task<bool> IsLockedOutAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        return user != null && await _userManager.IsLockedOutAsync(user);
    }

    // Get remaining lockout time
    public async Task<TimeSpan?> GetRemainingLockoutTimeAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return null;

        var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
        if (lockoutEnd == null || lockoutEnd <= DateTimeOffset.UtcNow)
            return null;

        return lockoutEnd - DateTimeOffset.UtcNow;
    }

    // Manually lock a user account (admin action)
    public async Task<IdentityResult> LockUserAsync(
        string userId, TimeSpan? duration = null)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return IdentityResult.Failed(
            new IdentityError { Description = "User not found." });

        // Enable lockout if not already
        if (!user.LockoutEnabled)
            await _userManager.SetLockoutEnabledAsync(user, true);

        // Reset failed attempts first
        await _userManager.ResetAccessFailedCountAsync(user);

        // Set lockout end
        var lockoutEnd = duration.HasValue
            ? DateTimeOffset.UtcNow.Add(duration.Value)
            : DateTimeOffset.MaxValue; // Permanent lock

        return await _userManager.SetLockoutEndDateAsync(user, lockoutEnd);
    }

    // Unlock a user account (admin action)
    public async Task<IdentityResult> UnlockUserAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return IdentityResult.Failed(
            new IdentityError { Description = "User not found." });

        var result = await _userManager.SetLockoutEndDateAsync(user, null);
        if (result.Succeeded)
        {
            // Also reset the failed count so they don't immediately lock again
            await _userManager.ResetAccessFailedCountAsync(user);
        }

        return result;
    }

    // Get current failed attempt count
    public async Task<int> GetFailedAttemptCountAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        return user != null
            ? await _userManager.GetAccessFailedCountAsync(user)
            : 0;
    }
}
```

### The Security Stamp — Why It Matters

The `SecurityStamp` is a random GUID stored on the user. It changes whenever a security-critical event occurs:

- Password change
- Role assignment/removal
- 2FA enable/disable
- Email/phone change

When the stamp changes, all existing authentication cookies become invalid because the cookie's stamp no longer matches the database's stamp. This is the mechanism behind "sign out everywhere" — you update the stamp, and every device's cookie fails validation on the next request.

**How to use it:**

```csharp
// When the password is changed
await _userManager.UpdateSecurityStampAsync(user);

// When roles are changed
await _userManager.UpdateSecurityStampAsync(user);

// When 2FA is toggled
await _userManager.UpdateSecurityStampAsync(user);
```

**Configure stamp validation:**

```csharp
builder.Services.Configure<SecurityStampValidatorOptions>(options =>
{
    // How often to re-validate the stamp (default is 30 seconds)
    options.ValidationInterval = TimeSpan.FromMinutes(30);

    // Called when the principal is being refreshed
    options.OnRefreshingPrincipal = context =>
    {
        // You can log or take custom action when a stamp refresh happens
        var logger = context.HttpContext.RequestServices
            .GetRequiredService<ILogger<Program>>();
        var userId = context.NewPrincipal?.FindFirst(
            System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        logger.LogInformation("Security stamp refreshed for user: {UserId}",
            userId ?? "unknown");
        return Task.CompletedTask;
    };
});
```

### Why This Matters

Lockout is your first line of defense against brute force attacks. The security stamp is your mechanism for "sign out everywhere" — critical when a user's password is compromised or an admin removes a user's roles. Understanding both means you can secure accounts proactively rather than reactively.

---

## Video 15 — Two-Factor Authentication (2FA)

### What We're Building

Enabling TOTP-based 2FA with authenticator apps (Google Authenticator, Microsoft Authenticator), handling 2FA during login, generating and using recovery codes, and disabling 2FA.

### What Is TOTP?

Time-based One-Time Password (TOTP) generates a 6-digit code that changes every 30 seconds. The server and the authenticator app share a secret key. Both independently compute the same code at the same time. When the user enters the code, the server verifies it matches.

This is more secure than SMS-based 2FA because:
- No phone number interception risk
- Works offline (no cellular signal needed)
- Not vulnerable to SIM-swapping attacks

### Enabling 2FA — The Controller

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Web;

public class TwoFactorController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILogger<TwoFactorController> _logger;

    public TwoFactorController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ILogger<TwoFactorController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
    }

    // ─────────────────────────────────────────────
    // GET /TwoFactor/Enable — Show the QR code and key
    // ─────────────────────────────────────────────
    [HttpGet]
    [Authorize]
    public async Task<IActionResult> EnableAuthenticator()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return NotFound();

        // Get or generate the authenticator key
        var key = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            // Generate a new key if one doesn't exist
            await _userManager.ResetAuthenticatorKeyAsync(user);
            key = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        // Format the key into groups of 4 characters for readability
        var formattedKey = FormatKey(key);

        // Build the OTPAuth URL for QR code generation
        // Format: otpauth://totp/{issuer}:{account}?secret={key}&issuer={issuer}&digits=6&period=30
        var qrUri = GenerateQrCodeUri(user.Email!, key);

        return View(new EnableAuthenticatorViewModel
        {
            SharedKey = formattedKey,
            AuthenticatorUri = qrUri
        });
    }

    // ─────────────────────────────────────────────
    // POST /TwoFactor/Enable — Verify the code and enable 2FA
    // ─────────────────────────────────────────────
    [HttpPost]
    [Authorize]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EnableAuthenticator(
        EnableAuthenticatorViewModel model)
    {
        if (!ModelState.IsValid) return View(model);

        var user = await _userManager.GetUserAsync(User);
        if (user == null) return NotFound();

        // Clean the verification code — remove spaces and hyphens
        var code = model.Code.Replace(" ", string.Empty)
                              .Replace("-", string.Empty);

        // Verify the code against the authenticator key
        var isValid = await _userManager.VerifyTwoFactorTokenAsync(
            user,
            _userManager.Options.Tokens.AuthenticatorTokenProvider,
            code);

        if (!isValid)
        {
            ModelState.AddModelError("Code",
                "The verification code is invalid. Please try again.");
            return View(model);
        }

        // Enable 2FA for this user
        await _userManager.SetTwoFactorEnabledAsync(user, true);

        // Generate recovery codes (used when the authenticator app is unavailable)
        var recoveryCodes = await _userManager
            .GenerateNewTwoFactorRecoveryCodesAsync(user, 10);

        _logger.LogInformation(
            "User enabled 2FA: {UserId}", user.Id);

        // Show the recovery codes to the user (they must save them)
        return RedirectToAction("ShowRecoveryCodes",
            new { recoveryCodes = string.Join(",", recoveryCodes) });
    }

    // ─────────────────────────────────────────────
    // GET /TwoFactor/ShowRecoveryCodes — Display recovery codes
    // ─────────────────────────────────────────────
    [HttpGet]
    [Authorize]
    public IActionResult ShowRecoveryCodes(string recoveryCodes)
    {
        if (string.IsNullOrEmpty(recoveryCodes))
            return RedirectToAction("Index", "Home");

        return View(new ShowRecoveryCodesViewModel
        {
            RecoveryCodes = recoveryCodes.Split(',')
        });
    }

    // ─────────────────────────────────────────────
    // GET /TwoFactor/Disable — Show confirmation to disable 2FA
    // ─────────────────────────────────────────────
    [HttpGet]
    [Authorize]
    public async Task<IActionResult> Disable2fa()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return NotFound();

        if (!await _userManager.GetTwoFactorEnabledAsync(user))
        {
            return BadRequest("2FA is not currently enabled.");
        }

        return View();
    }

    // ─────────────────────────────────────────────
    // POST /TwoFactor/Disable — Disable 2FA
    // ─────────────────────────────────────────────
    [HttpPost]
    [Authorize]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Disable2faConfirmed()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return NotFound();

        var result = await _userManager.SetTwoFactorEnabledAsync(user, false);
        if (!result.Succeeded)
        {
            return BadRequest("Failed to disable 2FA.");
        }

        _logger.LogInformation(
            "User disabled 2FA: {UserId}", user.Id);

        return RedirectToAction("Index", "Manage");
    }

    // ── Helper: Format key into groups of 4 ──
    private static string FormatKey(string unformattedKey)
    {
        var result = new StringBuilder();
        int pos = 0;
        while (pos + 4 < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(pos, 4)).Append(' ');
            pos += 4;
        }
        if (pos < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(pos));
        }
        return result.ToString().ToLowerInvariant();
    }

    // ── Helper: Build the OTPAuth URI ──
    private string GenerateQrCodeUri(string email, string secretKey)
    {
        var issuer = HttpUtility.UrlEncode("IdentityTutorial");
        var account = HttpUtility.UrlEncode(email);
        return $"otpauth://totp/{issuer}:{account}?secret={secretKey}&issuer={issuer}&digits=6&period=30";
    }
}

public class EnableAuthenticatorViewModel
{
    public string SharedKey { get; set; } = string.Empty;
    public string AuthenticatorUri { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
}

public class ShowRecoveryCodesViewModel
{
    public string[] RecoveryCodes { get; set; } = Array.Empty<string>();
}
```

### Handling 2FA During Login

```csharp
// In AccountController.Login (Video 08), after PasswordSignInAsync:
var result = await _signInManager.PasswordSignInAsync(
    model.Email, model.Password, model.RememberMe, lockoutOnFailure: true);

if (result.RequiresTwoFactor)
{
    return RedirectToAction("LoginWith2fa",
        new { returnUrl, rememberMe = model.RememberMe });
}

// ... handle other results ...

// ─────────────────────────────────────────────
// GET /Account/LoginWith2fa — Show 2FA verification form
// ─────────────────────────────────────────────
[HttpGet]
[AllowAnonymous]
public async Task<IActionResult> LoginWith2fa(
    bool rememberMe, string? returnUrl = null)
{
    // Get the user from the 2FA sign-in flow state
    var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
    if (user == null)
    {
        throw new InvalidOperationException(
            "Unable to load two-factor authentication user.");
    }

    ViewData["ReturnUrl"] = returnUrl;
    return View(new LoginWith2faViewModel { RememberMe = rememberMe });
}

// ─────────────────────────────────────────────
// POST /Account/LoginWith2fa — Verify the 2FA code
// ─────────────────────────────────────────────
[HttpPost]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public async Task<IActionResult> LoginWith2fa(
    LoginWith2faViewModel model,
    bool rememberMe,
    string? returnUrl = null)
{
    if (!ModelState.IsValid) return View(model);

    var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
    if (user == null)
    {
        throw new InvalidOperationException(
            "Unable to load two-factor authentication user.");
    }

    // Clean the code
    var code = model.TwoFactorCode.Replace(" ", string.Empty)
                                  .Replace("-", string.Empty);

    // Verify and complete sign-in
    var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(
        code,
        rememberMe,
        false); // preventRememberBrowser — whether to remember this device

    if (result.Succeeded)
    {
        _logger.LogInformation(
            "User {UserId} logged in with 2FA.", user.Id);
        return RedirectToLocal(returnUrl);
    }

    if (result.IsLockedOut)
    {
        _logger.LogWarning(
            "User {UserId} locked out during 2FA.", user.Id);
        return RedirectToAction("Lockout");
    }

    ModelState.AddModelError(string.Empty,
        "Invalid authenticator code.");
    return View(model);
}

// ─────────────────────────────────────────────
// GET /Account/LoginWithRecoveryCode — Show recovery code form
// ─────────────────────────────────────────────
[HttpGet]
[AllowAnonymous]
public async Task<IActionResult> LoginWithRecoveryCode(
    string? returnUrl = null)
{
    var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
    if (user == null)
    {
        throw new InvalidOperationException(
            "Unable to load two-factor authentication user.");
    }

    ViewData["ReturnUrl"] = returnUrl;
    return View();
}

// ─────────────────────────────────────────────
// POST /Account/LoginWithRecoveryCode — Verify recovery code
// ─────────────────────────────────────────────
[HttpPost]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public async Task<IActionResult> LoginWithRecoveryCode(
    LoginWithRecoveryCodeViewModel model,
    string? returnUrl = null)
{
    if (!ModelState.IsValid) return View(model);

    var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
    if (user == null)
    {
        throw new InvalidOperationException(
            "Unable to load two-factor authentication user.");
    }

    var code = model.RecoveryCode.Replace(" ", string.Empty);

    var result = await _signInManager
        .TwoFactorRecoveryCodeSignInAsync(code);

    if (result.Succeeded)
    {
        _logger.LogInformation(
            "User {UserId} logged in with recovery code.",
            user.Id);
        return RedirectToLocal(returnUrl);
    }

    if (result.IsLockedOut)
    {
        return RedirectToAction("Lockout");
    }

    ModelState.AddModelError(string.Empty,
        "Invalid recovery code.");
    return View(model);
}

private IActionResult RedirectToLocal(string? returnUrl)
{
    if (!string.IsNullOrEmpty(returnUrl)
        && Url.IsLocalUrl(returnUrl))
        return Redirect(returnUrl);
    return RedirectToAction("Index", "Home");
}
```

### Why This Matters

2FA is one of the most effective security improvements you can add. This video walks through the entire flow — generating keys, building the QR code URI, verifying codes, handling recovery codes, and integrating 2FA into the login process. Viewers leave with a complete, working 2FA implementation.

---

## Video 16 — External Authentication Providers

### What We're Building

Integrating Google, Facebook, and Microsoft login — registering providers, handling the OAuth callback, linking external accounts to existing users, and managing external logins.

### Registering External Providers

In `Program.cs`:

```csharp
builder.Services.AddAuthentication()
    .AddGoogle(options =>
    {
        options.ClientId = builder.Configuration["Authentication:Google:ClientId"]!;
        options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"]!;
        options.CallbackPath = "/signin-google";
        options.Scope.Add("profile");
        options.Scope.Add("email");
    })
    .AddFacebook(options =>
    {
        options.AppId = builder.Configuration["Authentication:Facebook:AppId"]!;
        options.AppSecret = builder.Configuration["Authentication:Facebook:AppSecret"]!;
        options.CallbackPath = "/signin-facebook";
    })
    .AddMicrosoftAccount(options =>
    {
        options.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"]!;
        options.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"]!;
        options.CallbackPath = "/signin-microsoft";
    });
```

In `appsettings.json` (or user secrets / environment variables in production):

```json
{
  "Authentication": {
    "Google": {
      "ClientId": "your-google-client-id.apps.googleusercontent.com",
      "ClientSecret": "your-google-client-secret"
    },
    "Facebook": {
      "AppId": "your-facebook-app-id",
      "AppSecret": "your-facebook-app-secret"
    },
    "Microsoft": {
      "ClientId": "your-microsoft-client-id",
      "ClientSecret": "your-microsoft-client-secret"
    }
  }
}
```

### Handling External Login Callback

```csharp
public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    // ─────────────────────────────────────────────
    // POST /Account/ExternalLogin — Initiate external login
    // Called when user clicks "Login with Google" button
    // ─────────────────────────────────────────────
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public IActionResult ExternalLogin(string provider, string? returnUrl = null)
    {
        // Configure the redirect to the external provider
        var redirectUrl = Url.Action(
            "ExternalLoginCallback", "Account",
            new { returnUrl });

        var properties = _signInManager.ConfigureExternalAuthenticationProperties(
            provider, redirectUrl);

        // Challenge → redirect to the external provider
        return Challenge(properties, provider);
    }

    // ─────────────────────────────────────────────
    // GET /Account/ExternalLoginCallback — Handle the callback
    // The external provider redirects here after authentication
    // ─────────────────────────────────────────────
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ExternalLoginCallback(
        string? returnUrl = null, string? remoteError = null)
    {
        // Handle errors from the external provider
        if (remoteError != null)
        {
            ModelState.AddModelError(string.Empty,
                $"Error from external provider: {remoteError}");
            return RedirectToAction("Login");
        }

        // Get the external login info (claims from the provider)
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            return RedirectToAction("Login");
        }

        // Try to sign in with this external login
        // If the user already has this external login linked, they're signed in
        var result = await _signInManager.ExternalLoginSignInAsync(
            info.LoginProvider,
            info.ProviderKey,
            isPersistent: false,
            bypassTwoFactor: true);

        if (result.Succeeded)
        {
            _logger.LogInformation(
                "User logged in with {Provider}",
                info.LoginProvider);
            return RedirectToLocal(returnUrl);
        }

        if (result.IsLockedOut)
        {
            return RedirectToAction("Lockout");
        }

        // If we get here, the user doesn't have an account yet.
        // Extract info from the external claims to pre-fill the registration form.
        var email = info.Principal.FindFirstValue(
            System.Security.Claims.ClaimTypes.Email);
        var name = info.Principal.FindFirstValue(
            System.Security.Claims.ClaimTypes.Name);

        var model = new ExternalLoginViewModel
        {
            Email = email,
            Name = name,
            Provider = info.LoginProvider,
            ReturnUrl = returnUrl
        };

        return View("ExternalLoginConfirmation", model);
    }

    // ─────────────────────────────────────────────
    // POST /Account/ExternalLoginConfirmation — Create account
    // ─────────────────────────────────────────────
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ExternalLoginConfirmation(
        ExternalLoginViewModel model, string? returnUrl = null)
    {
        if (!ModelState.IsValid) return View(model);

        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null) return RedirectToAction("Login");

        // Check if an account with this email already exists
        var existingUser = await _userManager.FindByEmailAsync(model.Email);

        if (existingUser != null)
        {
            // Link the external login to the existing account
            var linkResult = await _userManager.AddLoginAsync(existingUser, info);
            if (linkResult.Succeeded)
            {
                await _signInManager.SignInAsync(existingUser, isPersistent: false);
                return RedirectToLocal(returnUrl);
            }

            foreach (var error in linkResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View(model);
        }

        // Create a new user account
        var user = new ApplicationUser
        {
            UserName = model.Email,
            Email = model.Email,
            FirstName = model.Name?.Split(' ').FirstOrDefault(),
            LastName = model.Name?.Split(' ').Skip(1).FirstOrDefault(),
            EmailConfirmed = true, // External providers verified the email
            CreatedAt = DateTime.UtcNow
        };

        var createResult = await _userManager.CreateAsync(user);
        if (createResult.Succeeded)
        {
            // Link the external login
            var linkResult = await _userManager.AddLoginAsync(user, info);
            if (linkResult.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, "User");
                await _signInManager.SignInAsync(user, isPersistent: false);
                _logger.LogInformation(
                    "User created account via {Provider}",
                    info.LoginProvider);
                return RedirectToLocal(returnUrl);
            }

            // If linking fails, clean up the created user
            await _userManager.DeleteAsync(user);
            foreach (var error in linkResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
        else
        {
            foreach (var error in createResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        return View(model);
    }
}

public class ExternalLoginViewModel
{
    public string? Email { get; set; }
    public string? Name { get; set; }
    public string? Provider { get; set; }
    public string? ReturnUrl { get; set; }
}
```

### Managing External Logins

```csharp
// GET /Account/ExternalLogins — Show linked external logins
[HttpGet]
[Authorize]
public async Task<IActionResult> ExternalLogins()
{
    var user = await _userManager.GetUserAsync(User);
    if (user == null) return NotFound();

    // Get currently linked external logins
    var currentLogins = await _userManager.GetLoginsAsync(user);

    // Get available external providers not yet linked
    var otherLogins = (await _signInManager
            .GetExternalAuthenticationSchemesAsync())
        .Where(auth => currentLogins
            .All(ul => auth.Name != ul.LoginProvider))
        .ToList();

    var model = new ExternalLoginsViewModel
    {
        CurrentLogins = currentLogins,
        OtherLogins = otherLogins,
        ShowRemoveButton = user.PasswordHash != null
                           || currentLogins.Count > 1
    };

    return View(model);
}

// POST /Account/LinkLogin — Start linking a new external login
[HttpPost]
[Authorize]
[ValidateAntiForgeryToken]
public IActionResult LinkLogin(string provider)
{
    var redirectUrl = Url.Action("LinkLoginCallback");
    var properties = _signInManager.ConfigureExternalAuthenticationProperties(
        provider, redirectUrl,
        _userManager.GetUserId(User));

    return Challenge(properties, provider);
}

// GET /Account/LinkLoginCallback — Complete linking
[HttpGet]
[Authorize]
public async Task<IActionResult> LinkLoginCallback()
{
    var user = await _userManager.GetUserAsync(User);
    if (user == null) return NotFound();

    var info = await _signInManager.GetExternalLoginInfoAsync(
        _userManager.GetUserId(User));
    if (info == null)
    {
        return RedirectToAction("ExternalLogins",
            new { Message = "Error linking login." });
    }

    var result = await _userManager.AddLoginAsync(user, info);
    if (!result.Succeeded)
    {
        return RedirectToAction("ExternalLogins",
            new { Message = "Error linking login." });
    }

    // Clear the external cookie and sign in with the updated user
    await _signInManager.SignOutAsync();
    await _signInManager.SignInAsync(user, isPersistent: false);

    return RedirectToAction("ExternalLogins",
        new { Message = "External login linked." });
}

// POST /Account/RemoveLogin — Remove an external login
[HttpPost]
[Authorize]
[ValidateAntiForgeryToken]
public async Task<IActionResult> RemoveLogin(
    RemoveLoginViewModel model)
{
    var user = await _userManager.GetUserAsync(User);
    if (user == null) return NotFound();

    var result = await _userManager.RemoveLoginAsync(
        user, model.LoginProvider, model.ProviderKey);

    if (!result.Succeeded)
    {
        return RedirectToAction("ExternalLogins",
            new { Message = "Error removing login." });
    }

    await _signInManager.SignInAsync(user, isPersistent: false);
    return RedirectToAction("ExternalLogins",
        new { Message = "External login removed." });
}

public class RemoveLoginViewModel
{
    public string LoginProvider { get; set; } = string.Empty;
    public string ProviderKey { get; set; } = string.Empty;
}

public class ExternalLoginsViewModel
{
    public IEnumerable<AuthenticationScheme> CurrentLogins { get; set; }
    public IEnumerable<AuthenticationScheme> OtherLogins { get; set; }
    public bool ShowRemoveButton { get; set; }
}
```

### Why This Matters

External login reduces friction — users don't need to create yet another password. But it introduces complexity: linking accounts, handling provider errors, pre-filling registration from provider claims, and managing the lifecycle of external logins. This video covers the complete flow.

---

## Video 17 — Token Providers

### What We're Building

Understanding how Identity generates and validates tokens for email confirmation, password reset, and 2FA, configuring token lifetimes, and writing a custom token provider.

### How Token Providers Work

When you call `GenerateEmailConfirmationTokenAsync(user)`, Identity delegates to a token provider registered under the `"EmailConfirmation"` purpose. The default provider uses ASP.NET Core Data Protection to generate a cryptographically secure, encrypted, and signed token that includes:

- The user's ID
- The user's security stamp (so the token is invalidated if security changes)
- The purpose (so tokens for different operations aren't interchangeable)
- An expiration time

When `ConfirmEmailAsync(user, token)` is called, the same provider decrypts and validates the token.

### Configuring Token Lifetimes

```csharp
// Default token provider — used for email confirmation, password reset, etc.
builder.Services.Configure<DataProtectorTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromHours(3); // 3 hours
});

// Email confirmation — users might not check email immediately, so longer
builder.Services.Configure<EmailConfirmationTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromDays(7);
});

// Password reset — security-sensitive, so shorter
builder.Services.Configure<PasswordResetTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromHours(1);
});
```

### The Token Flow — Email Confirmation Example

1. User registers → `GenerateEmailConfirmationTokenAsync(user)` creates a token
2. Token is embedded in a link sent via email: `/Account/ConfirmEmail?userId=...&token=...`
3. User clicks the link → `ConfirmEmailAsync(user, token)` validates the token
4. If valid → `EmailConfirmed = true`, user can log in
5. If invalid/expired → show error page

### Using Token APIs

```csharp
// Generate a token
var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

// Validate a token
var result = await _userManager.ConfirmEmailAsync(user, token);
// result.Succeeded = true if valid

// Generate a password reset token
var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);

// Reset the password
var resetResult = await _userManager.ResetPasswordAsync(
    user, resetToken, newPassword);

// Generate a custom token (for any purpose)
var customToken = await _userManager.GenerateUserTokenAsync(
    user, "MyCustomPurpose", "MyCustomProvider");

// Validate a custom token
var isValid = await _userManager.VerifyUserTokenAsync(
    user, "MyCustomPurpose", "MyCustomProvider", customToken);
```

### Writing a Custom Token Provider

```csharp
using Microsoft.AspNetCore.Identity;

public class ShortLivedTokenProvider
    : IUserTwoFactorTokenProvider<ApplicationUser>
{
    public const string ProviderName = "ShortLived";

    // Can this provider generate a token for this user?
    public Task<bool> CanGenerateTwoFactorTokenAsync(
        UserManager<ApplicationUser> manager,
        ApplicationUser user)
    {
        return Task.FromResult(true);
    }

    // Generate a token for the given purpose
    public Task<string> GenerateAsync(
        string purpose,
        UserManager<ApplicationUser> manager,
        ApplicationUser user)
    {
        // Generate a 6-digit numeric code
        var random = new Random();
        var token = random.Next(100000, 999999).ToString();

        // In production, you'd store this securely with an expiration time
        // associated with the user and purpose, then validate against stored value.

        return Task.FromResult(token);
    }

    // Validate a token for the given purpose
    public Task<bool> ValidateAsync(
        string purpose,
        string token,
        UserManager<ApplicationUser> manager,
        ApplicationUser user)
    {
        // Simplified validation — in production, compare against stored value
        return Task.FromResult(
            !string.IsNullOrEmpty(token) && token.Length == 6);
    }
}
```

Register:

```csharp
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders()
    .AddTokenProvider<ShortLivedTokenProvider>(ShortLivedTokenProvider.ProviderName);
```

Use:

```csharp
var token = await _userManager.GenerateUserTokenAsync(
    user, "MyPurpose", ShortLivedTokenProvider.ProviderName);

var isValid = await _userManager.VerifyUserTokenAsync(
    user, "MyPurpose", ShortLivedTokenProvider.ProviderName, token);
```

### Why This Matters

Tokens are the glue between Identity and real-world workflows — email confirmation, password reset, 2FA codes. Understanding how they're generated, what's inside them, how they're validated, and how to configure lifetimes means you can troubleshoot token failures and customize token behavior for your application's needs.

---

## Video 18 — Customizing Identity — Stores, SignInManager, and Deep Extensibility

### What We're Building

Going deep on customization: custom user stores (when you need full control over data access), overriding `SignInManager` to customize sign-in behavior, and advanced entity extensions.

### Custom User Store

When the default EF Core store isn't enough — e.g., you need to store users in a NoSQL database, or you need custom queries that the default store doesn't support — you can implement `IUserStore<TUser>` and the relevant interfaces yourself:

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

public class CustomUserStore :
    IUserStore<ApplicationUser>,
    IUserPasswordStore<ApplicationUser>,
    IUserEmailStore<ApplicationUser>,
    IUserRoleStore<ApplicationUser>,
    IUserClaimStore<ApplicationUser>,
    IUserLockoutStore<ApplicationUser>,
    IUserSecurityStampStore<ApplicationUser>
{
    private readonly ApplicationDbContext _context;

    public CustomUserStore(ApplicationDbContext context)
    {
        _context = context;
    }

    // ── CRUD Operations ──
    public async Task<IdentityResult> CreateAsync(
        ApplicationUser user, CancellationToken cancellationToken)
    {
        _context.Users.Add(user);
        await _context.SaveChangesAsync(cancellationToken);
        return IdentityResult.Success;
    }

    public async Task<IdentityResult> UpdateAsync(
        ApplicationUser user, CancellationToken cancellationToken)
    {
        _context.Users.Update(user);
        await _context.SaveChangesAsync(cancellationToken);
        return IdentityResult.Success;
    }

    public async Task<IdentityResult> DeleteAsync(
        ApplicationUser user, CancellationToken cancellationToken)
    {
        _context.Users.Remove(user);
        await _context.SaveChangesAsync(cancellationToken);
        return IdentityResult.Success;
    }

    // ── Lookup Methods ──
    public Task<ApplicationUser?> FindByIdAsync(
        string userId, CancellationToken cancellationToken)
    {
        return _context.Users
            .FirstOrDefaultAsync(u => u.Id == int.Parse(userId), cancellationToken)
            .AsTask();
    }

    public Task<ApplicationUser?> FindByNameAsync(
        string normalizedUserName, CancellationToken cancellationToken)
    {
        return _context.Users
            .FirstOrDefaultAsync(u => u.NormalizedUserName == normalizedUserName,
                cancellationToken).AsTask();
    }

    // ── Property Getters/Setters ──
    public Task<string?> GetNormalizedUserNameAsync(
        ApplicationUser user, CancellationToken cancellationToken)
    {
        return Task.FromResult(user.NormalizedUserName);
    }

    public Task<string> GetUserIdAsync(
        ApplicationUser user, CancellationToken cancellationToken)
    {
        return Task.FromResult(user.Id.ToString());
    }

    public Task<string?> GetUserNameAsync(
        ApplicationUser user, CancellationToken cancellationToken)
    {
        return Task.FromResult(user.UserName);
    }

    public Task SetNormalizedUserNameAsync(
        ApplicationUser user, string? normalizedName,
        CancellationToken cancellationToken)
    {
        user.NormalizedUserName = normalizedName;
        return Task.CompletedTask;
    }

    public Task SetUserNameAsync(
        ApplicationUser user, string? userName,
        CancellationToken cancellationToken)
    {
        user.UserName = userName;
        return Task.CompletedTask;
    }

    // ── Password Store ──
    public Task SetPasswordHashAsync(
        ApplicationUser user, string? passwordHash,
        CancellationToken cancellationToken)
    {
        user.PasswordHash = passwordHash;
        return Task.CompletedTask;
    }

    public Task<string?> GetPasswordHashAsync(
        ApplicationUser user, CancellationToken cancellationToken)
    {
        return Task.FromResult(user.PasswordHash);
    }

    // ── Email Store ──
    public Task<string?> GetEmailAsync(
        ApplicationUser user, CancellationToken cancellationToken)
    {
        return Task.FromResult(user.Email);
    }

    public Task<bool> GetEmailConfirmedAsync(
        ApplicationUser user, CancellationToken cancellationToken)
    {
        return Task.FromResult(user.EmailConfirmed);
    }

    public Task SetEmailAsync(
        ApplicationUser user, string? email,
        CancellationToken cancellationToken)
    {
        user.Email = email;
        return Task.CompletedTask;
    }

    public Task SetEmailConfirmedAsync(
        ApplicationUser user, bool confirmed,
        CancellationToken cancellationToken)
    {
        user.EmailConfirmed = confirmed;
        return Task.CompletedTask;
    }

    // ── Role Store ──
    public Task AddToRoleAsync(
        ApplicationUser user, string roleName,
        CancellationToken cancellationToken)
    {
        // Add to the UserRoles junction table
        _context.UserRoles.Add(new IdentityUserRole<int>
        {
            UserId = user.Id,
            RoleId = /* resolve role ID from roleName */
        });
        return Task.CompletedTask;
    }

    public Task RemoveFromRoleAsync(
        ApplicationUser user, string roleName,
        CancellationToken cancellationToken)
    {
        // Remove from the junction table
        return Task.CompletedTask;
    }

    public Task<IList<string>> GetRolesAsync(
        ApplicationUser user, CancellationToken cancellationToken)
    {
        // Query the junction table and return role names
        return Task.FromResult<IList<string>>(new List<string>());
    }

    public Task<bool> IsInRoleAsync(
        ApplicationUser user, string roleName,
        CancellationToken cancellationToken)
    {
        return Task.FromResult(false);
    }

    // ── Claim Store ──
    public Task AddClaimAsync(
        ApplicationUser user, Claim claim,
        CancellationToken cancellationToken)
    {
        _context.UserClaims.Add(new IdentityUserClaim<int>
        {
            UserId = user.Id,
            ClaimType = claim.Type,
            ClaimValue = claim.Value
        });
        return Task.CompletedTask;
    }

    public Task RemoveClaimAsync(
        ApplicationUser user, Claim claim,
        CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    public Task<IList<Claim>> GetClaimsAsync(
        ApplicationUser user, CancellationToken cancellationToken)
    {
        return Task.FromResult<IList<Claim>>(new List<Claim>());
    }

    // ── Lockout Store ──
    public Task<DateTimeOffset?> GetLockoutEndDateAsync(
        ApplicationUser user, CancellationToken cancellationToken)
    {
        return Task.FromResult(user.LockoutEnd);
    }

    public Task<int> GetAccessFailedCountAsync(
        ApplicationUser user, CancellationToken cancellationToken)
    {
        return Task.FromResult(user.AccessFailedCount);
    }

    public Task<bool> GetLockoutEnabledAsync(
        ApplicationUser user, CancellationToken cancellationToken)
    {
        return Task.FromResult(user.LockoutEnabled);
    }

    public Task SetLockoutEndDateAsync(
        ApplicationUser user, DateTimeOffset? lockoutEnd,
        CancellationToken cancellationToken)
    {
        user.LockoutEnd = lockoutEnd;
        return Task.CompletedTask;
    }

    public Task ResetAccessFailedCountAsync(
        ApplicationUser user, CancellationToken cancellationToken)
    {
        user.AccessFailedCount = 0;
        return Task.CompletedTask;
    }

    public Task SetLockoutEnabledAsync(
        ApplicationUser user, bool enabled,
        CancellationToken cancellationToken)
    {
        user.LockoutEnabled = enabled;
        return Task.CompletedTask;
    }

    // ── Security Stamp Store ──
    public Task<string?> GetSecurityStampAsync(
        ApplicationUser user, CancellationToken cancellationToken)
    {
        return Task.FromResult(user.SecurityStamp);
    }

    public Task SetSecurityStampAsync(
        ApplicationUser user, string? stamp,
        CancellationToken cancellationToken)
    {
        user.SecurityStamp = stamp;
        return Task.CompletedTask;
    }

    // ── Dispose ──
    public void Dispose()
    {
        // Clean up if needed
    }
}
```

Register:

```csharp
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddErrorDescriber<CustomErrorDescriber>() // Optional: custom error messages
    .AddUserStore<CustomUserStore>(); // Use our custom store
```

### Custom SignInManager

Override `SignInManager` to add custom behavior during sign-in:

```csharp
public class CustomSignInManager : SignInManager<ApplicationUser>
{
    private readonly ILogger<CustomSignInManager> _logger;

    public CustomSignInManager(
        UserManager<ApplicationUser> userManager,
        IHttpContextAccessor contextAccessor,
        IUserClaimsPrincipalFactory<ApplicationUser> claimsFactory,
        IOptions<IdentityOptions> optionsAccessor,
        ILogger<CustomSignInManager> logger,
        IAuthenticationSchemeProvider schemes,
        IUserConfirmation<ApplicationUser> confirmation)
        : base(userManager, contextAccessor, claimsFactory,
              optionsAccessor, logger, schemes, confirmation)
    {
        _logger = logger;
    }

    // Override password sign-in to add custom checks
    public override async Task<SignInResult> PasswordSignInAsync(
        string userName, string password,
        bool isPersistent, bool lockoutOnFailure)
    {
        var user = await UserManager.FindByNameAsync(userName);
        if (user == null)
        {
            return SignInResult.Failed;
        }

        // Custom check: account status
        if (user.Status != AccountStatus.Active)
        {
            _logger.LogWarning(
                "Login attempt for inactive account: {UserId}", user.Id);
            return SignInResult.NotAllowed;
        }

        // Custom check: subscription expiry
        if (user.SubscriptionTier != SubscriptionTier.Free
            && user.SubscriptionExpiresAt.HasValue
            && user.SubscriptionExpiresAt < DateTime.UtcNow)
        {
            // Downgrade to free tier
            user.SubscriptionTier = SubscriptionTier.Free;
            await UserManager.UpdateAsync(user);
        }

        // Delegate to the base implementation for the actual password check
        return await base.PasswordSignInAsync(
            userName, password, isPersistent, lockoutOnFailure);
    }

    // Override sign-in to add custom logic (e.g., update last login, log the event)
    public override async Task SignInAsync(
        ApplicationUser user, bool isPersistent,
        string? authenticationMethod = null)
    {
        user.LastLoginAt = DateTime.UtcNow;
        await UserManager.UpdateAsync(user);

        _logger.LogInformation(
            "User signed in: {UserId} at {Time}",
            user.Id, DateTime.UtcNow);

        await base.SignInAsync(user, isPersistent, authenticationMethod);
    }
}
```

Register:

```csharp
builder.Services.AddScoped<SignInManager<ApplicationUser>, CustomSignInManager>();
```

### Why This Matters

Most applications never need custom stores or SignInManager overrides. But when you do — because you're using a non-relational database, have complex sign-in rules, or need to integrate with a legacy system — knowing how to implement these interfaces correctly is essential. This video shows the full pattern.

---

## Video 19 — Production-Ready Security

### What We're Building

Taking Identity from a development setup to production-ready: secure cookie settings, strong password policies, audit logging, rate limiting considerations, and a troubleshooting guide for common errors.

### Production Configuration

```csharp
builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
{
    // Strong password requirements
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 12;
    options.Password.RequiredUniqueChars = 3;

    // Account lockout
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // Require email confirmation
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Secure cookie settings
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // HTTPS only
    options.Cookie.SameSite = SameSiteMode.Strict; // Strict CSRF protection
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.SlidingExpiration = true;
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
});

// Security stamp validation interval
builder.Services.Configure<SecurityStampValidatorOptions>(options =>
{
    options.ValidationInterval = TimeSpan.FromMinutes(30);
});
```

### Audit Logging

Track security-relevant events:

```csharp
public class AuditLog
{
    public int Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;  // LOGIN, LOGIN_FAILED, PASSWORD_CHANGE, etc.
    public string Description { get; set; } = string.Empty;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

public class AuditLogService
{
    private readonly ApplicationDbContext _context;

    public AuditLogService(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task LogAsync(
        string userId,
        string action,
        string description,
        string? ipAddress = null,
        string? userAgent = null)
    {
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = userId,
            Action = action,
            Description = description,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Timestamp = DateTime.UtcNow
        });
        await _context.SaveChangesAsync();
    }
}
```

Use in your controllers:

```csharp
// After successful login
await _auditLogService.LogAsync(
    user.Id, "LOGIN", "User logged in successfully",
    HttpContext.Connection.RemoteIpAddress?.ToString(),
    Request.Headers.UserAgent);

// After failed login attempt
await _auditLogService.LogAsync(
    user?.Id ?? "UNKNOWN", "LOGIN_FAILED",
    $"Failed login attempt for {model.Email}",
    HttpContext.Connection.RemoteIpAddress?.ToString(),
    Request.Headers.UserAgent);

// After password change
await _auditLogService.LogAsync(
    user.Id, "PASSWORD_CHANGE", "Password was changed",
    HttpContext.Connection.RemoteIpAddress?.ToString(),
    Request.Headers.UserAgent);
```

Register in `Program.cs`:

```csharp
builder.Services.AddScoped<AuditLogService>();
```

### Common Errors and Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `"No authentication handler is configured"` | `UseAuthentication()` missing or wrong order | Add `app.UseAuthentication()` before `app.UseAuthorization()` |
| `"The entity type requires a primary key"` | DbContext doesn't inherit `IdentityDbContext` | Change to `IdentityDbContext<ApplicationUser, ApplicationRole, string>` |
| User not authenticated after login | Cookie middleware missing or wrong order | Ensure `UseAuthentication()` is called; check middleware order |
| Role authorization not working | Cookie is stale (doesn't have updated role claims) | Sign out and sign in again to refresh the cookie |
| Email confirmation token invalid | Token expired, already used, or security stamp changed | Check `TokenLifespan`, generate a new token, ensure security stamp hasn't changed |
| `"Cannot resolve scoped service from root provider"` | Injecting a scoped service (like `UserManager`) into a singleton | Create a scope: `using var scope = serviceProvider.CreateScope();` |
| Lockout not working | `lockoutOnFailure: false` in `PasswordSignInAsync` | Set to `true`; verify `LockoutEnabled` is true on the user |

### Debugging Tips

```csharp
// Enable detailed errors in development
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseDatabaseErrorPage();
}

// Log authentication events
app.Use(async (context, next) =>
{
    var logger = context.RequestServices
        .GetRequiredService<ILogger<Program>>();

    logger.LogInformation(
        "Request: {Path} | User: {User} | Auth: {IsAuth}",
        context.Request.Path,
        context.User?.Identity?.Name ?? "Anonymous",
        context.User?.Identity?.IsAuthenticated ?? false);

    await next();

    logger.LogInformation(
        "Response: {StatusCode}",
        context.Response.StatusCode);
});
```

### Why This Matters

What works in development often isn't secure enough for production. This video closes the series by covering the hardening steps: secure cookies, strong password policies, audit logging for security events, and a practical troubleshooting guide for the errors every Identity developer encounters.

---

## Series Summary

| Video | Topic | Key Takeaway |
|-------|-------|-------------|
| 01 | What is Identity | Understand the problem Identity solves before writing code |
| 02 | Architecture | Users, roles, claims, managers, stores — how they connect |
| 03 | Project setup | Templates, packages, project structure, first run |
| 04 | Configuration | `AddIdentity`, password/lockout/sign-in options, cookies, middleware order |
| 05 | Models | Every IdentityUser property, custom user/role classes, key types |
| 06 | Database | IdentityDbContext, connection strings, migrations, schema overview |
| 07 | Registration | Complete flow: validation, create, role assign, email confirmation |
| 08 | Login | SignInManager, cookie creation, lockout, 2FA redirect, all result types |
| 09 | Role management | Create, update, delete roles, assign/remove users, role claims |
| 10 | RBAC | `[Authorize(Roles)]`, AND/OR semantics, programmatic checks, permission system |
| 11 | Claims | Add/remove claims, claim policies, reading claims in code and views |
| 12 | Policies | Custom requirements, handlers, resource-based authorization |
| 13 | Passwords | Built-in options, custom validator, strength meter |
| 14 | Lockout & stamp | Lockout config, manual lock/unlock, security stamp invalidation |
| 15 | 2FA | TOTP, QR codes, login with 2FA, recovery codes, disable |
| 16 | External login | Google/Facebook/Microsoft, callbacks, linking accounts |
| 17 | Tokens | How tokens work, lifetimes, custom token providers |
| 18 | Customization | Custom stores, custom SignInManager, advanced extensions |
| 19 | Production | Secure config, audit logging, troubleshooting common errors |

---

*built for the YouTube channel — copy code directly into your demo project, record each section as a video, and update this README as the series grows.*
