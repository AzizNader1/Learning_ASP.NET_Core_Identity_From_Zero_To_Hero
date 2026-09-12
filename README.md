# ASP.NET Core Identity in .NET API — From Zero to Hero

> **The single comprehensive resource for mastering ASP.NET Core Identity in a .NET API project.**
> Every section is one YouTube video. All code is API endpoints — testable in Postman or Swagger.
> No MVC, no Razor views, no `View()` calls. Just controllers, JSON, and Postman.

---

## What This Document Is

A complete, step-by-step, line-by-line guide to building authentication and authorization in a **.NET API project** using ASP.NET Core Identity. It covers everything from "what is Identity" to production-ready security, with real code you can copy into your API project and test immediately with Postman or Swagger.

This is organized as a **YouTube playlist of 19 videos**, ordered from zero to mastery. Each video builds on the previous one. The code is all in one API project that grows as the series progresses.

---

## Table of Contents (Playlist Order)

| # | Video Title | What You Build |
|---|-------------|----------------|
| 01 | [What Is ASP.NET Core Identity in an API?](#video-01--what-is-aspnet-core-identity-in-an-api) | The big picture — what Identity solves, API vs MVC, when to use Identity vs JWT-only vs IdentityServer |
| 02 | [Architecture — Users, Roles, Claims, Managers, Stores, Authentication Schemes](#video-02--architecture) | Every major type, how they connect, cookie vs JWT, what `AddIdentity` vs `AddIdentityCore` means for APIs |
| 03 | [Creating the API Project & Installing Packages](#video-03--creating-the-api-project) | `dotnet new webapi`, NuGet packages, project structure, checking what's generated |
| 04 | [Configuring Identity Services for an API](#video-04--configuring-identity-services) | `AddIdentityCore` vs `AddIdentity`, JWT setup, password/lockout options, token providers, `Program.cs` end to end |
| 05 | [The Identity Models — IdentityUser, IdentityRole, Custom Classes](#video-05--the-identity-models) | Every property explained, custom user/role classes, integer vs string keys, what to include in an API |
| 06 | [Database Setup — IdentityDbContext, Connection Strings, Migrations](#video-06--database-setup) | DbContext, connection strings, migrations, the full Identity schema, seeding roles |
| 07 | [User Registration API — Complete Endpoint](#video-07--user-registration-api) | `POST /api/account/register`, ViewModel validation, create user, assign role, return JSON, email confirmation token |
| 08 | [Login API — JWT Token Issuance](#video-08--login-api) | `POST /api/account/login`, validate credentials, check lockout, generate JWT, return token + claims, logout |
| 09 | [Role Management API — CRUD Roles, Assign/Remove Users](#video-09--role-management-api) | `POST/PUT/DELETE /api/roles`, `POST/DELETE /api/users/{id}/roles`, role claims |
| 10 | [RBAC in API — `[Authorize(Roles)]`, Policy Tests, Permission System](#video-10--rbac-in-api) | Role-based endpoint protection, multiple roles, AND vs OR, building a permission system on top of roles |
| 11 | [Claims in API — Add/Remove Claims, Claim Policies, Reading Claims from JWT](#video-11--claims-in-api) | Add/remove claims via API, refresh token to include new claims, claim-based policies, reading claims from the JWT in controllers |
| 12 | [Policy-Based Authorization in API — Custom Requirements & Handlers](#video-12--policy-based-authorization) | `IAuthorizationRequirement`, handlers, register policies, resource-based authorization with JWT |
| 13 | [Password Policies & Custom Validation in API](#video-13--password-policies-custom-validation) | PasswordOptions, custom `IPasswordValidator`, password strength check endpoint |
| 14 | [Account Lockout & Security Stamp in API](#video-14--account-lockout-security-stamp) | Lockout config, lock/unlock endpoints, security stamp, "sign out everywhere" |
| 15 | [Two-Factor Authentication (2FA) API — TOTP, Recovery Codes](#video-15--two-factor-authentication-2fa) | Enable 2FA endpoint, verify TOTP, generate recovery codes, 2FA login flow with JWT, disable 2FA |
| 16 | [External Login Providers in API — Google, Facebook, Microsoft](#video-16--external-login-providers) | Register providers, handle OAuth callback, issue JWT for external users, link/unlink external logins |
| 17 | [Token Providers — Email Confirmation, Password Reset, Custom Providers](#video-17--token-providers) | How tokens work, lifetimes, email confirmation endpoint, password reset endpoint, custom token provider |
| 18 | [Customizing Identity in API — Custom Stores, Custom SignInManager, JWT Customization](#video-18--customizing-identity-in-api) | Custom user store, overriding SignInManager for API, custom JWT claims, custom token handling |
| 19 | [Production-Ready API Security — Best Practices, Audit Logging, Troubleshooting](#video-19--production-ready-api-security) | Production config, secure JWT handling, audit logging endpoints, rate limiting, common API errors and fixes |

---

## How to Use This Document

- **Watch videos in order.** Each video adds to the API project from the previous one.
- **Build along.** Create the API project from Video 03 and add code as you go.
- **Test with Postman or Swagger.** Every endpoint is documented with the HTTP method, URL, request body, and expected response.
- **This is your reference.** Bookmark it. When you need to implement any Identity feature in a .NET API, come back to the relevant video.

---

## Video 01 — What Is ASP.NET Core Identity in an API?

### What We're Building

Nothing yet — concept video. By the end, you understand what problem Identity solves in an API context, how it differs from MVC, and when to choose Identity over other approaches.

### The Problem Identity Solves (API Context)

An API needs to know who is calling it. The options:

1. **Build it yourself** — store users in a table, hash passwords, write login endpoint, issue tokens, handle refresh, lockout, 2FA, email confirmation, password reset, external logins. Every piece is a security surface. Mistakes compound.

2. **Use ASP.NET Core Identity** — Microsoft's membership system. Handles user storage, password hashing (PBKDF2 + HMAC-SHA256), lockout, email confirmation, password reset, 2FA, claims, roles, external logins. You get a battle-tested foundation and focus on your API's business logic.

3. **Use a separate identity provider** — Duende IdentityServer, Auth0, Azure AD B2C. Appropriate when you have multiple apps sharing login, or you need OAuth 2.0/OpenID Connect for third-party access. More infrastructure; more complexity.

**For a single API with its own users logging in with email/password (or social login), Identity is the right choice.** It gives you a user database, authentication, and authorization out of the box, and you can issue JWTs from it for your API clients.

### Identity in an API vs. Identity in MVC

| Concern | MVC / Razor Pages | API |
|---------|-------------------|-----|
| Authentication transport | Authentication cookie (browser stores it, sends automatically) | JWT in `Authorization: Bearer <token>` header (client must send it explicitly) |
| Sign-in | `SignInManager.PasswordSignInAsync()` creates a cookie | Validate credentials, then generate and return a JWT |
| Sign-out | `SignInManager.SignOutAsync()` clears the cookie | Client discards the token; server can blacklist/rotate the token if needed |
| Authorization | `[Authorize]` reads the cookie's ClaimsPrincipal | `[Authorize]` reads the JWT's ClaimsPrincipal (with JWT bearer middleware) |
| Session state | Cookie is stateful on the server side (security stamp validation) | JWT is stateless by default (until revoked); security stamp is harder to enforce without a token blacklist |
| "Remember me" | Cookie `isPersistent` flag | Longer-lived refresh token, or longer JWT expiry (less secure) |

**Key takeaway:** Identity manages users, passwords, roles, claims, and security features the same way regardless of transport. The difference is how the client authenticates each request — cookie (MVC) or JWT (API). This tutorial uses JWT for the API.

### Identity vs. JWT-Only vs. IdentityServer

| Approach | What you get | When to use |
|----------|-------------|-------------|
| **JWT-only (no Identity)** | You write your own user storage, password hashing, token generation. Lightweight but you own all security. | Very simple APIs, or when you already have user infrastructure elsewhere |
| **ASP.NET Core Identity + JWT** | Identity manages users/security; you add JWT issuance on top. Full feature set. | Most APIs that have their own user base and need registration, login, roles, claims, 2FA, etc. |
| **IdentityServer / Duende** | OAuth 2.0 + OpenID Connect server. Multiple apps, SSO, third-party clients. | When you need a central identity provider for multiple applications or external clients |

**This tutorial uses ASP.NET Core Identity + JWT.** Identity manages the user database and security; we add JWT bearer authentication for the API transport.

### Why This Matters

Starting with the right mental model prevents misdesign. If you treat Identity like a cookie-only system and try to use `SignInManager` for API sign-in, you'll fight the framework. If you treat JWT as a replacement for Identity, you'll rebuild features Identity already provides. Understanding both layers — Identity for user management, JWT for API transport — lets you use each correctly.

---

## Video 02 — Architecture — Users, Roles, Claims, Managers, Stores, Authentication Schemes

### What We're Building

A mental model of every major Identity type and how they connect, plus the API-specific authentication flow: credentials → Identity validates → JWT issued → client sends JWT → JWT bearer middleware validates → `[Authorize]` checks claims/roles/policies.

### The Core Types (API Context)

**`IdentityUser`** — the user entity stored in the database:

| Property | Purpose |
|----------|---------|
| `Id` | Primary key — GUID string by default |
| `UserName` | Login identifier |
| `NormalizedUserName` | Uppercase — case-insensitive lookup |
| `Email` / `NormalizedEmail` | Email for login/recovery, normalized for lookup |
| `EmailConfirmed` | Has the user confirmed their email? |
| `PasswordHash` | Hashed password (PBKDF2 + HMAC-SHA256) — never plain text |
| `SecurityStamp` | Random value that changes on security events; invalidates tokens/cookies |
| `ConcurrencyStamp` | Optimistic concurrency |
| `PhoneNumber` / `PhoneNumberConfirmed` | For SMS 2FA |
| `TwoFactorEnabled` | Is 2FA turned on? |
| `LockoutEnd` | When lockout expires (`null` = not locked) |
| `LockoutEnabled` | Can this user be locked out? |
| `AccessFailedCount` | Failed login attempts since last success/reset |

**`IdentityRole`** — a role entity: `Id`, `Name`, `NormalizedName`, `ConcurrencyStamp`. Assigned to users; users inherit role permissions.

**`UserManager<TUser>`** — business logic layer. Used for:
- `CreateAsync(user, password)` — create user, hash password, save
- `FindByEmailAsync` / `FindByIdAsync` / `FindByNameAsync` — lookup
- `CheckPasswordAsync(user, password)` — verify password (returns `PasswordVerificationResult`)
- `AddToRoleAsync(user, roleName)` / `RemoveFromRoleAsync` / `GetRolesAsync` / `IsInRoleAsync`
- `AddClaimAsync` / `RemoveClaimAsync` / `GetClaimsAsync`
- `GenerateEmailConfirmationTokenAsync` / `ConfirmEmailAsync`
- `GeneratePasswordResetTokenAsync` / `ResetPasswordAsync`
- `GenerateAuthenticatorKeyAsync` / `VerifyTwoFactorTokenAsync` / `SetTwoFactorEnabledAsync`
- `IsLockedOutAsync` / `SetLockoutEndDateAsync` / `ResetAccessFailedCountAsync`
- `UpdateSecurityStampAsync` — invalidate all tokens for this user

**`SignInManager<TUser>`** — sign-in orchestration. In an API, you use it less directly because you're issuing JWTs, not cookies. But it's still useful for:
- `CheckPasswordSignInAsync(user, password, lockoutOnFailure)` — validates password, checks lockout, returns `SignInResult` (does NOT create a cookie)
- `PasswordSignInAsync` — same but creates a cookie (not what we want in API)
- `GetTwoFactorAuthenticationUserAsync()` — retrieves user mid-2FA flow
- `TwoFactorAuthenticatorSignInAsync` / `TwoFactorRecoveryCodeSignInAsync` — completes 2FA (creates cookie; in API, we verify and then issue JWT ourselves)

**For API sign-in, prefer `CheckPasswordSignInAsync` + manual JWT generation.** This avoids cookie creation and gives you full control over the JWT.

**`RoleManager<TRole>`** — create/update/delete roles, add/remove role claims, find roles.

**The Store Pattern** — `UserManager` doesn't talk to the database directly. It calls store interfaces: `IUserStore<TUser>`, `IUserPasswordStore<TUser>`, `IUserEmailStore<TUser>`, `IUserRoleStore<TUser>`, `IUserClaimStore<TUser>`, `IUserLockoutStore<TUser>`, `IUserSecurityStampStore<TUser>`. The EF Core package provides `UserStore<TUser, TRole, TContext>` implementing all of these.

This abstraction means you can swap storage without changing business logic. For an API, you almost always use the EF Core store, but knowing the pattern helps when you need custom behavior.

### The API Authentication Flow

```
Client                          API
  │                               │
  │  POST /api/account/login      │
  │  { email, password }         │
  │──────────────────────────────▶│
  │                               │ 1. Find user by email
  │                               │ 2. CheckPasswordSignInAsync
  │                               │    (verify password + lockout check)
  │                               │ 3. If valid: generate JWT
  │                               │    - Subject = user.Id
  │                               │    - Claims = roles + custom claims
  │                               │    - Sign with secret key
  │                               │ 4. Return { token, expiry, user }
  │◀──────────────────────────────│
  │                               │
  │  GET /api/protected           │
  │  Authorization: Bearer <JWT> │
  │──────────────────────────────▶│
  │                               │ 5. JWT bearer middleware validates token
  │                               │ 6. Builds ClaimsPrincipal from JWT claims
  │                               │ 7. [Authorize] checks roles/claims/policies
  │                               │ 8. Returns protected data or 401/403
  │◀──────────────────────────────│
```

### `AddIdentity` vs `AddIdentityCore` (API Decision)

- **`AddIdentity<TUser, TRole>()`** — configures Identity **plus** cookie authentication. Sets up `Identity.Application` scheme as the default. In an API with JWT, you don't want the cookie scheme as default. You can still use this and configure JWT as the default, but it adds cookie services you won't use.

- **`AddIdentityCore<TUser>()`** — configures only Identity's user management services (UserManager, RoleManager, stores, token providers) **without** cookie authentication. This is the right choice for APIs where you handle authentication yourself (JWT). You then add `AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(...)` separately.

**For this tutorial, we use `AddIdentityCore` + JWT.**

### Data Flow: Login Example (API)

1. Client sends `POST /api/account/login` with `{ email, password }`
2. Controller calls `_userManager.FindByEmailAsync(email)` → finds user
3. Controller calls `_signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true)`:
   - Retrieves `PasswordHash` from the store
   - Hashes the provided password with the same salt
   - Compares (constant-time)
   - Checks lockout if `lockoutOnFailure` is true
   - Returns `SignInResult.Succeeded` / `.IsLockedOut` / `.IsNotAllowed` / `.RequiresTwoFactor`
4. If `Succeeded`: generate JWT with user claims, return `{ token, expiry }`
5. Client stores the JWT and sends it in `Authorization: Bearer <token>` on subsequent requests
6. JWT bearer middleware validates the token on each request, builds `ClaimsPrincipal`, makes it available as `User`

### Why This Matters

Understanding the separation between Identity (user management) and the authentication scheme (cookie vs JWT) is the foundation of everything in this tutorial. Getting this right means the rest flows naturally. Getting it wrong means fighting the framework.

---

## Video 03 — Creating the API Project & Installing Packages

### What We're Building

A fresh .NET API project with Identity and EF Core packages installed, ready for configuration in the next video. No generated UI — just the API skeleton.

### Step 1 — Create the API Project

```bash
# Create a .NET 8/9 Web API project (no auth template — we configure manually)
dotnet new webapi -n IdentityApiTutorial --no-https

# Navigate into it
cd IdentityApiTutorial
```

**Why `--no-https`?** For local development it simplifies things. In production you'll use HTTPS. We'll cover production config in Video 19.

**Why not `--auth Individual`?** That template is for MVC/Razor Pages projects and generates UI we don't need. For an API, we configure Identity manually to have full control.

### Step 2 — Install NuGet Packages

```bash
# Core Identity types (UserManager, SignInManager, IdentityUser, IdentityOptions, etc.)
dotnet add package Microsoft.AspNetCore.Identity

# Entity Framework Core integration for Identity (IdentityDbContext, UserStore, etc.)
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore

# SQL Server provider for EF Core
dotnet add package Microsoft.EntityFrameworkCore.SqlServer

# EF Core tools for migrations (dotnet ef commands)
dotnet add package Microsoft.EntityFrameworkCore.Tools

# Design-time package (required for dotnet ef to work in the project)
dotnet add package Microsoft.EntityFrameworkCore.Design

# JWT bearer authentication (for API token transport)
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer

# Optionally: System.IdentityModel.Tokens.Jwt (usually pulled in by JwtBearer, but good to know)
# dotnet add package System.IdentityModel.Tokens.Jwt
```

### Step 3 — Understand the Project Structure

After creation, the project has:

```
IdentityApiTutorial/
├── Controllers/
│   └── WeatherForecastController.cs   # Remove this later — demo controller
├── Program.cs                          # Entry point — configure Identity + JWT here
├── appsettings.json                    # Connection strings, JWT settings
├── IdentityApiTutorial.csproj          # Project file with package references
└── bin/ Debug/ Release/               # Build output
```

We'll add:
- `Models/` — `ApplicationUser`, `ApplicationRole`, ViewModels/Request DTOs
- `Data/` — `ApplicationDbContext`
- `Controllers/` — `AccountController`, `RoleManagementController`, etc.
- `Services/` — optional services (token service, audit log service)

### Step 4 — Verify the Setup

```bash
# Run the project to verify it starts
dotnet run

# In another terminal, check the API responds
curl http://localhost:5000/weatherforecast
```

You should get a JSON response from the default WeatherForecast controller. This confirms the API project is working before we add Identity.

### Step 5 — Prepare for the Next Videos

Delete or ignore `WeatherForecastController.cs`. We'll replace it with our Identity controllers. The project is now ready for configuration.

### Why This Matters

Starting clean — no template-generated UI, no assumptions — means every piece of code in this tutorial is intentional. You'll know exactly what each package does and why it's there.

---

## Video 04 — Configuring Identity Services for an API

### What We're Building

A complete `Program.cs` that configures Identity Core (no cookie), JWT bearer authentication, authorization policies, and the middleware pipeline — all tailored for an API.

### The Complete Program.cs

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using IdentityApiTutorial.Data;
using IdentityApiTutorial.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// ─────────────────────────────────────────────
// 1. Entity Framework Core — Database context
// ─────────────────────────────────────────────
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection")));

// ─────────────────────────────────────────────
// 2. Identity Core — user & role management (NO cookie auth)
// ─────────────────────────────────────────────
builder.Services.AddIdentityCore<ApplicationUser>(options =>
{
    // --- Password settings ---
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 8;
    options.Password.RequiredUniqueChars = 1;

    // --- Lockout settings ---
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // --- User settings ---
    options.User.RequireUniqueEmail = true;

    // --- Sign-in settings ---
    // In an API, RequireConfirmedEmail affects whether we allow login.
    // We'll check this in the login endpoint.
    options.SignIn.RequireConfirmedEmail = false; // Set true in production
})
.AddRoles<ApplicationRole>()                 // Enable role management
.AddEntityFrameworkStores<ApplicationDbContext>()  // EF Core storage
.AddDefaultTokenProviders();                 // Token providers for email confirmation, password reset, 2FA

// ─────────────────────────────────────────────
// 3. JWT Bearer Authentication
// ─────────────────────────────────────────────
var jwtKey = builder.Configuration["Jwt:Key"] ?? "YourSuperSecretKeyThatIsAtLeast32Chars!";
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "IdentityApiTutorial";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "IdentityApiTutorialUsers";

builder.Services.AddAuthentication(options =>
{
    // Set JWT as the default authentication scheme
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
        // Clock skew: allow some leeway for token expiry validation (default 5 min)
        ClockSkew = TimeSpan.Zero // Set to Zero for stricter validation; useful for short-lived tokens
    };

    // Optional: events for logging/token handling
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            var logger = context.HttpContext.RequestServices
                .GetRequiredService<ILogger<Program>>();
            logger.LogWarning("JWT authentication failed: {Error}",
                context.Exception.Message);
            return Task.CompletedTask;
        }
    };
});

// ─────────────────────────────────────────────
// 4. Authorization
// ─────────────────────────────────────────────
builder.Services.AddAuthorization(options =>
{
    // Example: role-based policy
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));

    // Example: claim-based policy
    options.AddPolicy("MustHaveEmailClaim",
        policy => policy.RequireClaim("email"));

    // We'll add more policies in Videos 10-12
});

// ─────────────────────────────────────────────
// 5. Controllers
// ─────────────────────────────────────────────
builder.Services.AddControllers();

// Optional: Swagger for testing
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new()
    {
        Title = "Identity API Tutorial",
        Version = "v1"
    });

    // Add JWT authentication to Swagger
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token.",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
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

var app = builder.Build();

// ─────────────────────────────────────────────
// 6. Middleware Pipeline — ORDER MATTERS
// ─────────────────────────────────────────────
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();   // ← MUST come before Authorization
app.UseAuthorization();    // ← Reads [Authorize] attributes
app.MapControllers();

app.Run();
```

### Line-by-Line Breakdown

**`AddIdentityCore<ApplicationUser>`** — registers UserManager, RoleManager, stores, token providers. No cookie authentication. This is the API-appropriate choice.

**`.AddRoles<ApplicationRole>()`** — enables role management. Without this, `AddToRoleAsync` and role-related methods won't work. Even if you use `IdentityRole` directly (not a custom role class), you still need this line.

**`.AddEntityFrameworkStores<ApplicationDbContext>()`** — wires up all store interfaces to EF Core using your DbContext.

**`.AddDefaultTokenProviders()`** — registers DataProtectorTokenProvider (email confirmation, password reset), AuthenticatorTokenProvider (TOTP), PhoneNumberTokenProvider, EmailTokenProvider.

**JWT Configuration:**

| Setting | Purpose |
|---------|---------|
| `ValidateIssuer` | Verify the token was issued by our API |
| `ValidateAudience` | Verify the token is for our API |
| `ValidateLifetime` | Check token hasn't expired |
| `ValidateIssuerSigningKey` | Verify the token was signed with our key |
| `IssuerSigningKey` | The symmetric key used to sign/validate tokens — keep this secret! |
| `ClockSkew` | Leeway for token expiry. `TimeSpan.Zero` = strict; default = 5 minutes |

**Middleware order:**

```
app.UseAuthentication();   // ← first: reads JWT, builds ClaimsPrincipal
app.UseAuthorization();    // ← second: checks [Authorize], policies, roles
```

Swap these and `[Authorize]` won't work because there's no ClaimsPrincipal yet.

### appsettings.json

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=IdentityApiTutorial;Trusted_Connection=True;MultipleActiveResultSets=true"
  },
  "Jwt": {
    "Key": "YourSuperSecretKeyThatIsAtLeast32CharsLong!",
    "Issuer": "IdentityApiTutorial",
    "Audience": "IdentityApiTutorialUsers"
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

**Important:** Never commit real JWT keys to source control. In production, use environment variables or a secrets manager. The key must be at least 32 characters for a 256-bit key (HS256).

### Why This Matters

This is the configuration everything else depends on. If JWT validation is misconfigured, every protected endpoint returns 401. If Identity Core isn't configured with roles, `AddToRoleAsync` fails. If middleware order is wrong, `[Authorize]` doesn't work. This video gets it all right.

---

## Video 05 — The Identity Models — IdentityUser, IdentityRole, Custom Classes

### What We're Building

Custom user and role classes tailored for an API, with properties that make sense for an API-backed application (not presentation concerns like display names that belong on the frontend).

### ApplicationUser — Custom User Class

```csharp
using Microsoft.AspNetCore.Identity;

namespace IdentityApiTutorial.Models;

// Inherit from IdentityUser to get all standard properties.
// Add only what your API needs — avoid presentation-specific fields.
public class ApplicationUser : IdentityUser
{
    // ── Personal Information (for API responses, admin queries) ──
    public string? FirstName { get; set; }
    public string? LastName { get; set; }

    // Computed property — not stored in DB, derived on read
    // Useful for API responses that need a combined name
    public string? FullName => $"{FirstName} {LastName}".Trim();

    // ── Contact Information ──
    public string? PhoneNumber { get; set; }           // Already in IdentityUser, but we note it
    public bool PhoneNumberConfirmed { get; set; }     // Already in IdentityUser

    // ── Account Metadata (API-relevant) ──
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }         // Updated on each successful login
    public bool IsActive { get; set; } = true;         // Soft-delete / account status

    // ── API-Specific ──
    // For APIs that tier users by subscription or access level
    public string? SubscriptionTier { get; set; } = "Free";
    public DateTime? SubscriptionExpiresAt { get; set; }

    // TwoFactorEnabled, LockoutEnd, LockoutEnabled, AccessFailedCount,
    // EmailConfirmed, SecurityStamp, ConcurrencyStamp, PasswordHash, UserName,
    // NormalizedUserName, NormalizedEmail, Email — all inherited from IdentityUser.
    // We don't need to redeclare them.
}
```

**What we skip (API-appropriate):**
- `ProfilePictureUrl` — frontend concern; store in a profile service or CDN, not Identity
- `Address`, `City`, `Country`, `PostalCode` — only include if your API actually uses them
- `TimeZone`, `Language`, `Theme` — frontend preferences; store in a separate profile endpoint, not in the auth system
- `DisplayName` — frontend can construct from FirstName + LastName; not an auth concern

**What we include:**
- `FirstName`, `LastName` — commonly needed in API responses, admin queries
- `CreatedAt` — audit, analytics
- `LastLoginAt` — security monitoring, "last active" display
- `IsActive` — soft account disable without deleting
- `SubscriptionTier` — if your API gates features by subscription (can also use claims)

### ApplicationRole — Custom Role Class

```csharp
using Microsoft.AspNetCore.Identity;

namespace IdentityApiTutorial.Models;

public class ApplicationRole : IdentityRole
{
    // Description for admin UI / API documentation
    public string? Description { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // System roles (Admin, User) shouldn't be deletable via API
    public bool IsSystemRole { get; set; }

    // Optional: department/team for org-based role hierarchies
    public string? Department { get; set; }
}
```

### Using Integer Keys (Optional — Decide Early)

By default, Identity uses `string` keys (GUIDs). For APIs, string keys are fine and often simpler (no conversion needed in JWTs, URLs, etc.). But if you prefer integers:

```csharp
public class ApplicationUser : IdentityUser<int>
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
}

public class ApplicationRole : IdentityRole<int>
{
    public string? Description { get; set; }
}

// DbContext must match
public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, int>
{
    // ...
}

// Program.cs must match
builder.Services.AddIdentityCore<ApplicationUser>()
    .AddRoles<ApplicationRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();
```

**Tradeoff:** Integer keys are shorter in JWTs and URLs but require conversion when used in claims (JWT claims are strings). String GUID keys are the default for a reason — they're simpler in distributed systems. For this tutorial, we use string keys (the default).

### Why This Matters

Custom user/role classes are where you define what your API knows about users. Include only what you need; avoid mixing presentation concerns into the auth system. Getting this right means your API responses are clean and your database schema is purposeful.

---

## Video 06 — Database Setup — IdentityDbContext, Connection Strings, Migrations

### What We're Building

A complete `ApplicationDbContext`, connection string configuration, and a migration that creates all Identity tables plus seed data for default roles.

### ApplicationDbContext

```csharp
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using IdentityApiTutorial.Models;

namespace IdentityApiTutorial.Data;

// IdentityDbContext<TUser, TRole, TKey> provides:
// - DbSet<TUser>, DbSet<TRole>
// - DbSet<IdentityUserRole<TKey>>, DbSet<IdentityUserClaim<TKey>>,
//   DbSet<IdentityRoleClaim<TKey>>, DbSet<IdentityUserLogin<TKey>>,
//   DbSet<IdentityUserToken<TKey>>
// - Entity configuration: table names, indexes, relationships, keys
public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    // Your application entities go here (products, orders, etc.)
    // They share the same database as Identity.
    // Example:
    // public DbSet<Product> Products { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        // MUST call base first — this configures all Identity entities
        // (table names, column types, indexes, relationships, keys)
        base.OnModelCreating(builder);

        // ── Customize table names (optional) ──
        // Default: AspNetUsers, AspNetRoles, AspNetUserRoles, etc.
        // Many teams prefer shorter names. Pick one convention and stick with it.
        builder.Entity<ApplicationUser>(entity =>
        {
            entity.ToTable(name: "Users");
            entity.Property(e => e.Id).HasMaxLength(36); // GUID string
        });

        builder.Entity<ApplicationRole>(entity =>
        {
            entity.ToTable(name: "Roles");
            entity.Property(e => e.Id).HasMaxLength(36);
        });

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

        // ── Custom user property configuration ──
        builder.Entity<ApplicationUser>(entity =>
        {
            entity.Property(e => e.FirstName).HasMaxLength(100);
            entity.Property(e => e.LastName).HasMaxLength(100);
            entity.Property(e => e.SubscriptionTier).HasMaxLength(50);

            // Ensure email uniqueness (in addition to NormalizedEmail index)
            entity.HasIndex(e => e.Email).IsUnique();
        });

        // ── Seed default roles ──
        SeedRoles(builder);
    }

    private void SeedRoles(ModelBuilder builder)
    {
        var adminRole = new ApplicationRole
        {
            Id = Guid.NewGuid().ToString(),
            Name = "Admin",
            NormalizedName = "ADMIN",
            Description = "Full access to all API endpoints",
            IsSystemRole = true,
            CreatedAt = new DateTime(2024, 1, 1)
        };

        var userRole = new ApplicationRole
        {
            Id = Guid.NewGuid().ToString(),
            Name = "User",
            NormalizedName = "USER",
            Description = "Standard API access",
            IsSystemRole = true,
            CreatedAt = new DateTime(2024, 1, 1)
        };

        // HasData → inserted when migration is applied (if table is empty)
        builder.Entity<ApplicationRole>().HasData(adminRole, userRole);
    }
}
```

### Connection String

In `appsettings.json` (same as Video 04):

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=IdentityApiTutorial;Trusted_Connection=True;MultipleActiveResultSets=true"
  }
}
```

Read in `Program.cs`:

```csharp
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection")));
```

### Migrations

```bash
# Ensure dotnet-ef tool is installed
dotnet tool install --global dotnet-ef

# Create initial migration — scans DbContext, generates CreateTable for all entities
dotnet ef migrations add InitialCreate

# Review the migration file in Migrations/ folder.
# Should include CreateTable for: Users, Roles, UserRoles, UserClaims,
# RoleClaims, UserLogins, UserTokens, plus seed data for Admin and User roles.

# Apply migration — creates the database and tables
dotnet ef database update

# Verify: check the database has the Users, Roles tables with seed data
# (Use SQL Server Object Explorer in VS, or sqlcmd, or Azure Data Studio)

# Later: add a property to ApplicationUser
# dotnet ef migrations add AddFirstNameToUser
# dotnet ef database update

# Rollback (if a migration has an error):
# dotnet ef database update <PreviousMigrationName>

# Remove last unapplied migration:
# dotnet ef migrations remove
```

### The Identity Schema (API Context)

| Table | Purpose | API Relevance |
|-------|---------|---------------|
| `Users` | User accounts + custom properties | `UserManager.FindByEmailAsync`, `UserManager.CreateAsync` read/write here |
| `Roles` | Role definitions | `RoleManager.FindByNameAsync`, seed data lives here |
| `UserRoles` | User ↔ Role many-to-many | `UserManager.AddToRoleAsync`, `UserManager.GetRolesAsync`, `IsInRoleAsync` |
| `UserClaims` | Claims on individual users | `UserManager.AddClaimAsync`, `UserManager.GetClaimsAsync` |
| `RoleClaims` | Claims on roles (inherited by all users in role) | `RoleManager.AddClaimAsync`, `RoleManager.GetClaimsAsync` |
| `UserLogins` | External login providers linked to users | `UserManager.AddLoginAsync`, `UserManager.RemoveLoginAsync`, external login flow |
| `UserTokens` | Tokens (2FA, remember-me, etc.) | Used internally by Identity; you rarely query this directly |

Indexes (created automatically by IdentityDbContext):
- `NormalizedUserName` — fast case-insensitive username lookup
- `NormalizedEmail` — fast case-insensitive email lookup
- `Role.Name` / `Role.NormalizedName` — fast role lookup
- Foreign keys on all junction tables

### Why This Matters

The database is where Identity lives. Understanding the schema lets you write raw queries when needed, debug data issues, and know what EF Core is doing. Seeding roles means your API has Admin and User roles from the first run — no manual setup.

---

## Video 07 — User Registration API — Complete Endpoint

### What We're Building

`POST /api/account/register` — a complete registration endpoint that validates input, checks for existing emails, creates the user, assigns the default "User" role, generates an email confirmation token, and returns a clean JSON response.

### The Request DTO

```csharp
using System.ComponentModel.DataAnnotations;

namespace IdentityApiTutorial.Models;

public class RegisterRequest
{
    [Required(ErrorMessage = "Username is required")]
    [StringLength(50, MinimumLength = 3,
        ErrorMessage = "Username must be 3-50 characters")]
    [RegularExpression(@"^[a-zA-Z0-9_]+$",
        ErrorMessage = "Username can only contain letters, numbers, underscores")]
    public string UserName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email address")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "First name is required")]
    [StringLength(100)]
    public string FirstName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Last name is required")]
    [StringLength(100)]
    public string LastName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [StringLength(100, MinimumLength = 8,
        ErrorMessage = "Password must be at least 8 characters")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Please confirm your password")]
    [Compare("Password", ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; } = string.Empty;
}
```

**Validation attributes:**
- `[Required]` — field must not be null/empty. If invalid, `ModelState.IsValid` is false and the endpoint returns 400 with the error.
- `[StringLength]` — enforces min/max length.
- `[RegularExpression]` — allows only letters, numbers, underscores in usernames. Prevents issues with special characters in URLs or downstream systems.
- `[EmailAddress]` — validates email format.
- `[Compare("Password")]` — ensures `ConfirmPassword` matches `Password`.

### The Account Controller — Register Endpoint

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.Models;

namespace IdentityApiTutorial.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AccountController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        RoleManager<ApplicationRole> roleManager,
        ILogger<AccountController> logger)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _logger = logger;
    }

    /// <summary>
    /// POST /api/account/register
    /// Register a new user.
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        // ── 1. Validate the request ──
        // DataAnnotations on RegisterRequest + [ApiController] auto-validate.
        // [ApiController] automatically returns 400 if ModelState is invalid.
        // But we also check explicitly for clarity and to add custom errors.
        if (!ModelState.IsValid)
        {
            return BadRequest(new
            {
                Message = "Validation failed",
                Errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
            });
        }

        // ── 2. Check if email is already registered ──
        // Case-insensitive lookup (NormalizedEmail is stored uppercase)
        var existingUser = await _userManager.FindByEmailAsync(request.Email);
        if (existingUser != null)
        {
            return BadRequest(new
            {
                Message = "An account with this email already exists"
            });
        }

        // Also check username uniqueness
        var existingUsername = await _userManager.FindByNameAsync(request.UserName);
        if (existingUsername != null)
        {
            return BadRequest(new
            {
                Message = "That username is already taken"
            });
        }

        // ── 3. Create the user object ──
        // Note: we do NOT set PasswordHash — UserManager.CreateAsync does that.
        var user = new ApplicationUser
        {
            UserName = request.UserName,
            Email = request.Email,
            FirstName = request.FirstName,
            LastName = request.LastName,
            CreatedAt = DateTime.UtcNow,
            EmailConfirmed = false,     // Will be true after email confirmation
            IsActive = true
        };

        // ── 4. Create the user in the database ──
        // UserManager.CreateAsync:
        //   1. Validates password against PasswordOptions + custom validators
        //   2. Hashes password with PBKDF2 + HMAC-SHA256
        //   3. Sets NormalizedUserName and NormalizedEmail (uppercase)
        //   4. Generates SecurityStamp and ConcurrencyStamp
        //   5. Saves to database via the user store
        var result = await _userManager.CreateAsync(user, request.Password);

        // ── 5. Handle result ──
        if (result.Succeeded)
        {
            _logger.LogInformation("User registered: {Email}", request.Email);

            // ── 5a. Assign default "User" role ──
            // Creates a row in UserRoles junction table.
            // If the role doesn't exist yet, this will fail — ensure roles are seeded.
            var roleResult = await _userManager.AddToRoleAsync(user, "User");
            if (!roleResult.Succeeded)
            {
                _logger.LogWarning("Failed to assign User role: {Errors}",
                    string.Join(", ", roleResult.Errors.Select(e => e.Description)));

                // Don't fail registration for this — log and continue
                // In production, you might want to fail if role assignment is critical
            }

            // ── 5b. Generate email confirmation token (if email confirmation is enabled) ──
            // The token is time-limited and tied to the user's SecurityStamp.
            // Store it or send it via email — for the API demo, we return it in the response.
            string? confirmationToken = null;

            if (_userManager.Options.SignIn.RequireConfirmedEmail)
            {
                confirmationToken = await _userManager
                    .GenerateEmailConfirmationTokenAsync(user);

                // In production: send confirmationToken via email to user.Email
                // For demo: return it so the caller can hit /api/account/confirm-email
            }

            // ── 5c. Return success response ──
            return CreatedAtAction(
                actionName: nameof(GetUserById),
                controllerName: "Account",
                routeValues: new { id = user.Id },
                new
                {
                    Message = "User registered successfully",
                    UserId = user.Id,
                    Email = user.Email,
                    UserName = user.UserName,
                    EmailConfirmed = user.EmailConfirmed,
                    ConfirmationToken = confirmationToken,  // null if email confirmation not required
                    CreatedAt = user.CreatedAt
                });
        }

        // ── 6. Handle errors ──
        // IdentityResult.Errors contains IdentityError objects with Code and Description.
        // Example errors: "PasswordTooShort", "EmailAlreadyRegistered",
        // "UserNameAlreadyTaken", "PasswordRequiresDigit", etc.
        return BadRequest(new
        {
            Message = "Registration failed",
            Errors = result.Errors.Select(e => e.Description)
        });
    }

    /// <summary>
    /// GET /api/account/users/{id}
    /// Get a user by ID (for CreatedAtAction reference and admin queries).
    /// </summary>
    [HttpGet("users/{id}")]
    public async Task<IActionResult> GetUserById(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        var roles = await _userManager.GetRolesAsync(user);

        return Ok(new
        {
            Id = user.Id,
            UserName = user.UserName,
            Email = user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            FullName = user.FullName,
            EmailConfirmed = user.EmailConfirmed,
            IsActive = user.IsActive,
            CreatedAt = user.CreatedAt,
            Roles = roles
        });
    }
}
```

### Postman / Swagger Test Cases

**Request:**
```
POST /api/account/register
Content-Type: application/json

{
  "userName": "johndoe",
  "email": "john@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "password": "P@ssw0rd123",
  "confirmPassword": "P@ssw0rd123"
}
```

**Success response (201 Created):**
```json
{
  "message": "User registered successfully",
  "userId": "a1b2c3d4-...",
  "email": "john@example.com",
  "userName": "johndoe",
  "emailConfirmed": false,
  "confirmationToken": null,
  "createdAt": "2024-01-15T10:30:00Z"
}
```

**Validation error (400 Bad Request):**
```json
{
  "message": "Validation failed",
  "errors": ["Password must be at least 8 characters"]
}
```

**Duplicate email (400 Bad Request):**
```json
{
  "message": "An account with this email already exists"
}
```

### What Happens Inside `CreateAsync` (Step by Step)

1. **Password validation** — checks `PasswordOptions` (RequireDigit, RequireLowercase, etc.) and any custom `IPasswordValidator` implementations. If any fail, returns `IdentityResult.Failed` with descriptive errors.

2. **Password hashing** — uses `PasswordHasher<ApplicationUser>` which implements PBKDF2 with HMAC-SHA256. The hash includes a random salt. The same password produces a different hash each time (because of the salt), but verification works by extracting the salt from the stored hash and re-hashing.

3. **Normalization** — sets `NormalizedUserName = user.UserName.ToUpperInvariant()` and `NormalizedEmail = user.Email.ToUpperInvariant()`. This enables case-insensitive lookups.

4. **Security stamp** — generates a new random GUID for `SecurityStamp`. This is used later to invalidate tokens/cookies when security changes.

5. **Concurrency stamp** — generates a new random GUID for `ConcurrencyStamp`. Used by EF Core for optimistic concurrency.

6. **Save** — writes the user to the `Users` table via the user store.

7. **Return** — `IdentityResult.Succeeded` if all steps passed, or `IdentityResult.Failed` with errors.

### Why This Matters

Registration is the entry point for every user. A complete registration endpoint handles validation, duplicate checks, password hashing, role assignment, and email confirmation readiness. Each step has a purpose; skipping any creates a gap. This endpoint is the foundation the rest of the API builds on.

---

## Video 08 — Login API — JWT Token Issuance

### What We're Building

`POST /api/account/login` — validates credentials using `CheckPasswordSignInAsync`, checks lockout and email confirmation, generates a JWT with user claims, and returns the token. Plus `POST /api/account/logout` (client-side token discard, with option for server-side revocation).

### The Login Request DTO

```csharp
using System.ComponentModel.DataAnnotations;

namespace IdentityApiTutorial.Models;

public class LoginRequest
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email address")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; } = string.Empty;
}
```

### The Token Response DTO

```csharp
namespace IdentityApiTutorial.Models;

public class TokenResponse
{
    public string Token { get; set; } = string.Empty;
    public string TokenType { get; set; } = "Bearer";
    public int ExpiresIn { get; set; }           // Seconds until expiry
    public DateTime ExpiresAt { get; set; }
    public string? UserId { get; set; }
    public string? UserName { get; set; }
    public string? Email { get; set; }
    public IEnumerable<string>? Roles { get; set; }
}
```

### The Login Endpoint

```csharp
// Continued in AccountController from Video 07

/// <summary>
/// POST /api/account/login
/// Authenticate a user and return a JWT.
/// </summary>
[HttpPost("login")]
public async Task<IActionResult> Login([FromBody] LoginRequest request)
{
    // ── 1. Validate request ──
    if (!ModelState.IsValid)
    {
        return BadRequest(new
        {
            Message = "Invalid request",
            Errors = ModelState.Values
                .SelectMany(v => v.Errors)
                .Select(e => e.ErrorMessage)
        });
    }

    // ── 2. Find user by email (case-insensitive) ──
    var user = await _userManager.FindByEmailAsync(request.Email);

    // ── 3. If user not found, return generic error ──
    // Don't reveal whether the email exists — prevents username enumeration.
    if (user == null)
    {
        return BadRequest(new
        {
            Message = "Invalid email or password"
        });
    }

    // ── 4. Check if account is locked out ──
    if (await _userManager.IsLockedOutAsync(user))
    {
        var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
        var remainingMinutes = (lockoutEnd - DateTimeOffset.UtcNow).Minutes;

        _logger.LogWarning("Locked out login attempt for: {Email}", request.Email);

        return BadRequest(new
        {
            Message = $"Account is locked. Try again in {remainingMinutes} minutes.",
            LockoutEnd = lockoutEnd
        });
    }

    // ── 5. Check if account is active ──
    if (!user.IsActive)
    {
        return BadRequest(new
        {
            Message = "Account is disabled"
        });
    }

    // ── 6. Check if email confirmation is required but not confirmed ──
    if (_userManager.Options.SignIn.RequireConfirmedEmail
        && !user.EmailConfirmed)
    {
        return BadRequest(new
        {
            Message = "Please confirm your email before logging in"
        });
    }

    // ── 7. Verify password ──
    // CheckPasswordSignInAsync:
    //   - Retrieves PasswordHash from the store
    //   - Hashes the provided password with the stored salt
    //   - Compares (constant-time to prevent timing attacks)
    //   - If lockoutOnFailure: increments AccessFailedCount; if threshold reached, sets LockoutEnd
    //   - Returns SignInResult: Succeeded, IsLockedOut, IsNotAllowed, RequiresTwoFactor
    var signInResult = await _signInManager.CheckPasswordSignInAsync(
        user, request.Password, lockoutOnFailure: true);

    // ── 8. Handle sign-in result ──
    if (signInResult.Succeeded)
    {
        _logger.LogInformation("User logged in: {Email}", request.Email);

        // Update last login time
        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        // Reset failed access count on successful login
        await _userManager.ResetAccessFailedCountAsync(user);

        // ── 8a. Check if 2FA is required ──
        if (signInResult.RequiresTwoFactor)
        {
            // Return a special response indicating 2FA is needed.
            // The client then calls /api/account/verify-2fa with the code.
            return Ok(new
            {
                Message = "Two-factor authentication required",
                UserId = user.Id,
                Requires2Fa = true
            });
        }

        // ── 8b. Generate JWT ──
        var token = GenerateJwtToken(user);

        return Ok(token);
    }

    if (signInResult.IsLockedOut)
    {
        // This attempt caused the lockout (or the account was already locked)
        _logger.LogWarning("User locked out: {Email}", request.Email);
        return BadRequest(new
        {
            Message = "Account is locked due to too many failed attempts"
        });
    }

    if (signInResult.IsNotAllowed)
    {
        // Account exists but isn't allowed to sign in
        // (email not confirmed, phone not confirmed, etc.)
        return BadRequest(new
        {
            Message = "Account is not allowed to sign in"
        });
    }

    // ── 9. If we get here, password was wrong ──
    // Return generic error to prevent username enumeration
    return BadRequest(new
    {
        Message = "Invalid email or password"
    });
}
```

### JWT Generation Method

```csharp
// Inside AccountController

private readonly IConfiguration _configuration;

// Add IConfiguration to the constructor:
public AccountController(
    UserManager<ApplicationUser> userManager,
    RoleManager<ApplicationRole> roleManager,
    ILogger<AccountController> logger,
    IConfiguration configuration)
{
    _userManager = userManager;
    _roleManager = roleManager;
    _logger = logger;
    _configuration = configuration;
}

/// <summary>
/// Generate a JWT for the given user.
/// Includes: user ID, username, email, roles, and any custom claims.
/// </summary>
private TokenResponse GenerateJwtToken(ApplicationUser user)
{
    var jwtKey = _configuration["Jwt:Key"] ?? throw new InvalidOperationException("Jwt:Key not configured");
    var jwtIssuer = _configuration["Jwt:Issuer"] ?? throw new InvalidOperationException("Jwt:Issuer not configured");
    var jwtAudience = _configuration["Jwt:Audience"] ?? throw new InvalidOperationException("Jwt:Audience not configured");

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
    var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    // ── 1. Get user roles ──
    var roles = _userManager.GetRolesAsync(user).Result; // Synchronous for simplicity in token generation; in production, use async properly

    // ── 2. Get user claims ──
    var claims = new List<Claim>
    {
        new(JwtRegisteredClaimNames.Sub, user.Id),           // Subject — the user identifier
        new(JwtRegisteredClaimNames.Email, user.Email ?? ""), // Email
        new(JwtRegisteredClaimNames.UniqueName, user.UserName ?? ""), // Username
        new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Unique token ID
        new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64), // Issued at
        // Custom claims
        new("userId", user.Id),
        new("userName", user.UserName ?? ""),
        new("firstName", user.FirstName ?? ""),
        new("lastName", user.LastName ?? ""),
        new("emailConfirmed", user.EmailConfirmed.ToString().ToLowerInvariant()),
        new("isActive", user.IsActive.ToString().ToLowerInvariant()),
        new("subscriptionTier", user.SubscriptionTier ?? "Free"),
        // Role claims — these are what [Authorize(Roles = "...")] checks
        new(ClaimTypes.Role, roles.ToArray()) // Multiple roles as a single claim with array value
    };

    // Also add individual role claims (some systems prefer one claim per role)
    // Uncomment if you prefer individual role claims:
    // foreach (var role in roles)
    // {
    //     claims.Add(new Claim(ClaimTypes.Role, role));
    // }

    // ── 3. Create the token ──
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(claims),
        Expires = DateTime.UtcNow.AddHours(1),  // Token expires in 1 hour
        Issuer = jwtIssuer,
        Audience = jwtAudience,
        SigningCredentials = credentials
    };

    var tokenHandler = new JwtSecurityTokenHandler();
    var securityToken = tokenHandler.CreateToken(tokenDescriptor);
    var jwtToken = tokenHandler.WriteToken(securityToken);

    // ── 4. Build the response ──
    return new TokenResponse
    {
        Token = jwtToken,
        TokenType = "Bearer",
        ExpiresIn = 3600,  // 1 hour in seconds
        ExpiresAt = DateTime.UtcNow.AddHours(1),
        UserId = user.Id,
        UserName = user.UserName,
        Email = user.Email,
        Roles = roles
    };
}
```

### Postman / Swagger Test Cases

**Request:**
```
POST /api/account/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "P@ssw0rd123"
}
```

**Success response (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "tokenType": "Bearer",
  "expiresIn": 3600,
  "expiresAt": "2024-01-15T11:30:00Z",
  "userId": "a1b2c3d4-...",
  "userName": "johndoe",
  "email": "john@example.com",
  "roles": ["User"]
}
```

**Invalid credentials (400 Bad Request):**
```json
{
  "message": "Invalid email or password"
}
```

**Locked out (400 Bad Request):**
```json
{
  "message": "Account is locked. Try again in 5 minutes.",
  "lockoutEnd": "2024-01-15T10:35:00Z"
}
```

### Testing a Protected Endpoint with the JWT

After login, use the token to call a protected endpoint:

```
GET /api/account/me
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

We'll add the `/api/account/me` endpoint in the next section.

### The "/api/account/me" Endpoint — Test JWT Authentication

```csharp
/// <summary>
/// GET /api/account/me
/// Returns the current authenticated user's information.
/// Requires a valid JWT in the Authorization header.
/// </summary>
[HttpGet("me")]
[Authorize]  // Requires authentication — JWT must be valid
public async Task<IActionResult> GetCurrentUser()
{
    // Get the user ID from the JWT claims
    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)
                 ?? User.FindFirstValue("userId");

    if (userId == null)
    {
        return Unauthorized(new { Message = "User identifier not found in token" });
    }

    var user = await _userManager.FindByIdAsync(userId);
    if (user == null)
    {
        return NotFound(new { Message = "User not found" });
    }

    var roles = await _userManager.GetRolesAsync(user);
    var claims = await _userManager.GetClaimsAsync(user);

    return Ok(new
    {
        Id = user.Id,
        UserName = user.UserName,
        Email = user.Email,
        FirstName = user.FirstName,
        LastName = user.LastName,
        FullName = user.FullName,
        EmailConfirmed = user.EmailConfirmed,
        IsActive = user.IsActive,
        TwoFactorEnabled = user.TwoFactorEnabled,
        LockoutEnabled = user.LockoutEnabled,
        SubscriptionTier = user.SubscriptionTier,
        CreatedAt = user.CreatedAt,
        LastLoginAt = user.LastLoginAt,
        Roles = roles,
        Claims = claims.Select(c => new { c.Type, c.Value })
    });
}
```

### Logout Endpoint

```csharp
/// <summary>
/// POST /api/account/logout
/// In a JWT-based API, logout is primarily client-side (discard the token).
/// This endpoint can be used for server-side token revocation if needed.
/// </summary>
[HttpPost("logout")]
[Authorize]
public async Task<IActionResult> Logout()
{
    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)
                 ?? User.FindFirstValue("userId");
    var userName = User.Identity?.Name;

    _logger.LogInformation("User logged out: {UserName} ({UserId})", userName, userId);

    // In a pure JWT API, there's nothing to clear on the server.
    // The client simply discards the token.
    //
    // For server-side revocation, you'd need a token blacklist
    // (e.g., store the JTI in a blacklist with the token's remaining lifetime).
    // See Video 19 for production considerations.

    return Ok(new
    {
        Message = "Logged out successfully. Please discard your token."
    });
}
```

### Why This Matters

Login is the most critical API endpoint. It validates credentials, checks security status (lockout, email confirmation, active account), and issues a JWT that grants access to everything else. Understanding exactly what `CheckPasswordSignInAsync` does and how the JWT is constructed means you can secure and troubleshoot the login flow confidently.

---

## Video 09 — Role Management API — CRUD Roles, Assign/Remove Users

### What We're Building

A complete role management API: create roles, update roles, delete roles (with safety checks), list roles, get role details with users, add/remove claims from roles, and assign/remove roles from users.

### Role Management Controller

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using IdentityApiTutorial.Models;

namespace IdentityApiTutorial.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin")]  // Only admins can manage roles
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

    /// <summary>
    /// GET /api/rolemanagement
    /// List all roles.
    /// </summary>
    [HttpGet]
    public IActionResult GetAllRoles()
    {
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

        return Ok(new
        {
            Message = "Roles retrieved successfully",
            Count = roles.Count,
            Roles = roles
        });
    }

    /// <summary>
    /// GET /api/rolemanagement/{id}
    /// Get a specific role with its users and claims.
    /// </summary>
    [HttpGet("{id}")]
    public async Task<IActionResult> GetRole(string id)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { Message = "Role not found" });
        }

        var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name!);
        var roleClaims = await _roleManager.GetClaimsAsync(role);

        return Ok(new
        {
            Id = role.Id,
            Name = role.Name,
            Description = role.Description,
            IsSystemRole = role.IsSystemRole,
            CreatedAt = role.CreatedAt,
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

    /// <summary>
    /// POST /api/rolemanagement
    /// Create a new role.
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest(new { Message = "Role name is required" });
        }

        // Check if role already exists
        var existing = await _roleManager.FindByNameAsync(request.Name);
        if (existing != null)
        {
            return BadRequest(new { Message = "A role with this name already exists" });
        }

        var role = new ApplicationRole
        {
            Name = request.Name,
            NormalizedName = request.Name.ToUpperInvariant(),
            Description = request.Description,
            IsSystemRole = false,
            CreatedAt = DateTime.UtcNow
        };

        var result = await _roleManager.CreateAsync(role);
        if (!result.Succeeded)
        {
            return BadRequest(new
            {
                Message = "Failed to create role",
                Errors = result.Errors.Select(e => e.Description)
            });
        }

        _logger.LogInformation("Role created: {RoleName}", request.Name);

        return CreatedAtAction(nameof(GetRole), new { id = role.Id }, new
        {
            Message = "Role created successfully",
            Id = role.Id,
            Name = role.Name,
            Description = role.Description
        });
    }

    /// <summary>
    /// PUT /api/rolemanagement/{id}
    /// Update a role's name or description.
    /// </summary>
    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateRole(string id, [FromBody] UpdateRoleRequest request)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { Message = "Role not found" });
        }

        // If renaming, check the new name isn't taken
        if (!string.Equals(role.Name, request.Name, StringComparison.OrdinalIgnoreCase))
        {
            var existing = await _roleManager.FindByNameAsync(request.Name);
            if (existing != null)
            {
                return BadRequest(new { Message = "That role name is already in use" });
            }

            role.Name = request.Name;
            role.NormalizedName = request.Name.ToUpperInvariant();
        }

        role.Description = request.Description;

        var result = await _roleManager.UpdateAsync(role);
        if (!result.Succeeded)
        {
            return BadRequest(new
            {
                Message = "Failed to update role",
                Errors = result.Errors.Select(e => e.Description)
            });
        }

        _logger.LogInformation("Role updated: {RoleName}", role.Name);

        return Ok(new { Message = "Role updated successfully" });
    }

    /// <summary>
    /// DELETE /api/rolemanagement/{id}
    /// Delete a role (with safety checks).
    /// </summary>
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
            return BadRequest(new { Message = "System roles cannot be deleted" });
        }

        // Safety: can't delete a role that has users
        var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name!);
        if (usersInRole.Any())
        {
            return BadRequest(new
            {
                Message = "Remove all users from this role before deleting it",
                UserCount = usersInRole.Count
            });
        }

        var result = await _roleManager.DeleteAsync(role);
        if (!result.Succeeded)
        {
            return BadRequest(new
            {
                Message = "Failed to delete role",
                Errors = result.Errors.Select(e => e.Description)
            });
        }

        _logger.LogInformation("Role deleted: {RoleName}", role.Name);

        return Ok(new { Message = "Role deleted successfully" });
    }

    /// <summary>
    /// POST /api/rolemanagement/{id}/claims
    /// Add a claim to a role (all users in the role inherit the claim).
    /// </summary>
    [HttpPost("{id}/claims")]
    public async Task<IActionResult> AddClaimToRole(string id, [FromBody] AddClaimRequest request)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { Message = "Role not found" });
        }

        // Check if claim already exists on this role
        var existingClaims = await _roleManager.GetClaimsAsync(role);
        if (existingClaims.Any(c =>
            string.Equals(c.Type, request.ClaimType, StringComparison.OrdinalIgnoreCase)
            && string.Equals(c.Value, request.ClaimValue, StringComparison.OrdinalIgnoreCase)))
        {
            return BadRequest(new { Message = "This claim already exists on the role" });
        }

        var claim = new System.Security.Claims.Claim(request.ClaimType, request.ClaimValue);
        var result = await _roleManager.AddClaimAsync(role, claim);

        if (!result.Succeeded)
        {
            return BadRequest(new
            {
                Message = "Failed to add claim to role",
                Errors = result.Errors.Select(e => e.Description)
            });
        }

        _logger.LogInformation("Claim added to role {RoleName}: {ClaimType} = {ClaimValue}",
            role.Name, request.ClaimType, request.ClaimValue);

        return Ok(new { Message = "Claim added to role" });
    }

    /// <summary>
    /// DELETE /api/rolemanagement/{id}/claims
    /// Remove a claim from a role.
    /// </summary>
    [HttpDelete("{id}/claims")]
    public async Task<IActionResult> RemoveClaimFromRole(string id, [FromBody] RemoveClaimRequest request)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { Message = "Role not found" });
        }

        var claim = new System.Security.Claims.Claim(request.ClaimType, request.ClaimValue);
        var result = await _roleManager.RemoveClaimAsync(role, claim);

        if (!result.Succeeded)
        {
            return BadRequest(new
            {
                Message = "Failed to remove claim from role",
                Errors = result.Errors.Select(e => e.Description)
            });
        }

        _logger.LogInformation("Claim removed from role {RoleName}: {ClaimType} = {ClaimValue}",
            role.Name, request.ClaimType, request.ClaimValue);

        return Ok(new { Message = "Claim removed from role" });
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

### User Role Assignment Controller

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using IdentityApiTutorial.Models;

namespace IdentityApiTutorial.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin")]  // Only admins can manage user roles
public class UserRoleManagementController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly ILogger<UserRoleManagementController> _logger;

    public UserRoleManagementController(
        UserManager<ApplicationUser> userManager,
        RoleManager<ApplicationRole> roleManager,
        ILogger<UserRoleManagementController> logger)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _logger = logger;
    }

    /// <summary>
    /// GET /api/userrolemanagement/users/{userId}/roles
    /// Get all roles assigned to a user.
    /// </summary>
    [HttpGet("users/{userId}/roles")]
    public async Task<IActionResult> GetUserRoles(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        var roles = await _userManager.GetRolesAsync(user);

        return Ok(new
        {
            UserId = userId,
            UserName = user.UserName,
            Roles = roles
        });
    }

    /// <summary>
    /// POST /api/userrolemanagement/users/{userId}/roles
    /// Assign a role to a user.
    /// </summary>
    [HttpPost("users/{userId}/roles")]
    public async Task<IActionResult> AssignRoleToUser(string userId, [FromBody] AssignRoleRequest request)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        var role = await _roleManager.FindByIdAsync(request.RoleId);
        if (role == null)
        {
            // Fallback: try to find by name
            role = await _roleManager.FindByNameAsync(request.RoleName);
            if (role == null)
            {
                return NotFound(new { Message = "Role not found" });
            }
        }

        // Check if already assigned
        if (await _userManager.IsInRoleAsync(user, role.Name!))
        {
            return BadRequest(new { Message = "User already has this role" });
        }

        var result = await _userManager.AddToRoleAsync(user, role.Name!);
        if (!result.Succeeded)
        {
            return BadRequest(new
            {
                Message = "Failed to assign role",
                Errors = result.Errors.Select(e => e.Description)
            });
        }

        _logger.LogInformation("Role {RoleName} assigned to user {UserId}",
            role.Name, userId);

        // Note: The JWT for this user won't include the new role until they log in again.
        // To update an existing JWT, you'd need to re-issue it or use a refresh token flow.
        // See Video 11 for refreshing claims.

        return Ok(new
        {
            Message = $"Role '{role.Name}' assigned to user",
            UserId = userId,
            RoleName = role.Name
        });
    }

    /// <summary>
    /// DELETE /api/userrolemanagement/users/{userId}/roles/{roleId}
    /// Remove a role from a user.
    /// </summary>
    [HttpDelete("users/{userId}/roles/{roleId}")]
    public async Task<IActionResult> RemoveRoleFromUser(string userId, string roleId)
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
        if (role.Name == "Admin")
        {
            var admins = await _userManager.GetUsersInRoleAsync("Admin");
            if (admins.Count == 1 && admins[0].Id == userId)
            {
                return BadRequest(new
                {
                    Message = "Cannot remove the last administrator"
                });
            }
        }

        if (!await _userManager.IsInRoleAsync(user, role.Name!))
        {
            return BadRequest(new { Message = "User does not have this role" });
        }

        var result = await _userManager.RemoveFromRoleAsync(user, role.Name!);
        if (!result.Succeeded)
        {
            return BadRequest(new
            {
                Message = "Failed to remove role",
                Errors = result.Errors.Select(e => e.Description)
            });
        }

        _logger.LogInformation("Role {RoleName} removed from user {UserId}",
            role.Name, userId);

        return Ok(new
        {
            Message = $"Role '{role.Name}' removed from user",
            UserId = userId,
            RoleName = role.Name
        });
    }
}

public class AssignRoleRequest
{
    public string? RoleId { get; set; }
    public string? RoleName { get; set; }
}
```

### Why This Matters

Roles are the backbone of authorization in most APIs. This video shows the complete lifecycle: creating roles, updating them, deleting them safely (with checks for system roles and assigned users), managing role claims, and assigning/removing roles from users. Each endpoint has safety checks that prevent destructive operations.

---

## Video 10 — RBAC in API — `[Authorize(Roles)]`, Policy Tests, Permission System

### What We're Building

How to protect API endpoints with role-based authorization, how multiple roles work (OR vs AND), how to check roles in code, and how to build a permission system on top of roles for finer-grained access control.

### Role-Based Endpoint Protection

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.Models;

namespace IdentityApiTutorial.Controllers;

[ApiController]
[Route("api/[controller]")]
public class SampleProtectedController : ControllerBase
{
    /// <summary>
    /// GET /api/sampleprotected/admin-only
    /// Only users in the "Admin" role can access.
    /// </summary>
    [HttpGet("admin-only")]
    [Authorize(Roles = "Admin")]
    public IActionResult AdminOnly()
    {
        return Ok(new
        {
            Message = "This endpoint is restricted to Admins",
            User = User.Identity?.Name,
            Timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// GET /api/sampleprotected/admin-or-manager
    /// Users in EITHER "Admin" OR "Manager" role can access.
    /// Comma = OR semantics.
    /// </summary>
    [HttpGet("admin-or-manager")]
    [Authorize(Roles = "Admin,Manager")]
    public IActionResult AdminOrManager()
    {
        return Ok(new
        {
            Message = "This endpoint is for Admins or Managers",
            User = User.Identity?.Name,
            Timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// GET /api/sampleprotected/authenticated
    /// Any authenticated user (any role) can access.
    /// </summary>
    [HttpGet("authenticated")]
    [Authorize]  // Requires authentication, no specific role
    public IActionResult AuthenticatedOnly()
    {
        return Ok(new
        {
            Message = "This endpoint requires authentication (any role)",
            User = User.Identity?.Name,
            IsAuthenticated = User.Identity?.IsAuthenticated,
            Timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// GET /api/sampleprotected/public
    /// No authentication required.
    /// </summary>
    [HttpGet("public")]
    [AllowAnonymous]
    public IActionResult Public()
    {
        return Ok(new
        {
            Message = "This endpoint is public — no authentication required",
            Timestamp = DateTime.UtcNow
        });
    }
}
```

### AND Semantics — User Must Have ALL Specified Roles

```csharp
// A user must be in BOTH "Admin" AND "Manager" roles.
// Multiple [Authorize] attributes on the same action are ANDed.
[HttpGet("admin-and-manager")]
[Authorize(Roles = "Admin")]
[Authorize(Roles = "Manager")]
public IActionResult AdminAndManager()
{
    return Ok(new
    {
        Message = "This endpoint requires BOTH Admin AND Manager roles",
        User = User.Identity?.Name,
        Timestamp = DateTime.UtcNow
    });
}
```

### Checking Roles Programmatically in API Controllers

```csharp
[HttpGet("check-roles")]
[Authorize]  // Must be authenticated first
public async Task<IActionResult> CheckRoles()
{
    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)
                 ?? User.FindFirstValue("userId");

    if (userId == null)
    {
        return Unauthorized();
    }

    var user = await _userManager.FindByIdAsync(userId);
    if (user == null)
    {
        return NotFound(new { Message = "User not found" });
    }

    // Get all roles from the database (not from the JWT — fresh data)
    var roles = await _userManager.GetRolesAsync(user);

    // Check specific roles
    var isAdmin = await _userManager.IsInRoleAsync(user, "Admin");
    var isManager = await _userManager.IsInRoleAsync(user, "Manager");

    // Also check from the JWT claims (fast, but may be stale if roles changed)
    var rolesFromJwt = User.FindAll(ClaimTypes.Role)
        .Select(c => c.Value)
        .ToList();

    return Ok(new
    {
        UserId = userId,
        UserName = user.UserName,
        RolesFromDatabase = roles,
        RolesFromJwt = rolesFromJwt,
        IsAdmin = isAdmin,
        IsManager = isManager,
        Note = "RolesFromJwt may be stale. Use RolesFromDatabase for authoritative checks."
    });
}
```

**Important:** Roles in the JWT are set at login time. If an admin adds a role to a user after login, the existing JWT doesn't include the new role. For authoritative checks, query the database. For performance, rely on the JWT for routine authorization and re-issue tokens when roles change.

### Building a Permission System on Top of Roles

Roles are coarse — "Admin" or "User." For granular permissions like "Users.Create" or "Reports.Export", build a permission system:

```csharp
// ── Permission entity ──
public class Permission
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;    // e.g., "Users.Create"
    public string Description { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty; // e.g., "Users", "Reports"
}

// ── Role-Permission junction ──
public class RolePermission
{
    public string RoleId { get; set; } = string.Empty;
    public int PermissionId { get; set; }

    public ApplicationRole Role { get; set; } = null!;
    public Permission Permission { get; set; } = null!;
}

// ── Extend ApplicationRole ──
public class ApplicationRole : IdentityRole
{
    public string? Description { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool IsSystemRole { get; set; }
    public string? Department { get; set; }
    public virtual ICollection<RolePermission> RolePermissions { get; set; }
}
```

Add to `ApplicationDbContext`:

```csharp
public DbSet<Permission> Permissions { get; set; }
public DbSet<RolePermission> RolePermissions { get; set; }
```

Seed permissions in `OnModelCreating`:

```csharp
// Seed permissions
var permissions = new[]
{
    new Permission { Id = 1, Name = "Users.View", Description = "View users", Category = "Users" },
    new Permission { Id = 2, Name = "Users.Create", Description = "Create users", Category = "Users" },
    new Permission { Id = 3, Name = "Users.Edit", Description = "Edit users", Category = "Users" },
    new Permission { Id = 4, Name = "Users.Delete", Description = "Delete users", Category = "Users" },
    new Permission { Id = 5, Name = "Reports.View", Description = "View reports", Category = "Reports" },
    new Permission { Id = 6, Name = "Reports.Export", Description = "Export reports", Category = "Reports" }
};

builder.Entity<Permission>().HasData(permissions);

// Seed role-permission mappings (e.g., Admin gets all, User gets view-only)
builder.Entity<RolePermission>().HasData(
    // Admin gets all permissions
    new RolePermission { RoleId = "<AdminRoleId>", PermissionId = 1 },
    new RolePermission { RoleId = "<AdminRoleId>", PermissionId = 2 },
    new RolePermission { RoleId = "<AdminRoleId>", PermissionId = 3 },
    new RolePermission { RoleId = "<AdminRoleId>", PermissionId = 4 },
    new RolePermission { RoleId = "<AdminRoleId>", PermissionId = 5 },
    new RolePermission { RoleId = "<AdminRoleId>", PermissionId = 6 },
    // User gets view-only
    new RolePermission { RoleId = "<UserRoleId>", PermissionId = 1 },
    new RolePermission { RoleId = "<UserRoleId>", PermissionId = 5 }
);
```

**Permission service:**

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace IdentityApiTutorial.Services;

public interface IPermissionService
{
    Task<bool> HasPermissionAsync(string userId, string permissionName);
    Task<IEnumerable<string>> GetUserPermissionsAsync(string userId);
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

        var roles = await _userManager.GetRolesAsync(user);

        return await _context.RolePermissions
            .AnyAsync(rp => roles.Contains(rp.RoleId)
                && rp.Permission.Name == permissionName);
    }

    public async Task<IEnumerable<string>> GetUserPermissionsAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return Enumerable.Empty<string>();

        var roles = await _userManager.GetRolesAsync(user);

        return await _context.RolePermissions
            .Where(rp => roles.Contains(rp.RoleId))
            .Select(rp => rp.Permission.Name)
            .Distinct()
            .ToListAsync();
    }
}
```

**Register in Program.cs:**

```csharp
builder.Services.AddScoped<IPermissionService, PermissionService>();

// Permission-based policies
builder.Services.AddAuthorization(options =>
{
    // One policy per permission
    options.AddPolicy("Users.View", policy =>
        policy.Requirements.Add(new PermissionRequirement("Users.View")));
    options.AddPolicy("Users.Create", policy =>
        policy.Requirements.Add(new PermissionRequirement("Users.Create")));
    options.AddPolicy("Users.Edit", policy =>
        policy.Requirements.Add(new PermissionRequirement("Users.Edit")));
    options.AddPolicy("Users.Delete", policy =>
        policy.Requirements.Add(new PermissionRequirement("Users.Delete")));
    options.AddPolicy("Reports.View", policy =>
        policy.Requirements.Add(new PermissionRequirement("Reports.View")));
    options.AddPolicy("Reports.Export", policy =>
        policy.Requirements.Add(new PermissionRequirement("Reports.Export")));
});

builder.Services.AddSingleton<IAuthorizationHandler, PermissionHandler>();
```

**Permission requirement and handler:**

```csharp
public class PermissionRequirement : IAuthorizationRequirement
{
    public string Permission { get; }
    public PermissionRequirement(string permission) => Permission = permission;
}

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
        var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier)
                     ?? context.User.FindFirstValue("userId");

        if (userId == null) return;

        using var scope = _serviceProvider.CreateScope();
        var permissionService = scope.ServiceProvider.GetRequiredService<IPermissionService>();

        if (await permissionService.HasPermissionAsync(userId, requirement.Permission))
        {
            context.Succeed(requirement);
        }
    }
}
```

**Using permission policies:**

```csharp
[HttpGet("users")]
[Authorize(Policy = "Users.View")]
public async Task<IActionResult> GetUsers()
{
    // Only users with the "Users.View" permission can access
    return Ok(new { Message = "Users list", Timestamp = DateTime.UtcNow });
}

[HttpPost("users")]
[Authorize(Policy = "Users.Create")]
public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
{
    // Only users with the "Users.Create" permission can access
    return Ok(new { Message = "User created", Timestamp = DateTime.UtcNow });
}
```

### Why This Matters

RBAC with `[Authorize(Roles = "...")]` covers most scenarios. But when you need per-endpoint permissions that can be managed independently of roles, a permission system gives you that granularity. This video shows the progression and when to use each approach.

---

## Video 11 — Claims in API — Add/Remove Claims, Claim Policies, Reading Claims from JWT

### What We're Building

How to add and remove claims via API endpoints, how to define claim-based policies, and how to read claims from the JWT in controllers. Plus the critical point about refreshing the JWT after claim changes.

### Adding and Removing Claims — API Endpoints

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using IdentityApiTutorial.Models;

namespace IdentityApiTutorial.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin")]  // Only admins can manage user claims
public class UserClaimsController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<UserClaimsController> _logger;

    public UserClaimsController(
        UserManager<ApplicationUser> userManager,
        ILogger<UserClaimsController> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    /// <summary>
    /// GET /api/userclaims/{userId}
    /// Get all claims for a user.
    /// </summary>
    [HttpGet("{userId}")]
    public async Task<IActionResult> GetUserClaims(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        var claims = await _userManager.GetClaimsAsync(user);

        return Ok(new
        {
            UserId = userId,
            UserName = user.UserName,
            Claims = claims.Select(c => new
            {
                c.Type,
                c.Value
            })
        });
    }

    /// <summary>
    /// POST /api/userclaims/{userId}
    /// Add a claim to a user.
    /// </summary>
    [HttpPost("{userId}")]
    public async Task<IActionResult> AddClaim(string userId, [FromBody] AddClaimRequest request)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        // Check if claim already exists
        var existingClaims = await _userManager.GetClaimsAsync(user);
        if (existingClaims.Any(c =>
            string.Equals(c.Type, request.ClaimType, StringComparison.OrdinalIgnoreCase)
            && string.Equals(c.Value, request.ClaimValue, StringComparison.OrdinalIgnoreCase)))
        {
            return BadRequest(new { Message = "This claim already exists on the user" });
        }

        var claim = new System.Security.Claims.Claim(request.ClaimType, request.ClaimValue);
        var result = await _userManager.AddClaimAsync(user, claim);

        if (!result.Succeeded)
        {
            return BadRequest(new
            {
                Message = "Failed to add claim",
                Errors = result.Errors.Select(e => e.Description)
            });
        }

        _logger.LogInformation("Claim added to user {UserId}: {ClaimType} = {ClaimValue}",
            userId, request.ClaimType, request.ClaimValue);

        return Ok(new
        {
            Message = "Claim added successfully",
            UserId = userId,
            ClaimType = request.ClaimType,
            ClaimValue = request.ClaimValue,
            Note = "The existing JWT for this user does NOT include this new claim. " +
                   "The user must log in again (or a token must be re-issued) to get the new claim."
        });
    }

    /// <summary>
    /// DELETE /api/userclaims/{userId}
    /// Remove a claim from a user.
    /// </summary>
    [HttpDelete("{userId}")]
    public async Task<IActionResult> RemoveClaim(string userId, [FromBody] RemoveClaimRequest request)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        var claim = new System.Security.Claims.Claim(request.ClaimType, request.ClaimValue);
        var result = await _userManager.RemoveClaimAsync(user, claim);

        if (!result.Succeeded)
        {
            return BadRequest(new
            {
                Message = "Failed to remove claim",
                Errors = result.Errors.Select(e => e.Description)
            });
        }

        _logger.LogInformation("Claim removed from user {UserId}: {ClaimType} = {ClaimValue}",
            userId, request.ClaimType, request.ClaimValue);

        return Ok(new
        {
            Message = "Claim removed successfully",
            UserId = userId,
            ClaimType = request.ClaimType,
            ClaimValue = request.ClaimValue,
            Note = "The existing JWT for this user still has this claim until it expires. " +
                   "Consider re-issuing the token or waiting for expiry."
        });
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

### Claim-Based Policies

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

    // Complex policy using RequireAssertion
    options.AddPolicy("CanAccessPremium",
        policy => policy.RequireAssertion(context =>
        {
            var isPremium = context.User.HasClaim(
                c => c.Type == "SubscriptionTier" && c.Value == "Premium");
            var isEnterprise = context.User.HasClaim(
                c => c.Type == "SubscriptionTier" && c.Value == "Enterprise");
            return isPremium || isEnterprise;
        }));
});
```

**Using claim policies:**

```csharp
[HttpGet("finance-data")]
[Authorize(Policy = "DepartmentFinance")]
public IActionResult GetFinanceData()
{
    return Ok(new
    {
        Message = "Finance data — only users with Department=Finance claim",
        Timestamp = DateTime.UtcNow
    });
}

[HttpGet("senior-content")]
[Authorize(Policy = "SeniorStaff")]
public IActionResult GetSeniorContent()
{
    return Ok(new
    {
        Message = "Senior-level content",
        Timestamp = DateTime.UtcNow
    });
}

[HttpGet("premium-content")]
[Authorize(Policy = "CanAccessPremium")]
public IActionResult GetPremiumContent()
{
    return Ok(new
    {
        Message = "Premium content — requires Premium or Enterprise subscription",
        Timestamp = DateTime.UtcNow
    });
}
```

### Reading Claims from the JWT in Controllers

```csharp
[HttpGet("my-claims")]
[Authorize]
public IActionResult GetMyClaims()
{
    // Claims are available through User (ClaimsPrincipal)
    // They come from the JWT that was sent in the Authorization header

    // Get specific claims
    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)
                 ?? User.FindFirstValue("userId");

    var email = User.FindFirstValue(ClaimTypes.Email)
               ?? User.FindFirstValue("email");

    var userName = User.FindFirstValue(ClaimTypes.Name)
                   ?? User.FindFirstValue("userName");

    var firstName = User.FindFirstValue("firstName");
    var lastName = User.FindFirstValue("lastName");
    var subscriptionTier = User.FindFirstValue("subscriptionTier");

    // Check for a claim with specific value
    var isPremium = User.HasClaim(
        c => c.Type == "SubscriptionTier" && c.Value == "Premium");

    // Get all role claims
    var roles = User.FindAll(ClaimTypes.Role)
        .Select(c => c.Value)
        .ToList();

    // Get ALL claims (for debugging or display)
    var allClaims = User.Claims
        .Select(c => new { Type = c.Type, Value = c.Value })
        .ToList();

    return Ok(new
    {
        UserId = userId,
        Email = email,
        UserName = userName,
        FirstName = firstName,
        LastName = lastName,
        FullName = $"{firstName} {lastName}".Trim(),
        SubscriptionTier = subscriptionTier,
        IsPremium = isPremium,
        Roles = roles,
        AllClaims = allClaims
    });
}
```

### Adding Claims During Registration

In the registration endpoint (Video 07), after creating the user:

```csharp
if (result.Succeeded)
{
    // Add default claims
    var defaultClaims = new List<System.Security.Claims.Claim>
    {
        new("Department", "General"),
        new("SubscriptionTier", "Free"),
        new("CreatedAt", DateTime.UtcNow.ToString("O"))
    };

    await _userManager.AddClaimsAsync(user, defaultClaims);

    // Assign default role
    await _userManager.AddToRoleAsync(user, "User");

    // Generate JWT — the JWT will include these claims
    var token = GenerateJwtToken(user);

    return CreatedAtAction(..., new { ..., Token = token.Token });
}
```

### Refreshing JWT Claims After Changes

**Critical point:** When you add or remove a claim from a user, the existing JWT doesn't change. The claim is in the database, but the JWT was issued at login time with a snapshot of the user's claims.

Options:
1. **Re-issue the token** — call your JWT generation method again after the claim change. This gives the user a new token with updated claims.
2. **Wait for expiry** — the old token expires and the user logs in again to get a new one.
3. **Use a refresh token flow** — issue short-lived access tokens + long-lived refresh tokens. When the access token expires, the refresh token flow re-generates the access token with current claims.

For this tutorial, the simplest approach is to re-generate the JWT after claim changes:

```csharp
// After adding a claim:
await _userManager.AddClaimAsync(user, claim);

// Re-issue the JWT so the user has the updated claims immediately
var newToken = GenerateJwtToken(user);

return Ok(new
{
    Message = "Claim added and token re-issued",
    NewToken = newToken.Token,
    ExpiresAt = newToken.ExpiresAt
});
```

### Why This Matters

Claims are the flexible, granular alternative to roles. They let you encode any fact about a user in the JWT and use that fact for authorization. Understanding how claims flow from the database into the JWT, and that the JWT is a snapshot (not a live view), prevents subtle bugs where authorization appears to not work after claim changes.

---

## Video 12 — Policy-Based Authorization in API — Custom Requirements & Handlers

### What We're Building

Custom authorization policies with requirements and handlers — age verification, subscription tier checks, business hours checks, and resource-based authorization (can this user access THIS specific resource?).

### Custom Requirements

```csharp
// A requirement is a data container implementing IAuthorizationRequirement
// (which is an empty marker interface)

// Age requirement
public class MinimumAgeRequirement : IAuthorizationRequirement
{
    public int MinimumAge { get; }
    public MinimumAgeRequirement(int minimumAge) => MinimumAge = minimumAge;
}

// Subscription tier requirement
public class SubscriptionTierRequirement : IAuthorizationRequirement
{
    public string[] RequiredTiers { get; }
    public SubscriptionTierRequirement(params string[] requiredTiers)
        => RequiredTiers = requiredTiers;
}

// Business hours requirement
public class BusinessHoursRequirement : IAuthorizationRequirement
{
    public int StartHour { get; } = 9;
    public int EndHour { get; } = 17;
}
```

### Authorization Handlers

```csharp
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace IdentityApiTutorial.Authorization;

// Handler for age requirement
public class MinimumAgeHandler : AuthorizationHandler<MinimumAgeRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        MinimumAgeRequirement requirement)
    {
        var dobClaim = context.User.FindFirst("DateOfBirth");

        if (dobClaim == null)
        {
            // No date of birth claim — can't verify age
            return Task.CompletedTask;
        }

        if (DateTime.TryParse(dobClaim.Value, out var dob))
        {
            var age = CalculateAge(dob);
            if (age >= requirement.MinimumAge)
            {
                context.Succeed(requirement);
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
            age--;
        }
        return age;
    }
}

// Handler for subscription tier
public class SubscriptionTierHandler : AuthorizationHandler<SubscriptionTierRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        SubscriptionTierRequirement requirement)
    {
        var tierClaim = context.User.FindFirst("SubscriptionTier");

        if (tierClaim != null
            && requirement.RequiredTiers.Contains(tierClaim.Value, StringComparer.OrdinalIgnoreCase))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
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
```

### Registering Policies and Handlers

In `Program.cs`:

```csharp
builder.Services.AddAuthorization(options =>
{
    // Simple policies
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("MustHaveEmail",
        policy => policy.RequireClaim("email"));

    // Custom requirement policies
    options.AddPolicy("AtLeast18",
        policy => policy.Requirements.Add(new MinimumAgeRequirement(18)));

    options.AddPolicy("PremiumOrEnterprise",
        policy => policy.Requirements.Add(
            new SubscriptionTierRequirement("Premium", "Enterprise")));

    options.AddPolicy("BusinessHoursOnly",
        policy => policy.Requirements.Add(new BusinessHoursRequirement()));

    // Multiple requirements — ALL must be satisfied
    options.AddPolicy("AdminDuringBusinessHours", policy =>
    {
        policy.RequireRole("Admin");
        policy.Requirements.Add(new BusinessHoursRequirement());
    });

    // Inline assertion policy (lambda, no handler class needed)
    options.AddPolicy("CanEditContent", policy =>
        policy.RequireAssertion(context =>
        {
            var isAdmin = context.User.IsInRole("Admin");
            var isEditor = context.User.IsInRole("Editor");
            var hasPermission = context.User.HasClaim("Permission", "Content.Edit");
            return isAdmin || isEditor || hasPermission;
        }));
});

// Register handlers
builder.Services.AddSingleton<IAuthorizationHandler, MinimumAgeHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, SubscriptionTierHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, BusinessHoursHandler>();
```

### Using Policies in Controllers

```csharp
[ApiController]
[Route("api/[controller]")]
public class PolicyProtectedController : ControllerBase
{
    /// <summary>
    /// GET /api/policyprotected/adult-content
    /// Requires user to be at least 18 (DateOfBirth claim must indicate age >= 18).
    /// </summary>
    [HttpGet("adult-content")]
    [Authorize(Policy = "AtLeast18")]
    public IActionResult AdultContent()
    {
        return Ok(new
        {
            Message = "Adult content — age verified via DateOfBirth claim",
            Timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// GET /api/policyprotected/premium-content
    /// Requires Premium or Enterprise subscription tier.
    /// </summary>
    [HttpGet("premium-content")]
    [Authorize(Policy = "PremiumOrEnterprise")]
    public IActionResult PremiumContent()
    {
        return Ok(new
        {
            Message = "Premium content — SubscriptionTier claim verified",
            Timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// GET /api/policyprotected/business-hours
    /// Only accessible during business hours (9 AM - 5 PM).
    /// </summary>
    [HttpGet("business-hours")]
    [Authorize(Policy = "BusinessHoursOnly")]
    public IActionResult BusinessHoursOnly()
    {
        return Ok(new
        {
            Message = "Business hours content",
            CurrentTime = DateTime.Now,
            Timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// GET /api/policyprotected/admin-business-hours
    /// Requires Admin role AND business hours.
    /// </summary>
    [HttpGet("admin-business-hours")]
    [Authorize(Policy = "AdminDuringBusinessHours")]
    public IActionResult AdminDuringBusinessHours()
    {
        return Ok(new
        {
            Message = "Admin content during business hours",
            CurrentTime = DateTime.Now,
            Timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// GET /api/policyprotected/edit-content
    /// Requires Admin OR Editor role OR Content.Edit permission claim.
    /// Uses inline assertion policy.
    /// </summary>
    [HttpGet("edit-content")]
    [Authorize(Policy = "CanEditContent")]
    public IActionResult EditContent()
    {
        return Ok(new
        {
            Message = "Content editing access",
            Timestamp = DateTime.UtcNow
        });
    }
}
```

### Resource-Based Authorization

Sometimes authorization depends on the specific resource — e.g., "can this user access THIS document?" Use imperative authorization:

```csharp
// Resource entity
public class Document
{
    public int Id { get; set; }
    public string OwnerId { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public bool IsShared { get; set; }
    public List<DocumentShare> SharedWith { get; set; } = new();
}

public class DocumentShare
{
    public string UserId { get; set; } = string.Empty;
    public bool CanRead { get; set; } = true;
    public bool CanEdit { get; set; }
    public bool CanDelete { get; set; }
}

// Requirement
public class DocumentOperationRequirement : IAuthorizationRequirement
{
    public string Operation { get; }
    public DocumentOperationRequirement(string operation) => Operation = operation;
}

// Static factory for clean policy names
public static class DocumentPolicies
{
    public static DocumentOperationRequirement Read => new("Read");
    public static DocumentOperationRequirement Edit => new("Edit");
    public static DocumentOperationRequirement Delete => new("Delete");
}

// Handler
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
        var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier)
                     ?? context.User.FindFirstValue("userId");

        if (resource.OwnerId == userId)
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        // Shared users can do permitted operations
        var share = resource.SharedWith.FirstOrDefault(s => s.UserId == userId);
        if (share != null)
        {
            if (requirement.Operation == "Read" && share.CanRead)
            {
                context.Succeed(requirement);
            }
            else if (requirement.Operation == "Edit" && share.CanEdit)
            {
                context.Succeed(requirement);
            }
            else if (requirement.Operation == "Delete" && share.CanDelete)
            {
                context.Succeed(requirement);
            }
        }

        return Task.CompletedTask;
    }
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
    options.AddPolicy("DeleteDocument",
        policy => policy.Requirements.Add(DocumentPolicies.Delete));
});

builder.Services.AddSingleton<IAuthorizationHandler, DocumentAuthorizationHandler>();
```

Usage with resource-based authorization (imperative):

```csharp
[ApiController]
[Route("api/[controller]")]
public class DocumentsController : ControllerBase
{
    private readonly IAuthorizationService _authorizationService;
    private readonly IDocumentRepository _documentRepo;

    public DocumentsController(
        IAuthorizationService authorizationService,
        IDocumentRepository documentRepo)
    {
        _authorizationService = authorizationService;
        _documentRepo = documentRepo;
    }

    /// <summary>
    /// GET /api/documents/{id}
    /// Read a document — checked against the resource.
    /// </summary>
    [HttpGet("{id}")]
    [Authorize]  // Must be authenticated
    public async Task<IActionResult> GetDocument(int id)
    {
        var document = await _documentRepo.GetByIdAsync(id);
        if (document == null)
        {
            return NotFound(new { Message = "Document not found" });
        }

        // Resource-based authorization: check if user can read THIS document
        var result = await _authorizationService.AuthorizeAsync(
            User, document, "ReadDocument");

        if (!result.Succeeded)
        {
            return Forbid(new
            {
                Message = "You do not have permission to read this document"
            });
        }

        return Ok(new
        {
            Id = document.Id,
            Title = document.Title,
            Content = document.Content
        });
    }

    /// <summary>
    /// PUT /api/documents/{id}
    /// Edit a document — checked against the resource.
    /// </summary>
    [HttpPut("{id}")]
    [Authorize]
    public async Task<IActionResult> EditDocument(int id, [FromBody] EditDocumentRequest request)
    {
        var document = await _documentRepo.GetByIdAsync(id);
        if (document == null)
        {
            return NotFound(new { Message = "Document not found" });
        }

        var result = await _authorizationService.AuthorizeAsync(
            User, document, "EditDocument");

        if (!result.Succeeded)
        {
            return Forbid(new
            {
                Message = "You do not have permission to edit this document"
            });
        }

        document.Content = request.Content;
        await _documentRepo.UpdateAsync(document);

        return Ok(new
        {
            Message = "Document updated",
            Id = document.Id
        });
    }
}
```

### Why This Matters

Policies are the most powerful authorization mechanism in ASP.NET Core. They let you define complex rules once and apply them consistently. Resource-based authorization handles the case where access depends on the specific resource, not just the user's general permissions. This video takes you from simple `[Authorize(Roles = "...")]` to full custom policies.

---

## Video 13 — Password Policies & Custom Validation in API

### What We're Building

Configuring built-in password options, writing a custom `IPasswordValidator` that checks for common passwords, user info in passwords, sequential/repeated characters, and a password strength check endpoint.

### Built-in Password Options

In `Program.cs` (Video 04):

```csharp
builder.Services.AddIdentityCore<ApplicationUser>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 8;
    options.Password.RequiredUniqueChars = 1;
})
.AddRoles<ApplicationRole>()
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();
```

These are checked automatically in `UserManager.CreateAsync` and `UserManager.AddPasswordAsync`. If the password fails, the result's `Errors` collection contains descriptive errors.

### Custom Password Validator

```csharp
using Microsoft.AspNetCore.Identity;

namespace IdentityApiTutorial.Services;

public class CustomPasswordValidator : IPasswordValidator<ApplicationUser>
{
    public Task<IdentityResult> ValidateAsync(
        UserManager<ApplicationUser> manager,
        ApplicationUser user,
        string? password)
    {
        var errors = new List<IdentityError>();

        // ── 1. Null/empty ──
        if (string.IsNullOrEmpty(password))
        {
            return Task.FromResult(IdentityResult.Failed(
                new IdentityError
                {
                    Code = "PasswordEmpty",
                    Description = "Password is required"
                }));
        }

        // ── 2. Minimum length (stricter than default) ──
        if (password.Length < 10)
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordTooShort",
                Description = "Password must be at least 10 characters"
            });
        }

        // ── 3. Common passwords ──
        // In production, use a breached password API (e.g., HaveIBeenPwned)
        var commonPasswords = new[]
        {
            "password", "123456", "qwerty", "letmein", "admin",
            "welcome", "monkey", "dragon", "master", "login",
            "abc123", "111111", "passw0rd"
        };

        if (commonPasswords.Any(p =>
            password.ToLowerInvariant().Contains(p)))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordTooCommon",
                Description = "Password contains a common word or sequence"
            });
        }

        // ── 4. User info in password ──
        if (!string.IsNullOrEmpty(user.UserName)
            && password.ToLowerInvariant().Contains(user.UserName.ToLowerInvariant()))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordContainsUsername",
                Description = "Password cannot contain your username"
            });
        }

        if (!string.IsNullOrEmpty(user.Email))
        {
            var emailPrefix = user.Email.Split('@')[0];
            if (password.ToLowerInvariant().Contains(emailPrefix.ToLowerInvariant()))
            {
                errors.Add(new IdentityError
                {
                    Code = "PasswordContainsEmail",
                    Description = "Password cannot contain your email address"
                });
            }
        }

        // ── 5. Sequential characters ──
        if (HasSequentialChars(password, 3))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordHasSequence",
                Description = "Password cannot contain sequential characters (abc, 123, cba)"
            });
        }

        // ── 6. Repeated characters ──
        if (HasRepeatedChars(password, 3))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordHasRepetition",
                Description = "Password cannot contain repeated characters (aaa, 111)"
            });
        }

        return Task.FromResult(
            errors.Count == 0
                ? IdentityResult.Success
                : IdentityResult.Failed(errors.ToArray()));
    }

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
builder.Services.AddIdentityCore<ApplicationUser>(options =>
{
    // Password options...
})
.AddRoles<ApplicationRole>()
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders()
.AddPasswordValidator<CustomPasswordValidator>();  // ← Add this line
```

Multiple validators can be registered. They all run and aggregate errors.

### Password Strength Check Endpoint

```csharp
using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.Models;

namespace IdentityApiTutorial.Controllers;

[ApiController]
[Route("api/[controller]")]
[AllowAnonymous]  // Allow unauthenticated access for strength checking
public class PasswordController : ControllerBase
{
    /// <summary>
    /// POST /api/password/check-strength
    /// Check password strength without registering.
    /// Useful for frontend real-time feedback.
    /// </summary>
    [HttpPost("check-strength")]
    public IActionResult CheckPasswordStrength([FromBody] PasswordStrengthRequest request)
    {
        if (string.IsNullOrEmpty(request.Password))
        {
            return Ok(new
            {
                Score = 0,
                Strength = "None",
                Feedback = new[] { "Enter a password" }
            });
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
            feedback.Add("Avoid sequential characters (abc, 123, cba)");
        }

        if (HasRepeatedChars(request.Password, 3))
        {
            score -= 1;
            feedback.Add("Avoid repeated characters (aaa, 111)");
        }

        var common = new[] { "password", "123456", "qwerty", "admin", "letmein" };
        if (common.Any(p => request.Password.ToLowerInvariant().Contains(p)))
        {
            score -= 2;
            feedback.Add("Avoid common passwords");
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
            Strength = strength,
            Feedback = feedback
        });
    }

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
            if (ascending || descending) return true;
        }
        return false;
    }

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

public class PasswordStrengthRequest
{
    public string Password { get; set; } = string.Empty;
}
```

### Postman Test

```
POST /api/password/check-strength
Content-Type: application/json

{
  "password": "P@ssw0rd123"
}
```

**Response:**
```json
{
  "score": 7,
  "strength": "Good",
  "feedback": []
}
```

### Why This Matters

Password validation is a visible security feature. Built-in options cover the basics; custom validators enforce organizational policies, check against common passwords, and reject passwords containing user info. The strength endpoint improves UX with real-time feedback.

---

## Video 14 — Account Lockout & Security Stamp in API

### What We're Building

Account lockout configuration, lock/unlock endpoints, the security stamp mechanism, and how to invalidate all JWTs for a user when security-critical changes happen.

### Lockout Configuration (Already in Program.cs from Video 04)

```csharp
options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
options.Lockout.MaxFailedAccessAttempts = 5;
options.Lockout.AllowedForNewUsers = true;
```

### Lockout Endpoints

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using IdentityApiTutorial.Models;

namespace IdentityApiTutorial.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin")]  // Admin-only lockout management
public class LockoutManagementController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<LockoutManagementController> _logger;

    public LockoutManagementController(
        UserManager<ApplicationUser> userManager,
        ILogger<LockoutManagementController> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    /// <summary>
    /// GET /api/lockoutmanagement/users/{userId}/status
    /// Get a user's lockout status.
    /// </summary>
    [HttpGet("users/{userId}/status")]
    public async Task<IActionResult> GetLockoutStatus(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        var isLockedOut = await _userManager.IsLockedOutAsync(user);
        var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
        var accessFailedCount = await _userManager.GetAccessFailedCountAsync(user);
        var lockoutEnabled = user.LockoutEnabled;

        return Ok(new
        {
            UserId = userId,
            UserName = user.UserName,
            IsLockedOut = isLockedOut,
            LockoutEnd = lockoutEnd,
            RemainingLockoutMinutes = lockoutEnd.HasValue
                && lockoutEnd > DateTimeOffset.UtcNow
                ? (int)(lockoutEnd.Value - DateTimeOffset.UtcNow).TotalMinutes
                : null,
            AccessFailedCount = accessFailedCount,
            LockoutEnabled = lockoutEnabled
        });
    }

    /// <summary>
    /// POST /api/lockoutmanagement/users/{userId}/lock
    /// Manually lock a user's account.
    /// </summary>
    [HttpPost("users/{userId}/lock")]
    public async Task<IActionResult> LockUser(string userId, [FromBody] LockUserRequest request)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        // Safety: don't lock the last admin
        if (await _userManager.IsInRoleAsync(user, "Admin"))
        {
            var admins = await _userManager.GetUsersInRoleAsync("Admin");
            if (admins.Count == 1 && admins[0].Id == userId)
            {
                return BadRequest(new
                {
                    Message = "Cannot lock the last administrator"
                });
            }
        }

        // Enable lockout if not already
        if (!user.LockoutEnabled)
        {
            await _userManager.SetLockoutEnabledAsync(user, true);
        }

        // Reset failed attempts before locking (so they don't immediately unlock)
        await _userManager.ResetAccessFailedCountAsync(user);

        // Set lockout end
        var lockoutEnd = request.DurationMinutes > 0
            ? DateTimeOffset.UtcNow.AddMinutes(request.DurationMinutes)
            : DateTimeOffset.MaxValue; // Permanent lock

        var result = await _userManager.SetLockoutEndDateAsync(user, lockoutEnd);

        if (!result.Succeeded)
        {
            return BadRequest(new
            {
                Message = "Failed to lock user",
                Errors = result.Errors.Select(e => e.Description)
            });
        }

        _logger.LogInformation("User {UserId} locked out by admin. Duration: {Duration} minutes",
            userId, request.DurationMinutes);

        return Ok(new
        {
            Message = "User account locked",
            UserId = userId,
            LockoutEnd = lockoutEnd,
            IsPermanent = request.DurationMinutes <= 0
        });
    }

    /// <summary>
    /// POST /api/lockoutmanagement/users/{userId}/unlock
    /// Unlock a user's account.
    /// </summary>
    [HttpPost("users/{userId}/unlock")]
    public async Task<IActionResult> UnlockUser(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        var result = await _userManager.SetLockoutEndDateAsync(user, null);

        if (!result.Succeeded)
        {
            return BadRequest(new
            {
                Message = "Failed to unlock user",
                Errors = result.Errors.Select(e => e.Description)
            });
        }

        // Reset failed attempts so they don't immediately re-lock
        await _userManager.ResetAccessFailedCountAsync(user);

        _logger.LogInformation("User {UserId} unlocked by admin", userId);

        return Ok(new
        {
            Message = "User account unlocked",
            UserId = userId
        });
    }
}

public class LockUserRequest
{
    public int DurationMinutes { get; set; } = 15; // Default 15 minutes; 0 = permanent
}
```

### The Security Stamp — API Context

The `SecurityStamp` is a random GUID on the user. It changes when security-critical events occur:
- Password change
- Role assignment/removal
- 2FA enable/disable
- Email/phone change

**In a cookie-based app**, when the stamp changes, the cookie's stamp no longer matches the database, and the user is signed out on the next request.

**In a JWT-based API**, the stamp isn't in the JWT by default (unless you add it as a claim). This means changing the stamp doesn't automatically invalidate existing JWTs. To achieve "sign out everywhere" in an API, you need one of:

1. **Add the SecurityStamp to the JWT as a claim** — then when the stamp changes, you can check it in a validation event and reject the token.
2. **Token blacklist** — store the JTI (unique token ID) in a blacklist with the token's remaining lifetime when the user signs out or the stamp changes.
3. **Short-lived access tokens + refresh tokens** — access tokens expire quickly (e.g., 15 minutes), and the refresh token flow re-validates the user's current state before issuing a new access token.

For this tutorial, we'll show option 1 (adding the stamp to the JWT) + option 3 (short-lived tokens) as the practical approach.

### Adding SecurityStamp to the JWT

In the `GenerateJwtToken` method (Video 08), add the security stamp as a claim:

```csharp
claims.Add(new("securityStamp", user.SecurityStamp ?? ""));
```

### Checking SecurityStamp on JWT Validation

In `Program.cs`, add an event to the JWT bearer options:

```csharp
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        // ... existing validation parameters ...
    };

    options.Events = new JwtBearerEvents
    {
        OnTokenValidated = context =>
        {
            // Check if the security stamp in the JWT matches the current user's stamp
            var securityStampClaim = context.Principal?.FindFirst("securityStamp");
            var userId = context.Principal?.FindFirstValue("userId")
                         ?? context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);

            if (!string.IsNullOrEmpty(userId))
            {
                // Note: This requires accessing the database on every request.
                // For high-traffic APIs, consider caching or using a blacklist approach.
                // For this tutorial, we show the concept.
                var userManager = context.HttpContext.RequestServices
                    .GetRequiredService<UserManager<ApplicationUser>>();

                // Don't await in a sync event — use a task and fire-and-forget,
                // or make the event async (JWT bearer supports async events in .NET 8+)
                Task.Run(async () =>
                {
                    var user = await userManager.FindByIdAsync(userId);
                    if (user != null
                        && securityStampClaim != null
                        && user.SecurityStamp != null
                        && !user.SecurityStamp.Equals(securityStampClaim.Value, StringComparison.Ordinal))
                    {
                        // Stamp mismatch — token is invalid
                        context.Fail(new SecurityTokenInvalidSignatureException(
                            "Security stamp mismatch — token has been revoked"));
                    }
                });
            }

            return Task.CompletedTask;
        }
    };
});
```

**Note:** The `OnTokenValidated` event runs on every authenticated request. Accessing the database on every request has performance implications. For production, consider:
- Short-lived access tokens (15 minutes) so the stamp check is only needed for revocation within that window
- A token blacklist for explicit revocation
- Caching the user's security stamp with a short TTL

### Updating the Security Stamp

```csharp
// In the appropriate controller (e.g., AccountController or a UserManagementController)

/// <summary>
/// POST /api/account/users/{userId}/revoke-tokens
/// Invalidate all existing tokens for a user (admin action or self-service).
/// Updates the security stamp, which will cause JWT validation to fail
/// (if stamp checking is enabled as shown above).
/// </summary>
[HttpPost("users/{userId}/revoke-tokens")]
[Authorize]  // Could be self-service (user can only revoke their own tokens)
public async Task<IActionResult> RevokeTokens(string userId)
{
    var currentUserId = User.FindFirstValue("userId")
                        ?? User.FindFirstValue(ClaimTypes.NameIdentifier);

    // Allow users to revoke only their own tokens, or admins to revoke any
    if (!string.Equals(userId, currentUserId))
    {
        if (!await _userManager.IsInRoleAsync(
            await _userManager.FindByIdAsync(currentUserId), "Admin"))
        {
            return Forbid();
        }
    }

    var user = await _userManager.FindByIdAsync(userId);
    if (user == null)
    {
        return NotFound(new { Message = "User not found" });
    }

    // Update the security stamp — this invalidates all tokens that include the old stamp
    await _userManager.UpdateSecurityStampAsync(user);

    _logger.LogInformation("Security stamp updated for user {UserId} — all tokens revoked",
        userId);

    return Ok(new
    {
        Message = "All tokens for this user have been revoked. The user must log in again.",
        UserId = userId
    });
}
```

### Why This Matters

Lockout is your first line of defense against brute force. The security stamp is your mechanism for "sign out everywhere" — critical when a password is compromised or an admin removes a user's access. In an API with JWTs, you need to understand that the stamp doesn't automatically invalidate tokens; you must add stamp checking to your JWT validation or use a blacklist/short-lived tokens.

---

## Video 15 — Two-Factor Authentication (2FA) API — TOTP, Recovery Codes

### What We're Building

API endpoints for enabling 2FA (TOTP with authenticator apps), verifying the TOTP code, generating recovery codes, the 2FA login flow (login → get "2FA required" response → verify code → get JWT), and disabling 2FA.

### Enable 2FA — Endpoint to Get the Secret Key

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using IdentityApiTutorial.Models;
using System.Text;
using System.Web;

namespace IdentityApiTutorial.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TwoFactorController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<TwoFactorController> _logger;

    public TwoFactorController(
        UserManager<ApplicationUser> userManager,
        ILogger<TwoFactorController> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    /// <summary>
    /// POST /api/twofactor/enable
    /// Start the 2FA enablement process.
    /// Returns the authenticator key (for manual entry) and the OTPAuth URI (for QR code generation).
    /// The client generates a QR code from the URI and the user scans it with their authenticator app.
    /// </summary>
    [HttpPost("enable")]
    [Authorize]
    public async Task<IActionResult> EnableTwoFactor([FromBody] Enable2FaRequest request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        // Get or generate the authenticator key
        var key = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            key = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        // Generate a QR code URI
        // Format: otpauth://totp/{issuer}:{account}?secret={key}&issuer={issuer}&digits=6&period=30
        var qrUri = GenerateQrCodeUri(user.Email!, key);

        // Format the key into groups of 4 for manual entry
        var formattedKey = FormatKey(key);

        return Ok(new
        {
            Message = "2FA setup initiated. Scan the QR code with your authenticator app, or enter the key manually.",
            UserId = user.Id,
            SharedKey = formattedKey,
            AuthenticatorUri = qrUri,
            Note = "After scanning/entering the key, call /api/twofactor/verify with the code from your authenticator app."
        });
    }

    /// <summary>
    /// POST /api/twofactor/verify
    /// Verify the TOTP code from the authenticator app and enable 2FA.
    /// Also generates recovery codes.
    /// </summary>
    [HttpPost("verify")]
    [Authorize]
    public async Task<IActionResult> VerifyTwoFactor([FromBody] Verify2FaRequest request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        // Clean the code — remove spaces and hyphens
        var code = request.Code.Replace(" ", string.Empty)
                               .Replace("-", string.Empty);

        // Verify the code
        var isValid = await _userManager.VerifyTwoFactorTokenAsync(
            user,
            _userManager.Options.Tokens.AuthenticatorTokenProvider,
            code);

        if (!isValid)
        {
            return BadRequest(new
            {
                Message = "Invalid verification code. Please try again."
            });
        }

        // Enable 2FA
        await _userManager.SetTwoFactorEnabledAsync(user, true);

        // Generate recovery codes (used when the authenticator app is unavailable)
        var recoveryCodes = await _userManager
            .GenerateNewTwoFactorRecoveryCodesAsync(user, 10);

        _logger.LogInformation("User {UserId} enabled 2FA", user.Id);

        return Ok(new
        {
            Message = "Two-factor authentication enabled successfully",
            UserId = user.Id,
            RecoveryCodes = recoveryCodes,  // User MUST save these — they're single-use
            Note = "Save these recovery codes in a secure location. They can be used to log in if your authenticator app is unavailable."
        });
    }

    /// <summary>
    /// POST /api/twofactor/disable
    /// Disable 2FA for the current user.
    /// </summary>
    [HttpPost("disable")]
    [Authorize]
    public async Task<IActionResult> DisableTwoFactor()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        if (!await _userManager.GetTwoFactorEnabledAsync(user))
        {
            return BadRequest(new
            {
                Message = "Two-factor authentication is not currently enabled"
            });
        }

        var result = await _userManager.SetTwoFactorEnabledAsync(user, false);
        if (!result.Succeeded)
        {
            return BadRequest(new
            {
                Message = "Failed to disable 2FA",
                Errors = result.Errors.Select(e => e.Description)
            });
        }

        _logger.LogInformation("User {UserId} disabled 2FA", user.Id);

        return Ok(new
        {
            Message = "Two-factor authentication disabled",
            UserId = user.Id
        });
    }

    /// <summary>
    /// GET /api/twofactor/status
    /// Check if 2FA is enabled for the current user.
    /// </summary>
    [HttpGet("status")]
    [Authorize]
    public async Task<IActionResult> GetTwoFactorStatus()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        return Ok(new
        {
            UserId = user.Id,
            TwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user),
            IsLockedOut = await _userManager.IsLockedOutAsync(user)
        });
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

    // ── Helper: Generate OTPAuth URI ──
    private string GenerateQrCodeUri(string email, string secretKey)
    {
        var issuer = HttpUtility.UrlEncode("IdentityApiTutorial");
        var account = HttpUtility.UrlEncode(email);
        return $"otpauth://totp/{issuer}:{account}?secret={secretKey}&issuer={issuer}&digits=6&period=30";
    }
}

public class Enable2FaRequest
{
    // No parameters needed — the user is identified from the JWT
}

public class Verify2FaRequest
{
    public string Code { get; set; } = string.Empty;
}
```

### 2FA Login Flow — Modified Login Endpoint

In the login endpoint (Video 08), after `CheckPasswordSignInAsync`:

```csharp
var signInResult = await _signInManager.CheckPasswordSignInAsync(
    user, request.Password, lockoutOnFailure: true);

if (signInResult.Succeeded)
{
    // ... update last login, reset failed count ...

    // ── Check if 2FA is required ──
    if (signInResult.RequiresTwoFactor)
    {
        // Don't issue the JWT yet — return a response indicating 2FA is needed
        return Ok(new
        {
            Message = "Two-factor authentication required",
            UserId = user.Id,
            Requires2Fa = true,
            Note = "Call /api/account/verify-2fa with the TOTP code to complete login and receive your JWT"
        });
    }

    // ── No 2FA — issue JWT normally ──
    var token = GenerateJwtToken(user);
    return Ok(token);
}
```

### Verify 2FA and Issue JWT — Login Endpoint Addition

```csharp
/// <summary>
/// POST /api/account/verify-2fa
/// Complete the login after 2FA verification.
/// Called after the login endpoint returns Requires2Fa = true.
/// </summary>
[HttpPost("verify-2fa")]
[AllowAnonymous]  // Allow unauthenticated — the user is identified by the temporary 2FA session
public async Task<IActionResult> Verify2FaAndLogin([FromBody] Verify2FaLoginRequest request)
{
    // In a full implementation, you'd store the user ID in a temporary 2FA session
    // (e.g., a short-lived cookie or a server-side session) during the login step.
    // For this tutorial, we'll accept the UserId in the request and validate it.
    //
    // Production approach: use a temporary cookie set by the login endpoint
    // that identifies the user mid-2FA flow, similar to how SignInManager
    // handles the 2FA flow in MVC.

    if (string.IsNullOrEmpty(request.UserId))
    {
        return BadRequest(new { Message = "User ID is required" });
    }

    var user = await _userManager.FindByIdAsync(request.UserId);
    if (user == null)
    {
        return NotFound(new { Message = "User not found" });
    }

    // Clean the code
    var code = request.Code.Replace(" ", string.Empty)
                           .Replace("-", string.Empty);

    // Verify the TOTP code
    var isValid = await _userManager.VerifyTwoFactorTokenAsync(
        user,
        _userManager.Options.Tokens.AuthenticatorTokenProvider,
        code);

    if (!isValid)
    {
        return BadRequest(new
        {
            Message = "Invalid 2FA code"
        });
    }

    // Optional: verify recovery code instead of TOTP
    if (request.UseRecoveryCode)
    {
        var recoveryResult = await _signInManager
            .TwoFactorRecoveryCodeSignInAsync(request.Code);

        if (recoveryResult.Succeeded)
        {
            // Recovery code consumed — issue JWT
            var token = GenerateJwtToken(user);
            return Ok(token);
        }

        if (recoveryResult.IsLockedOut)
        {
            return BadRequest(new { Message = "Account locked" });
        }

        return BadRequest(new { Message = "Invalid recovery code" });
    }

    // TOTP code verified — issue JWT
    var token = GenerateJwtToken(user);

    _logger.LogInformation("User {UserId} logged in with 2FA", user.Id);

    return Ok(token);
}

public class Verify2FaLoginRequest
{
    public string UserId { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
    public bool UseRecoveryCode { get; set; } = false;
}
```

### Postman Test Cases

**Step 1 — Enable 2FA:**
```
POST /api/twofactor/enable
Authorization: Bearer <jwt-for-authenticated-user>
```

Response includes `SharedKey` and `AuthenticatorUri`. Use the URI to generate a QR code (or enter the key manually in your authenticator app).

**Step 2 — Verify 2FA:**
```
POST /api/twofactor/verify
Authorization: Bearer <jwt-for-authenticated-user>
Content-Type: application/json

{
  "code": "123456"
}
```

Response includes `RecoveryCodes` — save them.

**Step 3 — Login with 2FA:**
```
POST /api/account/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "P@ssw0rd123"
}
```

Response: `{ "requires2Fa": true, "userId": "..." }`

Then:
```
POST /api/account/verify-2fa
Content-Type: application/json

{
  "userId": "...",
  "code": "123456"
}
```

Response: JWT token.

### Why This Matters

2FA is one of the most effective security improvements. This video shows the complete API flow: enabling 2FA (getting the key, verifying the code, generating recovery codes), the modified login flow (password correct → 2FA required → verify → JWT), and disabling 2FA. All testable with Postman.

---

## Video 16 — External Login Providers in API — Google, Facebook, Microsoft

### What We're Building

Registering external login providers, handling the OAuth callback, issuing a JWT for external users, linking external logins to existing accounts, and managing external logins.

### Registering External Providers

In `Program.cs`:

```csharp
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;

// After AddAuthentication(JwtBearerDefaults...) from Video 04:

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    // ... JWT configuration ...
})
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

In `appsettings.json`:

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

### External Login Callback — Issue JWT for External Users

```csharp
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.Models;

namespace IdentityApiTutorial.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AccountController : ControllerBase
{
    // ... existing dependencies from Video 07 ...

    /// <summary>
    /// GET /api/account/external-login-callback
    /// Called by the external provider after OAuth authentication.
    /// The provider redirects to this endpoint with the auth code.
    /// ASP.NET Core's external auth middleware handles the OAuth exchange
    /// and calls this endpoint with the external login info.
    ///
    /// NOTE: In a pure API, the OAuth flow is typically initiated from a
    /// frontend (web app or mobile app) that handles the redirect.
    /// The frontend then sends the external login token to this API.
    ///
    /// For this tutorial, we show the server-side callback approach.
    /// In production, consider having the frontend handle OAuth and
    /// send the ID token to the API for verification.
    /// </summary>
    [HttpGet("external-login-callback")]
    [AllowAnonymous]
    public async Task<IActionResult> ExternalLoginCallback(string? returnUrl = null, string? remoteError = null)
    {
        if (remoteError != null)
        {
            return BadRequest(new
            {
                Message = $"External provider error: {remoteError}"
            });
        }

        // Get the external login info from the ASP.NET Core external auth middleware
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            return BadRequest(new
            {
                Message = "External login info not available"
            });
        }

        // Try to sign in with this external login
        // (In MVC, SignInManager.ExternalLoginSignInAsync creates a cookie.
        //  In API, we check if the user exists and issue a JWT.)
        var result = await _signInManager.ExternalLoginSignInAsync(
            info.LoginProvider,
            info.ProviderKey,
            isPersistent: false,
            bypassTwoFactor: true);

        if (result.Succeeded)
        {
            // User has this external login already linked — get the user and issue JWT
            var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
            if (user != null)
            {
                var token = GenerateJwtToken(user);
                return Ok(new
                {
                    Message = $"Logged in via {info.LoginProvider}",
                    Token = token
                });
            }
        }

        // If we get here, the user doesn't have an account with this external login yet.
        // Extract info from the external claims to create/link an account.
        var email = info.Principal.FindFirstValue(ClaimTypes.Email);
        var name = info.Principal.FindFirstValue(ClaimTypes.Name);

        if (string.IsNullOrEmpty(email))
        {
            return BadRequest(new
            {
                Message = "External provider did not return an email address"
            });
        }

        // Check if an account with this email already exists
        var existingUser = await _userManager.FindByEmailAsync(email);

        if (existingUser != null)
        {
            // Link the external login to the existing account
            var linkResult = await _userManager.AddLoginAsync(existingUser, info);
            if (linkResult.Succeeded)
            {
                var token = GenerateJwtToken(existingUser);
                return Ok(new
                {
                    Message = $"External account linked and logged in via {info.LoginProvider}",
                    Token = token
                });
            }

            return BadRequest(new
            {
                Message = "Failed to link external account",
                Errors = linkResult.Errors.Select(e => e.Description)
            });
        }

        // Create a new user account
        var newUser = new ApplicationUser
        {
            UserName = email,  // Use email as username if no name provided
            Email = email,
            FirstName = name?.Split(' ').FirstOrDefault(),
            LastName = name?.Split(' ').Skip(1).FirstOrDefault(),
            EmailConfirmed = true,  // External providers verified the email
            CreatedAt = DateTime.UtcNow,
            IsActive = true
        };

        var createResult = await _userManager.CreateAsync(newUser);
        if (createResult.Succeeded)
        {
            // Link the external login
            var linkResult = await _userManager.AddLoginAsync(newUser, info);
            if (linkResult.Succeeded)
            {
                // Assign default role
                await _userManager.AddToRoleAsync(newUser, "User");

                var token = GenerateJwtToken(newUser);
                _logger.LogInformation("User created account via {Provider}", info.LoginProvider);

                return Ok(new
                {
                    Message = $"Account created and logged in via {info.LoginProvider}",
                    Token = token
                });
            }

            // If linking fails, clean up the created user
            await _userManager.DeleteAsync(newUser);
            return BadRequest(new
            {
                Message = "Failed to link external account after user creation"
            });
        }

        return BadRequest(new
        {
            Message = "Failed to create user account",
            Errors = createResult.Errors.Select(e => e.Description)
        });
    }
}
```

### Linking and Unlinking External Logins

```csharp
/// <summary>
/// GET /api/account/external-logins
/// Get the current user's linked external logins and available providers.
/// </summary>
[HttpGet("external-logins")]
[Authorize]
public async Task<IActionResult> GetExternalLogins()
{
    var user = await _userManager.GetUserAsync(User);
    if (user == null)
    {
        return NotFound(new { Message = "User not found" });
    }

    var currentLogins = await _userManager.GetLoginsAsync(user);

    return Ok(new
    {
        UserId = user.Id,
        CurrentLogins = currentLogins.Select(l => new
        {
            LoginProvider = l.LoginProvider,
            ProviderKey = l.ProviderKey
        }),
        Note = "To link a new external login, initiate the OAuth flow from your frontend and call the external-login-callback endpoint."
    });
}

/// <summary>
/// POST /api/account/external-logins/unlink
/// Remove an external login from the current user's account.
/// </summary>
[HttpPost("external-logins/unlink")]
[Authorize]
public async Task<IActionResult> UnlinkExternalLogin([FromBody] UnlinkExternalLoginRequest request)
{
    var user = await _userManager.GetUserAsync(User);
    if (user == null)
    {
        return NotFound(new { Message = "User not found" });
    }

    // Can't remove the last login method if the user has no password set
    if (user.PasswordHash == null && await _userManager.GetLoginsAsync(user).Count() <= 1)
    {
        return BadRequest(new
        {
            Message = "Cannot remove the last login method. Set a password first."
        });
    }

    var result = await _userManager.RemoveLoginAsync(user, request.LoginProvider, request.ProviderKey);

    if (!result.Succeeded)
    {
        return BadRequest(new
        {
            Message = "Failed to unlink external login",
            Errors = result.Errors.Select(e => e.Description)
        });
    }

    _logger.LogInformation("External login {Provider} removed from user {UserId}",
        request.LoginProvider, user.Id);

    return Ok(new
    {
        Message = "External login unlinked",
        UserId = user.Id
    });
}

public class UnlinkExternalLoginRequest
{
    public string LoginProvider { get; set; } = string.Empty;
    public string ProviderKey { get; set; } = string.Empty;
}
```

### Why This Matters

External login reduces friction — users don't need to create another password. But it introduces complexity: handling the OAuth callback, linking accounts, managing the lifecycle of external logins, and issuing JWTs for external users. This video covers the complete API flow.

---

## Video 17 — Token Providers — Email Confirmation, Password Reset, Custom Providers

### What We're Building

Email confirmation endpoint, password reset endpoint (forgot password + reset password), how token providers work internally, and writing a custom token provider.

### Email Confirmation Endpoint

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using IdentityApiTutorial.Models;

namespace IdentityApiTutorial.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AccountController : ControllerBase
{
    // ... existing dependencies ...

    /// <summary>
    /// POST /api/account/confirm-email
    /// Confirm a user's email using the token sent via email (or returned in the registration response for demo).
    /// </summary>
    [HttpPost("confirm-email")]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailRequest request)
    {
        if (string.IsNullOrEmpty(request.UserId) || string.IsNullOrEmpty(request.Token))
        {
            return BadRequest(new { Message = "User ID and token are required" });
        }

        var user = await _userManager.FindByIdAsync(request.UserId);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        var result = await _userManager.ConfirmEmailAsync(user, request.Token);

        if (result.Succeeded)
        {
            _logger.LogInformation("Email confirmed for user {UserId}", request.UserId);

            return Ok(new
            {
                Message = "Email confirmed successfully",
                UserId = request.UserId,
                Email = user.Email,
                EmailConfirmed = true
            });
        }

        return BadRequest(new
        {
            Message = "Invalid or expired confirmation token",
            Errors = result.Errors.Select(e => e.Description)
        });
    }

    /// <summary>
    /// GET /api/account/resend-confirmation-email
    /// Resend the email confirmation token (for users who didn't receive it).
    /// </summary>
    [HttpPost("resend-confirmation-email")]
    [AllowAnonymous]
    public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationRequest request)
    {
        if (string.IsNullOrEmpty(request.Email))
        {
            return BadRequest(new { Message = "Email is required" });
        }

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null || user.EmailConfirmed)
        {
            // Don't reveal whether the email exists or is already confirmed
            return Ok(new
            {
                Message = "If the email exists and is not confirmed, a new confirmation link has been sent."
            });
        }

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

        // In production: send the token via email to user.Email
        // For demo: return the token so the caller can use it with /api/account/confirm-email
        return Ok(new
        {
            Message = "Confirmation token generated",
            UserId = user.Id,
            Token = token,
            Note = "In production, this token would be sent via email, not returned in the API response."
        });
    }
}

public class ConfirmEmailRequest
{
    public string UserId { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
}

public class ResendConfirmationRequest
{
    public string Email { get; set; } = string.Empty;
}
```

### Password Reset Endpoints

```csharp
/// <summary>
/// POST /api/account/forgot-password
/// Initiate password reset — generate a reset token and send it via email.
/// </summary>
[HttpPost("forgot-password")]
[AllowAnonymous]
public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
{
    if (string.IsNullOrEmpty(request.Email))
    {
        return BadRequest(new { Message = "Email is required" });
    }

    var user = await _userManager.FindByEmailAsync(request.Email);

    // Don't reveal whether the email exists or is confirmed
    if (user == null || !await _userManager.IsEmailConfirmedAsync(user))
    {
        return Ok(new
        {
            Message = "If the email exists and is confirmed, a password reset link has been sent."
        });
    }

    var token = await _userManager.GeneratePasswordResetTokenAsync(user);

    // In production: send the token via email to user.Email
    // For demo: return the token so the caller can use it with /api/account/reset-password
    return Ok(new
    {
        Message = "If the email exists, a password reset token has been generated",
        UserId = user.Id,
        Token = token,
        Note = "In production, this token would be sent via email, not returned in the API response."
    });
}

/// <summary>
/// POST /api/account/reset-password
/// Reset the password using the token from the forgot-password step.
/// </summary>
[HttpPost("reset-password")]
[AllowAnonymous]
public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
{
    if (string.IsNullOrEmpty(request.UserId)
        || string.IsNullOrEmpty(request.Token)
        || string.IsNullOrEmpty(request.NewPassword))
    {
        return BadRequest(new { Message = "User ID, token, and new password are required" });
    }

    var user = await _userManager.FindByIdAsync(request.UserId);
    if (user == null)
    {
        return NotFound(new { Message = "User not found" });
    }

    var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);

    if (result.Succeeded)
    {
        // Update security stamp to invalidate all existing tokens
        await _userManager.UpdateSecurityStampAsync(user);

        _logger.LogInformation("Password reset for user {UserId}", request.UserId);

        return Ok(new
        {
            Message = "Password reset successfully. Please log in with your new password.",
            UserId = request.UserId
        });
    }

    return BadRequest(new
    {
        Message = "Invalid or expired reset token, or password does not meet requirements",
        Errors = result.Errors.Select(e => e.Description)
    });
}

public class ForgotPasswordRequest
{
    public string Email { get; set; } = string.Empty;
}

public class ResetPasswordRequest
{
    public string UserId { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
}
```

### How Token Providers Work

When you call `GenerateEmailConfirmationTokenAsync(user)`, Identity delegates to a token provider registered under the `"EmailConfirmation"` purpose. The default `DataProtectorTokenProvider`:

1. Uses ASP.NET Core Data Protection to encrypt and sign a payload containing:
   - The user's ID
   - The user's security stamp (so the token is invalidated if security changes)
   - The purpose (so tokens for different operations aren't interchangeable)
   - An expiration time
2. Returns the encrypted payload as a string token
3. When `ConfirmEmailAsync(user, token)` is called, the same provider decrypts and validates the payload

### Token Lifetimes

In `Program.cs`:

```csharp
builder.Services.Configure<DataProtectorTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromHours(3);  // Default for most tokens
});

builder.Services.Configure<EmailConfirmationTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromDays(7);  // Email confirmation — longer
});

builder.Services.Configure<PasswordResetTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromHours(1);  // Password reset — shorter
});
```

### Custom Token Provider

```csharp
using Microsoft.AspNetCore.Identity;

namespace IdentityApiTutorial.Services;

public class CustomTotpTokenProvider : IUserTwoFactorTokenProvider<ApplicationUser>
{
    public const string ProviderName = "CustomTotp";

    public Task<bool> CanGenerateTwoFactorTokenAsync(
        UserManager<ApplicationUser> manager,
        ApplicationUser user)
    {
        return Task.FromResult(true);
    }

    public Task<string> GenerateAsync(
        string purpose,
        UserManager<ApplicationUser> manager,
        ApplicationUser user)
    {
        // Generate a 6-digit numeric code
        var random = new Random();
        var token = random.Next(100000, 999999).ToString();

        // In production, store this securely with an expiration time
        // associated with the user and purpose

        return Task.FromResult(token);
    }

    public Task<bool> ValidateAsync(
        string purpose,
        string token,
        UserManager<ApplicationUser> manager,
        ApplicationUser user)
    {
        // Validate the token against stored value
        // This is a simplified example
        return Task.FromResult(
            !string.IsNullOrEmpty(token) && token.Length == 6);
    }
}
```

Register:

```csharp
builder.Services.AddIdentityCore<ApplicationUser>()
    .AddRoles<ApplicationRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders()
    .AddTokenProvider<CustomTotpTokenProvider>(CustomTotpTokenProvider.ProviderName);
```

Use:

```csharp
var token = await _userManager.GenerateUserTokenAsync(
    user, "MyPurpose", CustomTotpTokenProvider.ProviderName);

var isValid = await _userManager.VerifyUserTokenAsync(
    user, "MyPurpose", CustomTotpTokenProvider.ProviderName, token);
```

### Why This Matters

Tokens are the glue between Identity and real-world workflows — email confirmation, password reset, 2FA codes. Understanding how they're generated, what's inside them, how they're validated, and how to configure lifetimes means you can troubleshoot token failures and customize token behavior.

---

## Video 18 — Customizing Identity in API — Custom Stores, Custom SignInManager, JWT Customization

### What We're Building

Deep customization: custom user stores (when EF Core isn't enough), overriding SignInManager for API-specific behavior, and customizing JWT generation (adding custom claims, changing token format).

### Custom User Store

When the default EF Core store isn't enough — e.g., you need to store users in a NoSQL database, or you need custom queries — implement `IUserStore<TUser>` and the relevant interfaces:

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace IdentityApiTutorial.Services;

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

    public Task AddToRoleAsync(
        ApplicationUser user, string roleName,
        CancellationToken cancellationToken)
    {
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
        return Task.CompletedTask;
    }

    public Task<IList<string>> GetRolesAsync(
        ApplicationUser user, CancellationToken cancellationToken)
    {
        return Task.FromResult<IList<string>>(new List<string>());
    }

    public Task<bool> IsInRoleAsync(
        ApplicationUser user, string roleName,
        CancellationToken cancellationToken)
    {
        return Task.FromResult(false);
    }

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

    public void Dispose()
    {
    }
}
```

Register:

```csharp
builder.Services.AddIdentityCore<ApplicationUser>()
    .AddRoles<ApplicationRole>()
    .AddUserStore<CustomUserStore>();  // Use our custom store
```

### Custom SignInManager for API

Override to add API-specific behavior:

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityApiTutorial.Services;

public class ApiSignInManager : SignInManager<ApplicationUser>
{
    private readonly ILogger<ApiSignInManager> _logger;

    public ApiSignInManager(
        UserManager<ApplicationUser> userManager,
        IHttpContextAccessor contextAccessor,
        IUserClaimsPrincipalFactory<ApplicationUser> claimsFactory,
        IOptions<IdentityOptions> optionsAccessor,
        ILogger<ApiSignInManager> logger,
        IAuthenticationSchemeProvider schemes,
        IUserConfirmation<ApplicationUser> confirmation)
        : base(userManager, contextAccessor, claimsFactory,
              optionsAccessor, logger, schemes, confirmation)
    {
        _logger = logger;
    }

    // Override to add custom checks before password validation
    public override async Task<SignInResult> CheckPasswordSignInAsync(
        ApplicationUser user, string password,
        bool lockoutOnFailure)
    {
        // Custom check: account status
        if (!user.IsActive)
        {
            _logger.LogWarning("Login attempt for inactive account: {UserId}", user.Id);
            return SignInResult.NotAllowed;
        }

        // Custom check: subscription expiry
        if (user.SubscriptionTier != null
            && user.SubscriptionExpiresAt.HasValue
            && user.SubscriptionExpiresAt < DateTime.UtcNow
            && user.SubscriptionTier != "Free")
        {
            // Downgrade expired subscription
            user.SubscriptionTier = "Free";
            user.SubscriptionExpiresAt = null;
            await UserManager.UpdateAsync(user);
        }

        return await base.CheckPasswordSignInAsync(user, password, lockoutOnFailure);
    }

    // Override to add custom logic after sign-in
    public override async Task SignInAsync(
        ApplicationUser user, bool isPersistent,
        string? authenticationMethod = null)
    {
        // Update last login time
        user.LastLoginAt = DateTime.UtcNow;
        await UserManager.UpdateAsync(user);

        _logger.LogInformation("User signed in: {UserId} at {Time}",
            user.Id, DateTime.UtcNow);

        await base.SignInAsync(user, isPersistent, authenticationMethod);
    }
}
```

Register:

```csharp
builder.Services.AddScoped<SignInManager<ApplicationUser>, ApiSignInManager>();
```

### Custom JWT Generation — Adding More Claims

Modify the `GenerateJwtToken` method from Video 08 to include more claims:

```csharp
private TokenResponse GenerateJwtToken(ApplicationUser user)
{
    var roles = _userManager.GetRolesAsync(user).Result;

    var claims = new List<Claim>
    {
        new(JwtRegisteredClaimNames.Sub, user.Id),
        new(JwtRegisteredClaimNames.Email, user.Email ?? ""),
        new(JwtRegisteredClaimNames.UniqueName, user.UserName ?? ""),
        new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new(JwtRegisteredClaimNames.Iat,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
            ClaimValueTypes.Integer64),

        // Custom claims
        new("userId", user.Id),
        new("userName", user.UserName ?? ""),
        new("firstName", user.FirstName ?? ""),
        new("lastName", user.LastName ?? ""),
        new("fullName", user.FullName ?? ""),
        new("emailConfirmed", user.EmailConfirmed.ToString().ToLowerInvariant()),
        new("isActive", user.IsActive.ToString().ToLowerInvariant()),
        new("subscriptionTier", user.SubscriptionTier ?? "Free"),
        new("createdAt", user.CreatedAt.ToString("O")),
        new("lastLoginAt", user.LastLoginAt?.ToString("O") ?? ""),
        new("securityStamp", user.SecurityStamp ?? ""),

        // Role claims
        new(ClaimTypes.Role, roles.ToArray())
    };

    // Add individual role claims (alternative to array claim)
    foreach (var role in roles)
    {
        claims.Add(new Claim(ClaimTypes.Role, role));
    }

    // Add user claims from the database
    var userClaims = _userManager.GetClaimsAsync(user).Result;
    foreach (var claim in userClaims)
    {
        claims.Add(new Claim(claim.Type, claim.Value));
    }

    var key = new SymmetricSecurityKey(
        Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
    var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(claims),
        Expires = DateTime.UtcNow.AddHours(1),
        Issuer = _configuration["Jwt:Issuer"]!,
        Audience = _configuration["Jwt:Audience"]!,
        SigningCredentials = credentials
    };

    var tokenHandler = new JwtSecurityTokenHandler();
    var securityToken = tokenHandler.CreateToken(tokenDescriptor);
    var jwtToken = tokenHandler.WriteToken(securityToken);

    return new TokenResponse
    {
        Token = jwtToken,
        TokenType = "Bearer",
        ExpiresIn = 3600,
        ExpiresAt = DateTime.UtcNow.AddHours(1),
        UserId = user.Id,
        UserName = user.UserName,
        Email = user.Email,
        Roles = roles
    };
}
```

### Why This Matters

Most APIs never need custom stores or SignInManager overrides. But when you do — because you're using a non-relational database, have complex sign-in rules, or need to customize JWT claims — knowing how to implement these correctly is essential. This video shows the full pattern.

---

## Video 19 — Production-Ready API Security — Best Practices, Audit Logging, Troubleshooting

### What We're Building

Taking the API from development to production: secure JWT handling, strong password policies, audit logging endpoints, rate limiting considerations, and a troubleshooting guide for common API errors.

### Production Configuration

In `Program.cs`:

```csharp
builder.Services.AddIdentityCore<ApplicationUser>(options =>
{
    // Strong password requirements for production
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
.AddRoles<ApplicationRole>()
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();
```

**JWT configuration for production:**

```csharp
// Use environment variables or a secrets manager for these values
var jwtKey = builder.Configuration["Jwt:Key"]!;
var jwtIssuer = builder.Configuration["Jwt:Issuer"]!;
var jwtAudience = builder.Configuration["Jwt:Audience"]!;

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
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
        ClockSkew = TimeSpan.Zero  // Strict validation for short-lived tokens
    };

    // events for logging (as shown in Video 14)
});
```

**Key management:**
- Never commit JWT keys to source control
- Use environment variables, Azure Key Vault, AWS Secrets Manager, or similar
- Rotate keys periodically (requires a strategy for validating tokens signed with old keys)
- Use a key at least 32 characters for HS256 (256-bit)

### Audit Logging

Track security-relevant events:

```csharp
using Microsoft.EntityFrameworkCore;

namespace IdentityApiTutorial.Models;

public class AuditLog
{
    public int Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;  // LOGIN, LOGIN_FAILED, PASSWORD_CHANGE, TOKEN_REVOKED, etc.
    public string Description { get; set; } = string.Empty;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? UserAgentRaw { get; set; }
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

    public async Task<IEnumerable<AuditLog>> GetRecentAsync(string userId, int count = 50)
    {
        return await _context.AuditLogs
            .Where(a => a.UserId == userId)
            .OrderByDescending(a => a.Timestamp)
            .Take(count)
            .ToListAsync();
    }
}
```

Add to `ApplicationDbContext`:

```csharp
public DbSet<AuditLog> AuditLogs { get; set; }
```

Register:

```csharp
builder.Services.AddScoped<AuditLogService>();
```

Use in controllers:

```csharp
// After successful login
await _auditLogService.LogAsync(
    user.Id, "LOGIN", "User logged in successfully",
    HttpContext.Connection.RemoteIpAddress?.ToString(),
    Request.Headers.UserAgent.ToString());

// After failed login
await _auditLogService.LogAsync(
    user?.Id ?? "UNKNOWN", "LOGIN_FAILED",
    $"Failed login attempt for {request.Email}",
    HttpContext.Connection.RemoteIpAddress?.ToString(),
    Request.Headers.UserAgent.ToString());

// After password change
await _auditLogService.LogAsync(
    user.Id, "PASSWORD_CHANGE", "Password was changed",
    HttpContext.Connection.RemoteIpAddress?.ToString(),
    Request.Headers.UserAgent.ToString());

// After token revocation
await _auditLogService.LogAsync(
    user.Id, "TOKEN_REVOKED", "All tokens revoked (security stamp updated)",
    HttpContext.Connection.RemoteIpAddress?.ToString(),
    Request.Headers.UserAgent.ToString());
```

### Audit Log Endpoint

```csharp
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class AuditLogController : ControllerBase
{
    private readonly AuditLogService _auditLogService;

    public AuditLogController(AuditLogService auditLogService)
    {
        _auditLogService = auditLogService;
    }

    /// <summary>
    /// GET /api/auditlog/me
    /// Get recent audit logs for the current user.
    /// </summary>
    [HttpGet("me")]
    public async Task<IActionResult> GetMyAuditLogs([FromQuery] int count = 50)
    {
        var userId = User.FindFirstValue("userId")
                     ?? User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (userId == null)
        {
            return Unauthorized();
        }

        var logs = await _auditLogService.GetRecentAsync(userId, count);

        return Ok(new
        {
            UserId = userId,
            Count = logs.Count(),
            Logs = logs.Select(l => new
            {
                l.Id,
                l.Action,
                l.Description,
                l.Timestamp,
                l.IpAddress
            })
        });
    }
}
```

### Rate Limiting Considerations

Identity endpoints (login, register, password reset) are targets for brute force and enumeration attacks. Consider:

1. **ASP.NET Core Rate Limiting** (built-in in .NET 7+):
```csharp
builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = new FixedWindowRateLimiterOptions
    {
        Window = TimeSpan.FromMinutes(1),
        PermitLimit = 100,
        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
        QueueLimit = 0
    };

    // Specific limits for authentication endpoints
    options.AddPolicy("login", httpContext =>
        new FixedWindowRateLimiterOptions
        {
            Window = TimeSpan.FromMinutes(1),
            PermitLimit = 10,  // 10 login attempts per minute per IP
            QueueLimit = 0
        });
});

// Apply in Program.cs:
app.UseRateLimiter();

// On login endpoint:
[HttpPost("login")]
[EnableRateLimiting("login")]
public async Task<IActionResult> Login(...) { ... }
```

2. **IP-based lockout** — Identity's lockout is per-user. For additional protection, implement IP-based rate limiting to prevent an attacker from trying many passwords across many accounts.

3. **CAPTCHA** — on registration and login endpoints, consider requiring a CAPTCHA to prevent automated attacks.

### Common API Errors and Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `401 Unauthorized` on protected endpoint | JWT missing, expired, or invalid | Check Authorization header format (`Bearer <token>`), token expiry, JWT configuration |
| `401` with "Invalid issuer" | JWT issuer doesn't match `ValidIssuer` in `TokenValidationParameters` | Ensure JWT issuer in token generation matches the validation config |
| `401` with "Invalid signature" | JWT key doesn't match or token was tampered with | Verify the same key is used for signing and validation; check key encoding |
| `403 Forbidden` on role-protected endpoint | User doesn't have the required role in their JWT | Check roles in JWT claims; user may need to log in again after role change |
| `[Authorize]` not working at all | `UseAuthentication()` missing or wrong order | Ensure `app.UseAuthentication()` is called before `app.UseAuthorization()` |
| `AddToRoleAsync` fails with "Role does not exist" | Role not seeded or not created yet | Ensure roles are seeded in the database before assigning them |
| `FindByEmailAsync` returns null for existing user | Email case mismatch or NormalizedEmail not set | Identity stores NormalizedEmail uppercase; lookups are case-insensitive by design |
| Token works locally but not in production | Clock skew, different issuer/audience, or HTTPS/HTTP mismatch | Check all JWT config values; ensure ClockSkew is appropriate; verify HTTPS |
| `GenerateJwtToken` throws "Key not configured" | `Jwt:Key` missing from configuration | Verify `appsettings.json` or environment variables have the JWT settings |
| Lockout not triggering | `lockoutOnFailure: false` in `CheckPasswordSignInAsync` | Set to `true`; verify `LockoutEnabled` is true on the user |
| 2FA verification fails | Code timing issue (TOTP codes are time-sensitive) | Ensure server clock is synchronized; verify the authenticator app's time is correct |
| External login callback returns "info null" | OAuth middleware not configured or callback path mismatch | Verify provider configuration, callback path, and that the OAuth flow completed |

### Debugging Tips

```csharp
// Enable detailed errors in development
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Log JWT validation events
builder.Services.AddAuthentication(options =>
{
    // ...
})
.AddJwtBearer(options =>
{
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            var logger = context.HttpContext.RequestServices
                .GetRequiredService<ILogger<Program>>();
            logger.LogWarning("JWT authentication failed: {Error}",
                context.Exception.Message);
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            var logger = context.HttpContext.RequestServices
                .GetRequiredService<ILogger<Program>>();
            var userId = context.Principal?.FindFirstValue("userId");
            logger.LogInformation("Token validated for user: {UserId}", userId ?? "unknown");
            return Task.CompletedTask;
        }
    };
});
```

### Why This Matters

What works in development isn't secure enough for production. This video closes the series with hardening steps: secure JWT handling, strong password policies, audit logging for security events, rate limiting considerations, and a practical troubleshooting guide for the errors every Identity API developer encounters.

---

## Series Summary

| Video | Topic | Key API Takeaway |
|-------|-------|------------------|
| 01 | What is Identity in an API | Identity for user management + JWT for transport; when to use vs alternatives |
| 02 | Architecture | UserManager, SignInManager, stores, JWT flow, AddIdentityCore vs AddIdentity |
| 03 | Project setup | `dotnet new webapi`, NuGet packages, project structure |
| 04 | Configuration | AddIdentityCore + JWT bearer + authorization + middleware order |
| 05 | Models | Custom ApplicationUser/ApplicationRole, what to include in an API |
| 06 | Database | IdentityDbContext, connection strings, migrations, schema, seed roles |
| 07 | Registration API | POST /api/account/register — validation, create, role assign, return JSON |
| 08 | Login API | POST /api/account/login — CheckPasswordSignInAsync, JWT generation, token response |
| 09 | Role management API | CRUD roles, assign/remove user roles, role claims — all JSON endpoints |
| 10 | RBAC in API | [Authorize(Roles)], AND/OR semantics, programmatic checks, permission system |
| 11 | Claims in API | Add/remove claims, claim policies, reading claims from JWT, re-issuing tokens |
| 12 | Policy-based authorization | Custom requirements, handlers, resource-based authorization with JWT |
| 13 | Password policies | PasswordOptions, custom IPasswordValidator, password strength endpoint |
| 14 | Lockout & security stamp | Lockout endpoints, security stamp in JWT, token revocation |
| 15 | 2FA API | Enable 2FA, verify TOTP, recovery codes, 2FA login flow with JWT |
| 16 | External login providers | OAuth callbacks, issue JWT for external users, link/unlink logins |
| 17 | Token providers | Email confirmation endpoint, password reset endpoint, custom token providers |
| 18 | Customization | Custom user store, custom SignInManager, JWT customization |
| 19 | Production security | Secure config, audit logging, rate limiting, troubleshooting common API errors |

---

## Quick Reference — Endpoints Checklist

### AccountController
| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| POST | `/api/account/register` | No | Register a new user |
| POST | `/api/account/login` | No | Login and get JWT |
| POST | `/api/account/verify-2fa` | No | Complete login after 2FA |
| POST | `/api/account/logout` | Yes | Logout (client-side token discard) |
| POST | `/api/account/confirm-email` | No | Confirm email with token |
| POST | `/api/account/resend-confirmation-email` | No | Resend confirmation token |
| POST | `/api/account/forgot-password` | No | Initiate password reset |
| POST | `/api/account/reset-password` | No | Reset password with token |
| GET | `/api/account/me` | Yes | Get current user info |
| GET | `/api/account/external-login-callback` | No | External login OAuth callback |
| GET | `/api/account/external-logins` | Yes | Get linked external logins |
| POST | `/api/account/external-logins/unlink` | Yes | Unlink an external login |
| POST | `/api/account/users/{userId}/revoke-tokens` | Yes (self or admin) | Revoke all tokens for a user |

### RoleManagementController
| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| GET | `/api/rolemanagement` | Admin | List all roles |
| GET | `/api/rolemanagement/{id}` | Admin | Get role with users and claims |
| POST | `/api/rolemanagement` | Admin | Create a role |
| PUT | `/api/rolemanagement/{id}` | Admin | Update a role |
| DELETE | `/api/rolemanagement/{id}` | Admin | Delete a role |
| POST | `/api/rolemanagement/{id}/claims` | Admin | Add claim to role |
| DELETE | `/api/rolemanagement/{id}/claims` | Admin | Remove claim from role |

### UserRoleManagementController
| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| GET | `/api/userrolemanagement/users/{userId}/roles` | Admin | Get user's roles |
| POST | `/api/userrolemanagement/users/{userId}/roles` | Admin | Assign role to user |
| DELETE | `/api/userrolemanagement/users/{userId}/roles/{roleId}` | Admin | Remove role from user |

### TwoFactorController
| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| POST | `/api/twofactor/enable` | Yes | Get authenticator key and QR URI |
| POST | `/api/twofactor/verify` | Yes | Verify TOTP code and enable 2FA |
| POST | `/api/twofactor/disable` | Yes | Disable 2FA |
| GET | `/api/twofactor/status` | Yes | Check 2FA status |

### PasswordController
| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| POST | `/api/password/check-strength` | No | Check password strength |

### LockoutManagementController
| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| GET | `/api/lockoutmanagement/users/{userId}/status` | Admin | Get lockout status |
| POST | `/api/lockoutmanagement/users/{userId}/lock` | Admin | Lock user account |
| POST | `/api/lockoutmanagement/users/{userId}/unlock` | Admin | Unlock user account |

### UserClaimsController
| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| GET | `/api/userclaims/{userId}` | Admin | Get user's claims |
| POST | `/api/userclaims/{userId}` | Admin | Add claim to user |
| DELETE | `/api/userclaims/{userId}` | Admin | Remove claim from user |

### AuditLogController
| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| GET | `/api/auditlog/me` | Yes | Get current user's audit logs |

### SampleProtectedController (examples)
| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| GET | `/api/sampleprotected/admin-only` | Admin | Role-based protection example |
| GET | `/api/sampleprotected/admin-or-manager` | Admin or Manager | OR semantics example |
| GET | `/api/sampleprotected/authenticated` | Any authenticated | Authentication-only example |
| GET | `/api/sampleprotected/public` | No | Public endpoint example |
| GET | `/api/sampleprotected/admin-and-manager` | Admin AND Manager | AND semantics example |

### PolicyProtectedController (examples)
| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| GET | `/api/policyprotected/adult-content` | AtLeast18 policy | Age verification example |
| GET | `/api/policyprotected/premium-content` | PremiumOrEnterprise policy | Subscription tier example |
| GET | `/api/policyprotected/business-hours` | BusinessHoursOnly policy | Time-based example |
| GET | `/api/policyprotected/admin-business-hours` | AdminDuringBusinessHours policy | Combined policy example |
| GET | `/api/policyprotected/edit-content` | CanEditContent policy | Assertion policy example |

### DocumentsController (resource-based auth example)
| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| GET | `/api/documents/{id}` | Yes + ReadDocument policy | Read document with resource check |
| PUT | `/api/documents/{id}` | Yes + EditDocument policy | Edit document with resource check |

---

## Quick Reference — Postman Collection Structure

```
Identity API Tutorial
├── Authentication
│   ├── Register (POST /api/account/register)
│   ├── Login (POST /api/account/login)
│   ├── Verify 2FA (POST /api/account/verify-2fa)
│   ├── Logout (POST /api/account/logout)
│   ├── Get Me (GET /api/account/me)
│   ├── Confirm Email (POST /api/account/confirm-email)
│   ├── Forgot Password (POST /api/account/forgot-password)
│   └── Reset Password (POST /api/account/reset-password)
├── Roles
│   ├── List Roles (GET /api/rolemanagement)
│   ├── Create Role (POST /api/rolemanagement)
│   ├── Update Role (PUT /api/rolemanagement/{id})
│   ├── Delete Role (DELETE /api/rolemanagement/{id})
│   ├── Assign Role to User (POST /api/userrolemanagement/users/{id}/roles)
│   └── Remove Role from User (DELETE /api/userrolemanagement/users/{id}/roles/{rid})
├── Two-Factor Authentication
│   ├── Enable 2FA (POST /api/twofactor/enable)
│   ├── Verify 2FA (POST /api/twofactor/verify)
│   ├── Disable 2FA (POST /api/twofactor/disable)
│   └── Check Status (GET /api/twofactor/status)
├── Password
│   └── Check Strength (POST /api/password/check-strength)
├── Claims
│   ├── Get User Claims (GET /api/userclaims/{id})
│   ├── Add Claim (POST /api/userclaims/{id})
│   └── Remove Claim (DELETE /api/userclaims/{id})
├── Lockout
│   ├── Get Status (GET /api/lockoutmanagement/users/{id}/status)
│   ├── Lock User (POST /api/lockoutmanagement/users/{id}/lock)
│   └── Unlock User (POST /api/lockoutmanagement/users/{id}/unlock)
└── Audit
    └── Get My Logs (GET /api/auditlog/me)
```

---

## Quick Reference — JWT Claims Included by Default

| Claim | Source | Description |
|-------|--------|-------------|
| `sub` (JwtRegisteredClaimNames.Sub) | User ID | Subject — the user identifier |
| `email` (JwtRegisteredClaimNames.Email) | User.Email | User's email |
| `unique_name` (JwtRegisteredClaimNames.UniqueName) | User.UserName | Username |
| `jti` (JwtRegisteredClaimNames.Jti) | Generated GUID | Unique token ID |
| `iat` (JwtRegisteredClaimNames.Iat) | Current UTC time | Issued at |
| `userId` | Custom | User ID (duplicate of sub for convenience) |
| `userName` | Custom | Username |
| `firstName` | Custom | First name |
| `lastName` | Custom | Last name |
| `fullName` | Custom | First + Last name |
| `emailConfirmed` | Custom | Email confirmation status |
| `isActive` | Custom | Account active status |
| `subscriptionTier` | Custom | Subscription tier |
| `createdAt` | Custom | Account creation time |
| `lastLoginAt` | Custom | Last login time |
| `securityStamp` | Custom | Security stamp (for revocation checking) |
| `role` / `roles` (ClaimTypes.Role) | UserManager.GetRolesAsync | User's roles |

---

*the single resource for .NET Identity in .NET API — build along, test with Postman, and reference anytime.*
