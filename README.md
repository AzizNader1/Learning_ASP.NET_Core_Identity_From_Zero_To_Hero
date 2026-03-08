# Master ASP.NET Core Identity: Complete A to Z Guide

> **From Zero to Hero: Complete Guide to Identity, Role-Based Access Control, and Security in .NET**

---

## Table of Contents

1. [Introduction to ASP.NET Core Identity](#1-introduction-to-aspnet-core-identity)
2. [Identity Architecture Deep Dive](#2-identity-architecture-deep-dive)
3. [Project Setup and Installation](#3-project-setup-and-installation)
4. [Configuring Identity Services](#4-configuring-identity-services)
5. [Understanding Identity Models](#5-understanding-identity-models)
6. [Database Configuration with Entity Framework Core](#6-database-configuration-with-entity-framework-core)
7. [User Registration and Management](#7-user-registration-and-management)
8. [User Authentication (Login/Logout)](#8-user-authentication-loginlogout)
9. [Role Management with IdentityRole](#9-role-management-with-identityrole)
10. [Role-Based Access Control (RBAC)](#10-role-based-access-control-rbac)
11. [Claims-Based Authorization](#11-claims-based-authorization)
12. [Policy-Based Authorization](#12-policy-based-authorization)
13. [Password Policies and Validation](#13-password-policies-and-validation)
14. [Account Lockout and Security Features](#14-account-lockout-and-security-features)
15. [Two-Factor Authentication (2FA)](#15-two-factor-authentication-2fa)
16. [External Authentication Providers](#16-external-authentication-providers)
17. [Token Providers and Usage](#17-token-providers-and-usage)
18. [Customizing Identity](#18-customizing-identity)
19. [Best Practices and Security](#19-best-practices-and-security)
20. [Troubleshooting Common Issues](#20-troubleshooting-common-issues)

---

## 1. Introduction to ASP.NET Core Identity

### What is ASP.NET Core Identity?

ASP.NET Core Identity is a membership system that adds login functionality to ASP.NET Core applications. It provides a comprehensive, extensible framework for managing users, passwords, profile data, roles, claims, tokens, email confirmation, and more. Identity is built on top of ASP.NET Core's abstraction layer and integrates seamlessly with Entity Framework Core for data persistence, making it the de facto standard for authentication and authorization in .NET web applications.

Unlike custom authentication implementations that require you to build everything from scratch, Identity provides a battle-tested, security-hardened foundation that handles the complexities of modern authentication. It implements industry-standard security practices including password hashing using PBKDF2 with HMAC-SHA256, account lockout after failed attempts, support for two-factor authentication, and protection against common attacks like brute force and session hijacking. Microsoft maintains and updates Identity regularly to address new security vulnerabilities and follow evolving best practices.

The framework is designed with extensibility in mind. While it works excellently out of the box for typical scenarios, virtually every component can be customized or replaced. You can extend the user model with custom properties, implement custom password validators, use different storage mechanisms, integrate with external login providers like Google and Facebook, and implement custom token providers. This flexibility makes Identity suitable for applications ranging from simple websites to complex enterprise systems with sophisticated security requirements.

### Why Use Identity Instead of Custom Solutions?

Building a custom authentication system might seem straightforward at first—after all, validating a username and password against a database isn't complicated. However, authentication systems have a tendency to grow in complexity as security requirements evolve. Passwords must be properly hashed using cryptographically secure algorithms. Account lockout mechanisms must prevent brute force attacks while avoiding denial-of-service vulnerabilities. Email confirmation workflows require token generation and validation. Password reset functionality must be secure against various attack vectors. Two-factor authentication adds another layer of complexity. Each of these features, implemented incorrectly, can create security vulnerabilities that compromise your entire application.

Identity handles all these concerns out of the box, following security best practices that have been refined over years of real-world use. When you use Identity, you benefit from Microsoft's investment in security research and the collective experience of thousands of developers who have used and tested the framework. Security vulnerabilities are identified and patched through regular updates, which is far easier than maintaining your own authentication codebase where you're solely responsible for identifying and fixing security issues.

Furthermore, Identity integrates deeply with the ASP.NET Core ecosystem. It works seamlessly with the authorization system, enabling the `[Authorize]` attribute, role-based access control, and policy-based authorization. It integrates with ASP.NET Core's cookie middleware for session management or can be combined with JWT for API authentication. This integration means less glue code to write and fewer places where things can go wrong. The consistency across ASP.NET Core applications also means that developers familiar with Identity can quickly understand and contribute to any project using it.

### Identity vs. IdentityServer vs. Duende

It's important to understand the differences between related technologies in the .NET authentication ecosystem. ASP.NET Core Identity is designed for single-application authentication—it manages users and authenticates them within your application. IdentityServer (now Duende IdentityServer) is a different product designed for implementing OAuth 2.0 and OpenID Connect protocols, enabling single sign-on scenarios and federated authentication across multiple applications.

For most applications where users log in directly to your application, ASP.NET Core Identity is the appropriate choice. It's simpler to implement and maintain than running a separate identity provider. If you need single sign-on across multiple applications, or if you need to expose authentication as a service for third-party applications, then Duende IdentityServer becomes relevant. Many architectures use both: IdentityServer as the central identity provider, with ASP.NET Core Identity managing the user database that IdentityServer uses.

For this tutorial, we focus on ASP.NET Core Identity for direct authentication scenarios. The concepts you learn here—users, roles, claims, and authorization—also apply when working with IdentityServer, so this knowledge transfers well if you eventually need more complex authentication architectures.

---

## 2. Identity Architecture Deep Dive

### Core Components of Identity

ASP.NET Core Identity is built around several core types that work together to provide authentication and authorization functionality. Understanding these types and their relationships is essential for effectively using and customizing Identity. The primary types include `IdentityUser`, `IdentityRole`, `UserManager`, `RoleManager`, `SignInManager`, and the stores that persist data.

`IdentityUser` is the base class representing a user in the system. It contains properties like Id, UserName, NormalizedUserName, Email, NormalizedEmail, EmailConfirmed, PasswordHash, SecurityStamp, ConcurrencyStamp, PhoneNumber, PhoneNumberConfirmed, TwoFactorEnabled, LockoutEnd, LockoutEnabled, and AccessFailedCount. The normalized versions of UserName and Email are used for case-insensitive lookups, which is important for user experience—users expect that "John@example.com" and "john@example.com" refer to the same account.

`IdentityRole` represents a role that can be assigned to users. Like IdentityUser, it has Id, Name, NormalizedName, and ConcurrencyStamp properties. Roles are used for role-based authorization, where access to resources is granted based on the roles a user has. A user can have multiple roles, and roles can have associated claims that apply to all users in that role.

### Managers: UserManager, RoleManager, and SignInManager

The manager classes provide the business logic for working with Identity entities. `UserManager<TUser>` is perhaps the most commonly used, providing methods for creating, updating, deleting, and finding users, as well as managing passwords, roles, claims, and tokens. When you need to create a new user, validate a password, add a user to a role, or generate an email confirmation token, you use UserManager.

`RoleManager<TRole>` manages roles—creating, updating, deleting, and finding roles, as well as managing role claims. While you might have fewer roles than users and interact with RoleManager less frequently, it's essential for dynamic role management scenarios where roles can be created and modified at runtime rather than being hardcoded.

`SignInManager<TUser>` handles the actual sign-in process. It provides methods like `PasswordSignInAsync` (validates credentials and creates the authentication cookie), `SignOutAsync` (removes the authentication cookie), and `IsSignedIn` (checks if the current request is authenticated). SignInManager bridges between UserManager's user management capabilities and the HTTP context where authentication state is represented as claims principals.

### Stores and Persistence

Identity uses a store pattern to abstract data persistence. The `IUserStore<TUser>` interface defines the contract for persisting user data, with additional interfaces like `IUserPasswordStore`, `IUserEmailStore`, `IUserRoleStore`, and `IUserClaimStore` extending functionality for specific features. Entity Framework Core provides implementations of these interfaces through `UserStore<TUser, TRole, TContext>`, but the abstraction means you could implement custom stores using other databases or storage mechanisms.

The store abstraction is powerful because it allows Identity to work with any persistence mechanism while presenting a consistent API through the manager classes. When you call `UserManager.CreateAsync`, internally it calls the appropriate methods on the configured store implementations. This separation of concerns means that business logic in managers is decoupled from data access in stores, making the system more testable and flexible.

### IdentityDbContext

For Entity Framework Core integration, Identity provides `IdentityDbContext`, which is a specialized DbContext that includes DbSet properties for users, roles, and all the junction tables (user roles, user claims, role claims, and user tokens). This context also configures the entity mappings using the Fluent API, setting up appropriate table names, column types, indexes, and relationships.

You typically create your own application DbContext that inherits from `IdentityDbContext` (or one of its generic variants) and adds your application-specific entities. This approach allows Identity to manage its schema while you manage your application data in the same database context, enabling transactions that span both Identity and application data.

---

## 3. Project Setup and Installation

### Creating a New Project with Identity

The simplest way to create a project with Identity is using the .NET CLI templates. ASP.NET Core provides templates that include Identity pre-configured with either individual user accounts (stored locally) or cloud-based authentication (Azure AD, etc.). For most applications, the individual authentication template provides the best starting point.

```bash
# Create a new MVC project with Identity
dotnet new mvc -n IdentityDemo --auth Individual

# Or create a Web API project (Identity for API)
dotnet new webapi -n IdentityApiDemo --auth Individual

# Navigate to the project
cd IdentityDemo
```

The `--auth Individual` parameter configures the project with ASP.NET Core Identity for local user accounts. This template creates a project with Identity already set up, including the DbContext, user and role entities, and UI for login and registration. For MVC projects, it includes Razor Pages for account management; for API projects, you'll need to create your own authentication endpoints.

### Adding Identity to an Existing Project

If you have an existing project and want to add Identity, you'll need to install the necessary NuGet packages and configure the services manually. This approach gives you more control over the configuration and is useful for understanding how Identity works under the hood.

```bash
# Core Identity package
dotnet add package Microsoft.AspNetCore.Identity

# Entity Framework Core integration
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore

# SQL Server provider for EF Core
dotnet add package Microsoft.EntityFrameworkCore.SqlServer

# EF Core tools for migrations
dotnet add package Microsoft.EntityFrameworkCore.Tools
```

The `Microsoft.AspNetCore.Identity` package contains the core types like UserManager, SignInManager, and the base entity classes. The `Microsoft.AspNetCore.Identity.EntityFrameworkCore` package provides Entity Framework Core integration, including IdentityDbContext and the store implementations. You'll also need a database provider package—Microsoft.EntityFrameworkCore.SqlServer for SQL Server, or another provider for PostgreSQL, SQLite, MySQL, etc.

### Project Structure After Adding Identity

Once Identity is added, your project will have several new components. You'll have a DbContext class that inherits from IdentityDbContext, a User class that inherits from IdentityUser (and optionally a Role class inheriting from IdentityRole), and configuration in Program.cs that registers Identity services and middleware. The Areas folder typically contains Identity-related Razor Pages if you're using the default UI.

Understanding the generated code is important for customization. The Program.cs file will contain Identity service registration, including configuring password requirements, lockout settings, and token providers. The DbContext will have DbSet properties for users and roles, and the OnModelCreating method might contain additional configuration. The User class can be extended with custom properties that become part of your user profiles.

---

## 4. Configuring Identity Services

### Basic Identity Configuration

Identity is configured in Program.cs (for .NET 6 and later) through the `AddIdentity` or `AddIdentityCore` extension methods. The full `AddIdentity` method configures both authentication cookies and all Identity features, while `AddIdentityCore` configures only the user management services without cookie authentication—useful for APIs that use JWT.

Here's a complete Program.cs configuration for Identity with MVC:

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using IdentityDemo.Data;
using IdentityDemo.Models;

var builder = WebApplication.CreateBuilder(args);

// Configure Entity Framework Core with SQL Server
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection")));

// Configure Identity services
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 8;
    options.Password.RequiredUniqueChars = 1;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // User settings
    options.User.AllowedUserNameCharacters = 
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.User.RequireUniqueEmail = true;

    // Sign-in settings
    options.SignIn.RequireConfirmedEmail = true;
    options.SignIn.RequireConfirmedPhoneNumber = false;
    options.SignIn.RequireConfirmedAccount = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Configure cookie settings
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.LoginPath = "/Identity/Account/Login";
    options.LogoutPath = "/Identity/Account/Logout";
    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
    options.SlidingExpiration = true;
});

// Add MVC services
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

var app = builder.Build();

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Authentication must come before Authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();
```

### Identity Options Explained

The `IdentityOptions` class contains all configurable settings for Identity behavior. Let's examine each category in detail:

**Password Options** control password requirements. The default settings are reasonably secure, requiring at least six characters with some complexity requirements. For higher security applications, you might increase `RequiredLength` to 12 or more characters and enable all complexity requirements. However, be aware that overly strict password policies can frustrate users and sometimes lead to less secure behavior (like writing passwords down). Modern guidance favors longer passphrases over complex but short passwords.

**Lockout Options** protect against brute force attacks. `DefaultLockoutTimeSpan` determines how long an account is locked after the maximum failed attempts. `MaxFailedAccessAttempts` sets the threshold for lockout. `AllowedForNewUsers` determines whether new accounts are subject to lockout—typically this should be true. Lockout is applied per-user, not per-IP address, so a determined attacker could still try common passwords across many different accounts. Consider implementing IP-based rate limiting as a defense-in-depth measure.

**User Options** control username and email handling. `AllowedUserNameCharacters` specifies which characters are permitted in usernames. `RequireUniqueEmail` ensures no two users can have the same email address, which is important for email-based account recovery and communication. If you use email as the primary identifier, this setting should always be true.

**Sign-In Options** control sign-in requirements. `RequireConfirmedEmail` requires users to confirm their email before signing in. `RequireConfirmedPhoneNumber` requires phone confirmation. `RequireConfirmedAccount` is a convenience property that can be used by your application logic to check if an account is fully set up. These settings help ensure that users have provided valid contact information, which is important for account recovery scenarios.

### Token Provider Configuration

Identity uses token providers for various security-sensitive operations: email confirmation, password reset, two-factor authentication, and change email/phone number. The default token providers use the Data Protection API to generate tokens that are validated based on the user's security stamp.

```csharp
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Token lifespans
    options.Tokens.EmailConfirmationTokenProvider = "EmailConfirmation";
    options.Tokens.PasswordResetTokenProvider = "PasswordReset";
    options.Tokens.ProviderMap = new Dictionary<string, TokenProviderDescriptor>
    {
        ["EmailConfirmation"] = new TokenProviderDescriptor(
            typeof(DataProtectorTokenProvider<ApplicationUser>)),
        ["PasswordReset"] = new TokenProviderDescriptor(
            typeof(DataProtectorTokenProvider<ApplicationUser>))
    };
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();
```

You can customize token lifespans by configuring the token provider options:

```csharp
builder.Services.Configure<DataProtectorTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromHours(3);
});

builder.Services.Configure<EmailConfirmationTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromDays(7);
});
```

### Configuring Identity for API Scenarios

For APIs that use JWT tokens instead of cookies, use `AddIdentityCore` and configure JWT bearer authentication separately:

```csharp
// Add Identity core services (without cookie authentication)
builder.Services.AddIdentityCore<ApplicationUser>(options =>
{
    // Configure options as shown above
})
.AddRoles<IdentityRole>()
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Add authentication services
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
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!))
    };
});

// Add authorization services
builder.Services.AddAuthorization();
```

---

## 5. Understanding Identity Models

### The IdentityUser Class

The `IdentityUser` class is the base entity for users in Identity. It contains all the standard properties needed for authentication and account management. When you create your own user class, you inherit from `IdentityUser` and can add custom properties for your application's needs.

```csharp
// The IdentityUser base class (simplified representation)
public class IdentityUser : IdentityUser<string>
{
    public IdentityUser() : base()
    {
        Id = Guid.NewGuid().ToString();
        SecurityStamp = Guid.NewGuid().ToString();
    }
}

public class IdentityUser<TKey> where TKey : IEquatable<TKey>
{
    public virtual TKey Id { get; set; }
    public virtual string? UserName { get; set; }
    public virtual string? NormalizedUserName { get; set; }
    public virtual string? Email { get; set; }
    public virtual string? NormalizedEmail { get; set; }
    public virtual bool EmailConfirmed { get; set; }
    public virtual string? PasswordHash { get; set; }
    public virtual string? SecurityStamp { get; set; }
    public virtual string? ConcurrencyStamp { get; set; }
    public virtual string? PhoneNumber { get; set; }
    public virtual bool PhoneNumberConfirmed { get; set; }
    public virtual bool TwoFactorEnabled { get; set; }
    public virtual DateTimeOffset? LockoutEnd { get; set; }
    public virtual bool LockoutEnabled { get; set; }
    public virtual int AccessFailedCount { get; set; }
}
```

Each property serves a specific purpose. The `Id` is the primary key—by default a string containing a GUID, but you can use integers or other types. `NormalizedUserName` and `NormalizedEmail` store uppercase versions for case-insensitive lookups. `SecurityStamp` changes when the user's security state changes (password change, role changes, etc.), invalidating any tokens generated before the change. `ConcurrencyStamp` is used for optimistic concurrency control, preventing concurrent updates from overwriting each other.

### Creating a Custom User Class

Most applications need to store additional user information beyond what IdentityUser provides—first name, last name, profile picture, preferences, and so on. Create a custom user class that inherits from `IdentityUser` and adds your properties:

```csharp
using Microsoft.AspNetCore.Identity;

namespace IdentityDemo.Models
{
    public class ApplicationUser : IdentityUser
    {
        // Personal Information
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? DisplayName { get; set; }
        public string? ProfilePictureUrl { get; set; }
        public DateTime? DateOfBirth { get; set; }
        
        // Contact Information
        public string? Address { get; set; }
        public string? City { get; set; }
        public string? Country { get; set; }
        public string? PostalCode { get; set; }
        
        // Account Information
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastLoginAt { get; set; }
        public bool IsPremium { get; set; }
        public string? TimeZone { get; set; }
        public string? Language { get; set; }
        
        // Navigation properties for relationships
        public virtual ICollection<UserRole> UserRoles { get; set; }
        public virtual ICollection<IdentityUserClaim<string>> Claims { get; set; }
        public virtual ICollection<IdentityUserLogin<string>> Logins { get; set; }
        public virtual ICollection<IdentityUserToken<string>> Tokens { get; set; }
    }
}
```

The navigation properties allow Entity Framework Core to load related data—roles, claims, external logins, and tokens. These are optional but useful if you frequently query related data. Note that if you use a different key type (like `int` instead of `string`), you need to change the generic types in the navigation properties accordingly.

### The IdentityRole Class

`IdentityRole` represents a role that can be assigned to users. Like IdentityUser, it can be extended with custom properties:

```csharp
using Microsoft.AspNetCore.Identity;

namespace IdentityDemo.Models
{
    public class ApplicationRole : IdentityRole
    {
        public string? Description { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public bool IsSystemRole { get; set; } // System roles cannot be deleted
        public string? Department { get; set; } // For department-specific roles
        
        // Navigation property for users in this role
        public virtual ICollection<UserRole> Users { get; set; }
        
        // Navigation property for role claims
        public virtual ICollection<IdentityRoleClaim<string>> RoleClaims { get; set; }
    }
}
```

Role properties might include metadata about when the role was created, whether it's a system role that shouldn't be deleted, department association for organizational hierarchies, or descriptions for admin interfaces. Like users, roles can have claims associated with them—claims that apply to all users in that role.

### Related Entity Types

Identity uses several junction tables to represent relationships between users, roles, and claims:

**IdentityUserRole** links users to roles. This is a many-to-many relationship—a user can have multiple roles, and a role can be assigned to multiple users.

**IdentityUserClaim** stores claims associated with a specific user. Claims are key-value pairs that represent facts about the user, such as permissions or preferences.

**IdentityRoleClaim** stores claims associated with a role. All users in the role inherit these claims.

**IdentityUserLogin** stores external login provider information (Google, Facebook, Microsoft, etc.) linked to a user account.

**IdentityUserToken** stores tokens for the user, such as two-factor authentication tokens or password reset tokens.

These entities are managed automatically by Identity—you typically don't work with them directly. Instead, you use `UserManager` and `RoleManager` methods that handle these relationships internally.

### Using Non-String Primary Keys

By default, Identity uses strings for primary keys (GUIDs stored as strings). You might prefer to use integers or GUIDs for performance or personal preference. To do this, specify the key type when inheriting from the base classes:

```csharp
// User with integer primary key
public class ApplicationUser : IdentityUser<int>
{
    // Custom properties...
}

// Role with integer primary key
public class ApplicationRole : IdentityRole<int>
{
    // Custom properties...
}

// DbContext configuration
public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, int>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }
}

// Identity configuration
builder.Services.AddIdentity<ApplicationUser, ApplicationRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();
```

The key type flows through all related entities. `IdentityUserRole<int>`, `IdentityUserClaim<int>`, and so on will be used automatically. This is a significant change that should be decided early, as changing primary key types later requires recreating the database or writing migration scripts.

---

## 6. Database Configuration with Entity Framework Core

### Creating the ApplicationDbContext

The `ApplicationDbContext` is your Entity Framework Core context that includes Identity entities. It inherits from `IdentityDbContext`, which provides DbSet properties for all Identity-related tables and configures the entity mappings. Your application-specific entities go in this same context.

```csharp
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using IdentityDemo.Models;

namespace IdentityDemo.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        // Your application entities
        public DbSet<Product> Products { get; set; }
        public DbSet<Order> Orders { get; set; }
        public DbSet<Category> Categories { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Customize Identity table names
            builder.Entity<ApplicationUser>(entity =>
            {
                entity.ToTable(name: "Users");
                entity.Property(e => e.Id).HasMaxLength(36);
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

            // Configure custom user properties
            builder.Entity<ApplicationUser>(entity =>
            {
                entity.Property(e => e.FirstName).HasMaxLength(100);
                entity.Property(e => e.LastName).HasMaxLength(100);
                entity.Property(e => e.DisplayName).HasMaxLength(200);
                entity.HasIndex(e => e.Email).IsUnique();
            });

            // Seed initial data
            SeedData(builder);
        }

        private void SeedData(ModelBuilder builder)
        {
            // Seed roles
            var adminRole = new ApplicationRole
            {
                Id = Guid.NewGuid().ToString(),
                Name = "Admin",
                NormalizedName = "ADMIN",
                Description = "Administrator with full access",
                IsSystemRole = true,
                CreatedAt = new DateTime(2024, 1, 1)
            };

            var userRole = new ApplicationRole
            {
                Id = Guid.NewGuid().ToString(),
                Name = "User",
                NormalizedName = "USER",
                Description = "Standard user with limited access",
                IsSystemRole = true,
                CreatedAt = new DateTime(2024, 1, 1)
            };

            builder.Entity<ApplicationRole>().HasData(adminRole, userRole);
        }
    }
}
```

### Configuring the Connection String

Add a connection string to your `appsettings.json` file. The connection string format depends on your database provider:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=IdentityDemo;Trusted_Connection=True;MultipleActiveResultSets=true"
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

For SQL Server with Docker or a remote server:
```json
"DefaultConnection": "Server=localhost,1433;Database=IdentityDemo;User Id=sa;Password=YourPassword123;TrustServerCertificate=True"
```

For PostgreSQL:
```json
"DefaultConnection": "Host=localhost;Database=IdentityDemo;Username=postgres;Password=YourPassword"
```

### Creating and Applying Migrations

Entity Framework Core uses migrations to create and update the database schema. After defining your DbContext and entities, create an initial migration:

```bash
# Create the initial migration
dotnet ef migrations add InitialCreate

# Review the generated migration files in Migrations folder
# The migration creates tables for: Users, Roles, UserRoles, UserClaims, RoleClaims, UserLogins, UserTokens

# Apply the migration to create the database
dotnet ef database update

# To add a new migration after model changes
dotnet ef migrations add AddUserProfileFields

# To rollback to a specific migration
dotnet ef database update InitialCreate

# To remove the last migration (if not applied)
dotnet ef migrations remove
```

The migration process generates C# code that represents the changes to your database schema. Review this code before applying it—EF Core's migrations are generally reliable, but it's important to understand what changes will be made, especially for production databases. The migration files are stored in the `Migrations` folder and should be committed to source control.

### Database Schema Overview

The Identity schema consists of seven tables (using default names):

1. **AspNetUsers**: Stores user accounts with all properties from IdentityUser and your custom properties.

2. **AspNetRoles**: Stores role definitions.

3. **AspNetUserRoles**: Junction table linking users to roles (many-to-many relationship).

4. **AspNetUserClaims**: Stores claims specific to individual users.

5. **AspNetRoleClaims**: Stores claims associated with roles, inherited by all users in the role.

6. **AspNetUserLogins**: Stores external login provider information (Google, Facebook, etc.).

7. **AspNetUserTokens**: Stores authentication tokens (remember me tokens, two-factor tokens, etc.).

The tables have appropriate indexes for common query patterns: lookups by normalized username, normalized email, and external login provider keys. Foreign key relationships ensure referential integrity. Understanding this schema helps when writing custom queries or troubleshooting data issues.

---

## 7. User Registration and Management

### Implementing User Registration

User registration involves creating a new user account with valid credentials. The `UserManager` class provides the `CreateAsync` method for this purpose. A complete registration implementation validates input, checks for existing users, creates the user, assigns default roles, and handles email confirmation.

Create an `AccountController` with registration functionality:

```csharp
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using IdentityDemo.Models;
using IdentityDemo.ViewModels;

namespace IdentityDemo.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly ILogger<AccountController> _logger;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<ApplicationRole> roleManager,
            IEmailService emailService,
            ILogger<AccountController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _logger = logger;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Check if email already exists
            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError(string.Empty, "Email is already registered.");
                return View(model);
            }

            // Create the user
            var user = new ApplicationUser
            {
                UserName = model.UserName,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
                CreatedAt = DateTime.UtcNow,
                EmailConfirmed = false
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                _logger.LogInformation("User created a new account: {Email}", model.Email);

                // Assign default "User" role
                await _userManager.AddToRoleAsync(user, "User");

                // Generate email confirmation token
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action(
                    "ConfirmEmail",
                    "Account",
                    new { userId = user.Id, token = token },
                    Request.Scheme);

                // Send confirmation email
                await _emailService.SendConfirmationEmailAsync(user.Email, confirmationLink);

                // If email confirmation is not required, sign in immediately
                if (!_userManager.Options.SignIn.RequireConfirmedEmail)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return RedirectToAction("Index", "Home");
                }

                return RedirectToAction("RegisterConfirmation");
            }

            // Add errors to model state
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult RegisterConfirmation()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (userId == null || token == null)
            {
                return RedirectToAction("Index", "Home");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{userId}'.");
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                return View("ConfirmEmailSuccess");
            }

            return View("ConfirmEmailFailure");
        }
    }
}
```

### Creating the Registration ViewModel

```csharp
using System.ComponentModel.DataAnnotations;

namespace IdentityDemo.ViewModels
{
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "Username is required")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 50 characters")]
        [RegularExpression(@"^[a-zA-Z0-9_]+$", ErrorMessage = "Username can only contain letters, numbers, and underscores")]
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
        [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please confirm your password")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}
```

### User Management Operations

Beyond registration, applications need to support various user management operations: viewing profiles, updating information, changing passwords, and account deletion. Here's a comprehensive `UserManagementController` for admin operations:

```csharp
[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin")]
public class UserManagementController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<ApplicationRole> _roleManager;

    public UserManagementController(
        UserManager<ApplicationUser> userManager,
        RoleManager<ApplicationRole> roleManager)
    {
        _userManager = userManager;
        _roleManager = roleManager;
    }

    /// <summary>
    /// Get all users with pagination
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetUsers([FromQuery] int page = 1, [FromQuery] int pageSize = 10)
    {
        var users = _userManager.Users
            .OrderBy(u => u.UserName)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(u => new UserListViewModel
            {
                Id = u.Id,
                UserName = u.UserName!,
                Email = u.Email!,
                FirstName = u.FirstName!,
                LastName = u.LastName!,
                EmailConfirmed = u.EmailConfirmed,
                IsLockedOut = u.LockoutEnd.HasValue && u.LockoutEnd > DateTimeOffset.UtcNow,
                CreatedAt = u.CreatedAt
            })
            .ToList();

        var totalUsers = _userManager.Users.Count();

        return Ok(new
        {
            Users = users,
            TotalCount = totalUsers,
            Page = page,
            PageSize = pageSize,
            TotalPages = (int)Math.Ceiling(totalUsers / (double)pageSize)
        });
    }

    /// <summary>
    /// Get a specific user by ID
    /// </summary>
    [HttpGet("{id}")]
    public async Task<IActionResult> GetUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        var roles = await _userManager.GetRolesAsync(user);
        var claims = await _userManager.GetClaimsAsync(user);

        return Ok(new UserDetailsViewModel
        {
            Id = user.Id,
            UserName = user.UserName!,
            Email = user.Email!,
            FirstName = user.FirstName!,
            LastName = user.LastName!,
            EmailConfirmed = user.EmailConfirmed,
            PhoneNumber = user.PhoneNumber,
            TwoFactorEnabled = user.TwoFactorEnabled,
            Roles = roles.ToList(),
            Claims = claims.Select(c => new { c.Type, c.Value }).ToList(),
            CreatedAt = user.CreatedAt,
            LastLoginAt = user.LastLoginAt
        });
    }

    /// <summary>
    /// Update user information
    /// </summary>
    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateUser(string id, [FromBody] UpdateUserViewModel model)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        user.FirstName = model.FirstName;
        user.LastName = model.LastName;
        user.PhoneNumber = model.PhoneNumber;

        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
        }

        return Ok(new { Message = "User updated successfully" });
    }

    /// <summary>
    /// Delete a user
    /// </summary>
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        // Prevent deleting the last admin
        var admins = await _userManager.GetUsersInRoleAsync("Admin");
        if (admins.Count == 1 && await _userManager.IsInRoleAsync(user, "Admin"))
        {
            return BadRequest(new { Message = "Cannot delete the last administrator" });
        }

        var result = await _userManager.DeleteAsync(user);
        if (!result.Succeeded)
        {
            return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
        }

        return Ok(new { Message = "User deleted successfully" });
    }

    /// <summary>
    /// Change user password (admin override)
    /// </summary>
    [HttpPost("{id}/change-password")]
    public async Task<IActionResult> ChangePassword(string id, [FromBody] ChangePasswordViewModel model)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        // Remove existing password and set new one
        var removeResult = await _userManager.RemovePasswordAsync(user);
        if (!removeResult.Succeeded)
        {
            return BadRequest(new { Errors = removeResult.Errors.Select(e => e.Description) });
        }

        var addResult = await _userManager.AddPasswordAsync(user, model.NewPassword);
        if (!addResult.Succeeded)
        {
            return BadRequest(new { Errors = addResult.Errors.Select(e => e.Description) });
        }

        return Ok(new { Message = "Password changed successfully" });
    }

    /// <summary>
    /// Lock a user account
    /// </summary>
    [HttpPost("{id}/lock")]
    public async Task<IActionResult> LockUser(string id, [FromBody] LockUserViewModel model)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        // Prevent locking the last admin
        var admins = await _userManager.GetUsersInRoleAsync("Admin");
        if (admins.Count == 1 && await _userManager.IsInRoleAsync(user, "Admin"))
        {
            return BadRequest(new { Message = "Cannot lock the last administrator" });
        }

        var lockoutEnd = model.LockoutDurationMinutes > 0
            ? DateTimeOffset.UtcNow.AddMinutes(model.LockoutDurationMinutes)
            : DateTimeOffset.MaxValue; // Permanent lock

        var result = await _userManager.SetLockoutEndDateAsync(user, lockoutEnd);
        if (!result.Succeeded)
        {
            return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
        }

        return Ok(new { Message = "User account locked" });
    }

    /// <summary>
    /// Unlock a user account
    /// </summary>
    [HttpPost("{id}/unlock")]
    public async Task<IActionResult> UnlockUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        var result = await _userManager.SetLockoutEndDateAsync(user, null);
        if (!result.Succeeded)
        {
            return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
        }

        // Reset failed access count
        await _userManager.ResetAccessFailedCountAsync(user);

        return Ok(new { Message = "User account unlocked" });
    }
}
```

---

## 8. User Authentication (Login/Logout)

### Implementing Login Functionality

The login process validates user credentials and creates an authentication session. `SignInManager` provides the `PasswordSignInAsync` method that handles the complete flow: checking the password, handling lockout, and creating the authentication cookie.

```csharp
public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILogger<AccountController> _logger;

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Login(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        return View();
    }

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

        // Find user by email or username
        var user = await _userManager.FindByEmailAsync(model.Email)
                   ?? await _userManager.FindByNameAsync(model.Email);

        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(model);
        }

        // Check if email confirmation is required and not confirmed
        if (_userManager.Options.SignIn.RequireConfirmedEmail && !user.EmailConfirmed)
        {
            ModelState.AddModelError(string.Empty, "Please confirm your email before logging in.");
            return View(model);
        }

        // Check if account is locked out
        if (await _userManager.IsLockedOutAsync(user))
        {
            var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
            var remainingTime = lockoutEnd - DateTimeOffset.UtcNow;
            
            ModelState.AddModelError(string.Empty, 
                $"Account is locked out. Try again in {remainingTime?.Minutes ?? 0} minutes.");
            return View(model);
        }

        // Attempt to sign in
        var result = await _signInManager.PasswordSignInAsync(
            user.UserName!,
            model.Password,
            model.RememberMe,
            lockoutOnFailure: true);

        if (result.Succeeded)
        {
            _logger.LogInformation("User logged in: {Email}", model.Email);

            // Update last login time
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Redirect to return URL or home
            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return RedirectToAction("Index", "Home");
        }

        if (result.IsLockedOut)
        {
            _logger.LogWarning("User account locked out: {Email}", model.Email);
            return RedirectToAction("Lockout");
        }

        if (result.IsNotAllowed)
        {
            ModelState.AddModelError(string.Empty, "Account not allowed to sign in. Please confirm your email.");
            return View(model);
        }

        if (result.RequiresTwoFactor)
        {
            return RedirectToAction("LoginWith2fa", new { returnUrl, model.RememberMe });
        }

        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        var userName = User.Identity?.Name;
        await _signInManager.SignOutAsync();
        _logger.LogInformation("User logged out: {UserName}", userName);
        return RedirectToAction("Index", "Home");
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Lockout()
    {
        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult AccessDenied()
    {
        return View();
    }
}
```

### Login ViewModel

```csharp
public class LoginViewModel
{
    [Required(ErrorMessage = "Email or username is required")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    [Display(Name = "Remember me?")]
    public bool RememberMe { get; set; }

    public string? ReturnUrl { get; set; }
}
```

### Password Reset Flow

Password reset is a critical security feature. The flow involves generating a reset token, sending it via email, and validating it when the user submits the new password:

```csharp
[HttpGet]
[AllowAnonymous]
public IActionResult ForgotPassword()
{
    return View();
}

[HttpPost]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
{
    if (!ModelState.IsValid)
    {
        return View(model);
    }

    var user = await _userManager.FindByEmailAsync(model.Email);
    if (user == null || !await _userManager.IsEmailConfirmedAsync(user))
    {
        // Don't reveal that the user does not exist or is not confirmed
        return RedirectToAction("ForgotPasswordConfirmation");
    }

    // Generate reset token
    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
    var resetLink = Url.Action(
        "ResetPassword",
        "Account",
        new { email = model.Email, token = token },
        Request.Scheme);

    // Send email
    await _emailService.SendPasswordResetEmailAsync(model.Email, resetLink);

    return RedirectToAction("ForgotPasswordConfirmation");
}

[HttpGet]
[AllowAnonymous]
public IActionResult ForgotPasswordConfirmation()
{
    return View();
}

[HttpGet]
[AllowAnonymous]
public IActionResult ResetPassword(string? email, string? token)
{
    if (email == null || token == null)
    {
        return BadRequest("Invalid password reset link.");
    }

    return View(new ResetPasswordViewModel { Email = email, Token = token });
}

[HttpPost]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
{
    if (!ModelState.IsValid)
    {
        return View(model);
    }

    var user = await _userManager.FindByEmailAsync(model.Email);
    if (user == null)
    {
        // Don't reveal that the user does not exist
        return RedirectToAction("ResetPasswordConfirmation");
    }

    var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
    if (result.Succeeded)
    {
        // Update security stamp to invalidate other sessions
        await _userManager.UpdateSecurityStampAsync(user);
        return RedirectToAction("ResetPasswordConfirmation");
    }

    foreach (var error in result.Errors)
    {
        ModelState.AddModelError(string.Empty, error.Description);
    }

    return View(model);
}

[HttpGet]
[AllowAnonymous]
public IActionResult ResetPasswordConfirmation()
{
    return View();
}
```

---

## 9. Role Management with IdentityRole

### Understanding Role-Based Security

Role-based security is a fundamental access control model where permissions are assigned to roles, and users are assigned to roles. This abstraction simplifies permission management—rather than assigning specific permissions to each user, you assign users to roles that carry the appropriate permissions. When a new employee joins, you assign them the roles appropriate for their position; when they leave, you remove their role assignments.

ASP.NET Core Identity provides built-in support for role management through the `IdentityRole` class and `RoleManager<TRole>`. Roles integrate seamlessly with the authorization system—the `[Authorize(Roles = "Admin")]` attribute restricts access to users in the specified roles. Behind the scenes, roles are represented as role claims in the authentication cookie, making role checks fast since they don't require database lookups during request processing.

### Creating and Managing Roles

The `RoleManager` class provides methods for creating, updating, and deleting roles. Here's a comprehensive `RoleManagementController`:

```csharp
[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin")]
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
    /// Get all roles
    /// </summary>
    [HttpGet]
    public IActionResult GetAllRoles()
    {
        var roles = _roleManager.Roles
            .Select(r => new RoleListViewModel
            {
                Id = r.Id,
                Name = r.Name!,
                Description = r.Description,
                IsSystemRole = r.IsSystemRole,
                CreatedAt = r.CreatedAt
            })
            .ToList();

        return Ok(roles);
    }

    /// <summary>
    /// Get a specific role with its users
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
            Users = usersInRole.Select(u => new { u.Id, u.UserName, u.Email }),
            Claims = roleClaims.Select(c => new { c.Type, c.Value })
        });
    }

    /// <summary>
    /// Create a new role
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> CreateRole([FromBody] CreateRoleViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        // Check if role already exists
        var existingRole = await _roleManager.FindByNameAsync(model.Name);
        if (existingRole != null)
        {
            return BadRequest(new { Message = "Role already exists" });
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

        return CreatedAtAction(nameof(GetRole), new { id = role.Id }, new
        {
            Id = role.Id,
            Name = role.Name,
            Description = role.Description
        });
    }

    /// <summary>
    /// Update a role
    /// </summary>
    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateRole(string id, [FromBody] UpdateRoleViewModel model)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { Message = "Role not found" });
        }

        // Check if renaming to an existing name
        if (role.Name != model.Name)
        {
            var existingRole = await _roleManager.FindByNameAsync(model.Name);
            if (existingRole != null)
            {
                return BadRequest(new { Message = "Role name already exists" });
            }
        }

        role.Name = model.Name;
        role.Description = model.Description;

        var result = await _roleManager.UpdateAsync(role);
        if (!result.Succeeded)
        {
            return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
        }

        return Ok(new { Message = "Role updated successfully" });
    }

    /// <summary>
    /// Delete a role
    /// </summary>
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteRole(string id)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { Message = "Role not found" });
        }

        if (role.IsSystemRole)
        {
            return BadRequest(new { Message = "System roles cannot be deleted" });
        }

        // Check if any users are in this role
        var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name!);
        if (usersInRole.Any())
        {
            return BadRequest(new { 
                Message = "Cannot delete role with assigned users. Remove users from the role first.",
                UserCount = usersInRole.Count
            });
        }

        var result = await _roleManager.DeleteAsync(role);
        if (!result.Succeeded)
        {
            return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
        }

        _logger.LogInformation("Role deleted: {RoleName}", role.Name);

        return Ok(new { Message = "Role deleted successfully" });
    }

    /// <summary>
    /// Add a claim to a role
    /// </summary>
    [HttpPost("{id}/claims")]
    public async Task<IActionResult> AddClaimToRole(string id, [FromBody] AddClaimViewModel model)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { Message = "Role not found" });
        }

        // Check if claim already exists
        var existingClaims = await _roleManager.GetClaimsAsync(role);
        if (existingClaims.Any(c => c.Type == model.ClaimType && c.Value == model.ClaimValue))
        {
            return BadRequest(new { Message = "Claim already exists for this role" });
        }

        var claim = new Claim(model.ClaimType, model.ClaimValue);
        var result = await _roleManager.AddClaimAsync(role, claim);

        if (!result.Succeeded)
        {
            return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
        }

        return Ok(new { Message = "Claim added to role" });
    }

    /// <summary>
    /// Remove a claim from a role
    /// </summary>
    [HttpDelete("{id}/claims")]
    public async Task<IActionResult> RemoveClaimFromRole(string id, [FromBody] RemoveClaimViewModel model)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { Message = "Role not found" });
        }

        var claim = new Claim(model.ClaimType, model.ClaimValue);
        var result = await _roleManager.RemoveClaimAsync(role, claim);

        if (!result.Succeeded)
        {
            return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
        }

        return Ok(new { Message = "Claim removed from role" });
    }
}
```

### Assigning Users to Roles

User-role assignments are managed through `UserManager`:

```csharp
/// <summary>
/// Assign a role to a user
/// </summary>
[HttpPost("users/{userId}/roles")]
public async Task<IActionResult> AddUserToRole(string userId, [FromBody] AssignRoleViewModel model)
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

    if (await _userManager.IsInRoleAsync(user, role.Name!))
    {
        return BadRequest(new { Message = "User already has this role" });
    }

    var result = await _userManager.AddToRoleAsync(user, role.Name!);
    if (!result.Succeeded)
    {
        return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
    }

    _logger.LogInformation("User {UserId} assigned to role {RoleName}", userId, role.Name);

    return Ok(new { Message = "Role assigned to user" });
}

/// <summary>
/// Remove a role from a user
/// </summary>
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

    if (!await _userManager.IsInRoleAsync(user, role.Name!))
    {
        return BadRequest(new { Message = "User doesn't have this role" });
    }

    // Prevent removing the last admin
    var admins = await _userManager.GetUsersInRoleAsync("Admin");
    if (role.Name == "Admin" && admins.Count == 1 && admins[0].Id == userId)
    {
        return BadRequest(new { Message = "Cannot remove the last administrator" });
    }

    var result = await _userManager.RemoveFromRoleAsync(user, role.Name!);
    if (!result.Succeeded)
    {
        return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
    }

    _logger.LogInformation("User {UserId} removed from role {RoleName}", userId, role.Name);

    return Ok(new { Message = "Role removed from user" });
}

/// <summary>
/// Get all roles for a user
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
    return Ok(roles);
}
```

---

## 10. Role-Based Access Control (RBAC)

### Implementing RBAC with Identity

Role-Based Access Control (RBAC) restricts system access based on the roles assigned to users. In ASP.NET Core Identity, RBAC is implemented through the combination of IdentityRole, role assignments, and the `[Authorize]` attribute with the Roles parameter. This creates a clear separation between authentication (verifying who the user is) and authorization (determining what the user can do).

The core principle of RBAC is that permissions are not assigned directly to users but are instead assigned to roles. Users inherit the permissions of all roles they're assigned to. This model provides several benefits: simplified permission management (adding a new employee requires only assigning the appropriate role), easier auditing (you can see what permissions each role has), and reduced risk of permission creep (permissions don't accumulate over time if managed through roles).

### Using the Authorize Attribute with Roles

The `[Authorize]` attribute supports role-based restrictions through the Roles parameter. When specified, only users in at least one of the listed roles can access the endpoint:

```csharp
// Only administrators can access
[Authorize(Roles = "Admin")]
public class AdminController : Controller
{
    public IActionResult Dashboard()
    {
        return View();
    }
}

// Both Admin and Manager can access
[Authorize(Roles = "Admin,Manager")]
public class ReportsController : Controller
{
    public IActionResult ViewReports()
    {
        return View();
    }
}

// Controller accessible to all authenticated users, but specific actions restricted
public class ProductsController : Controller
{
    // Anyone can view products
    [Authorize]
    public IActionResult Index()
    {
        return View();
    }

    // Only Admin and Manager can create
    [Authorize(Roles = "Admin,Manager")]
    [HttpPost]
    public IActionResult Create(Product model)
    {
        // Create product
        return RedirectToAction(nameof(Index));
    }

    // Only Admin can delete
    [Authorize(Roles = "Admin")]
    [HttpPost]
    public IActionResult Delete(int id)
    {
        // Delete product
        return RedirectToAction(nameof(Index));
    }
}
```

For scenarios requiring multiple roles (user must have ALL specified roles), use multiple `[Authorize]` attributes:

```csharp
// User must be BOTH Admin AND in Finance department
[Authorize(Roles = "Admin")]
[Authorize(Roles = "Finance")]
public class FinancialAdminController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}
```

### Checking Roles Programmatically

Sometimes you need to check roles in your code rather than through attributes:

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
        var user = await _userManager.GetUserAsync(User);

        // Check if user is in a specific role
        var isAdmin = await _userManager.IsInRoleAsync(user, "Admin");

        // Get all user's roles
        var roles = await _userManager.GetRolesAsync(user);

        // Using User principal (from cookie)
        var isInRole = User.IsInRole("Admin");

        var viewModel = new DashboardViewModel
        {
            UserName = user.UserName,
            Roles = roles,
            ShowAdminPanel = isAdmin
        };

        return View(viewModel);
    }
}
```

### Creating a Permission System on Top of Roles

While Identity provides roles, many applications need a more granular permission system. A common pattern is to create a permission table and associate permissions with roles:

```csharp
// Permission entity
public class Permission
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
}

// Role-Permission junction table
public class RolePermission
{
    public string RoleId { get; set; } = string.Empty;
    public int PermissionId { get; set; }
    
    public ApplicationRole Role { get; set; } = null!;
    public Permission Permission { get; set; } = null!;
}

// Extend ApplicationRole
public class ApplicationRole : IdentityRole
{
    public string? Description { get; set; }
    public virtual ICollection<RolePermission> RolePermissions { get; set; }
}
```

Create a permission service:

```csharp
public interface IPermissionService
{
    Task<bool> HasPermissionAsync(string userId, string permissionName);
    Task<List<string>> GetUserPermissionsAsync(string userId);
    Task GrantPermissionToRoleAsync(string roleId, int permissionId);
    Task RevokePermissionFromRoleAsync(string roleId, int permissionId);
}

public class PermissionService : IPermissionService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly ApplicationDbContext _context;

    public PermissionService(
        UserManager<ApplicationUser> userManager,
        RoleManager<ApplicationRole> roleManager,
        ApplicationDbContext context)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _context = context;
    }

    public async Task<bool> HasPermissionAsync(string userId, string permissionName)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return false;

        var roles = await _userManager.GetRolesAsync(user);
        
        var hasPermission = await _context.RolePermissions
            .AnyAsync(rp => roles.Contains(rp.RoleId) && 
                           rp.Permission.Name == permissionName);

        return hasPermission;
    }

    public async Task<List<string>> GetUserPermissionsAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return new List<string>();

        var roles = await _userManager.GetRolesAsync(user);

        var permissions = await _context.RolePermissions
            .Where(rp => roles.Contains(rp.RoleId))
            .Select(rp => rp.Permission.Name)
            .Distinct()
            .ToListAsync();

        return permissions;
    }

    public async Task GrantPermissionToRoleAsync(string roleId, int permissionId)
    {
        var exists = await _context.RolePermissions
            .AnyAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId);

        if (!exists)
        {
            _context.RolePermissions.Add(new RolePermission
            {
                RoleId = roleId,
                PermissionId = permissionId
            });
            await _context.SaveChangesAsync();
        }
    }

    public async Task RevokePermissionFromRoleAsync(string roleId, int permissionId)
    {
        var rolePermission = await _context.RolePermissions
            .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId);

        if (rolePermission != null)
        {
            _context.RolePermissions.Remove(rolePermission);
            await _context.SaveChangesAsync();
        }
    }
}
```

Create a custom authorization attribute:

```csharp
public class PermissionAttribute : AuthorizeAttribute
{
    public PermissionAttribute(string permission)
    {
        Policy = $"Permission_{permission}";
    }
}

// Register permission policies in Program.cs
builder.Services.AddAuthorization(options =>
{
    // Get all permissions and create policies
    var permissions = new[] { "Users.View", "Users.Create", "Users.Edit", "Users.Delete",
                              "Products.View", "Products.Create", "Products.Edit", "Products.Delete",
                              "Reports.View", "Reports.Export" };

    foreach (var permission in permissions)
    {
        options.AddPolicy($"Permission_{permission}", policy =>
            policy.Requirements.Add(new PermissionRequirement(permission)));
    }
});

// Permission requirement and handler
public class PermissionRequirement : IAuthorizationRequirement
{
    public string Permission { get; }

    public PermissionRequirement(string permission)
    {
        Permission = permission;
    }
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
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId == null) return;

        using var scope = _serviceProvider.CreateScope();
        var permissionService = scope.ServiceProvider.GetRequiredService<IPermissionService>();

        if (await permissionService.HasPermissionAsync(userId, requirement.Permission))
        {
            context.Succeed(requirement);
        }
    }
}

// Register the handler
builder.Services.AddSingleton<IAuthorizationHandler, PermissionHandler>();
```

Now you can use the permission attribute:

```csharp
[Permission("Users.View")]
public IActionResult Index()
{
    return View();
}

[Permission("Users.Create")]
[HttpPost]
public IActionResult Create(UserViewModel model)
{
    // Create user
    return RedirectToAction(nameof(Index));
}
```

---

## 11. Claims-Based Authorization

### Understanding Claims

Claims are key-value pairs that represent facts about a user. While roles are a simple string that represents a group, claims provide a more flexible and expressive way to describe user attributes. A claim might represent the user's email, their department, their clearance level, whether they're a premium subscriber, or any other piece of information that's relevant to authorization decisions.

The distinction between roles and claims is important: roles are a categorization mechanism (the user IS an Admin), while claims are statements about the user (the user HAS a department claim with value "Finance"). In practice, ASP.NET Core treats roles as a special type of claim—when you add a user to a role, internally Identity adds a claim of type `ClaimTypes.Role` with the role name as the value. This means all the authorization mechanisms that work with claims also work with roles.

Claims become part of the authentication cookie, making them available during request processing without database queries. This is both an advantage (fast access) and a consideration (the cookie size grows with more claims, and claims become stale until the user signs in again). For frequently changing data, you might query the database rather than storing claims in the cookie.

### Adding Claims to Users

Claims can be added to individual users or to roles (all users in the role inherit the claims):

```csharp
public class UserClaimsController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;

    public UserClaimsController(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    // Add a claim to a user
    [HttpPost]
    public async Task<IActionResult> AddClaim(string userId, string claimType, string claimValue)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        var claim = new Claim(claimType, claimValue);
        var result = await _userManager.AddClaimAsync(user, claim);

        if (result.Succeeded)
        {
            // Refresh the user's sign-in cookie to include the new claim
            await _signInManager.RefreshSignInAsync(user);
            return Ok();
        }

        return BadRequest(result.Errors);
    }

    // Remove a claim from a user
    [HttpPost]
    public async Task<IActionResult> RemoveClaim(string userId, string claimType, string claimValue)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        var claim = new Claim(claimType, claimValue);
        var result = await _userManager.RemoveClaimAsync(user, claim);

        if (result.Succeeded)
        {
            await _signInManager.RefreshSignInAsync(user);
            return Ok();
        }

        return BadRequest(result.Errors);
    }

    // Get all claims for a user
    [HttpGet]
    public async Task<IActionResult> GetClaims(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        var claims = await _userManager.GetClaimsAsync(user);
        return Ok(claims.Select(c => new { c.Type, c.Value }));
    }
}
```

### Using Claims in Authorization

The `[Authorize]` attribute can require specific claims:

```csharp
// User must have a specific claim value
[Authorize(Policy = "DepartmentFinance")]
public class FinanceController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}
```

Define claim-based policies in Program.cs:

```csharp
builder.Services.AddAuthorization(options =>
{
    // Require specific claim value
    options.AddPolicy("DepartmentFinance", policy =>
        policy.RequireClaim("Department", "Finance"));

    // Require claim with any value
    options.AddPolicy("HasEmployeeId", policy =>
        policy.RequireClaim("EmployeeId"));

    // Require claim with multiple possible values
    options.AddPolicy("SeniorStaff", policy =>
        policy.RequireClaim("Level", "Senior", "Lead", "Manager", "Director"));

    // Complex policy using RequireAssertion
    options.AddPolicy("CanAccessPremium", policy =>
        policy.RequireAssertion(context =>
        {
            var isPremium = context.User.HasClaim(c => 
                c.Type == "Subscription" && c.Value == "Premium");
            var isEmployee = context.User.HasClaim(c => 
                c.Type == "EmployeeType");
            return isPremium || isEmployee;
        }));
});
```

### Accessing Claims in Code

Claims are available through the `User` property (a ClaimsPrincipal) in controllers and views:

```csharp
public class ProfileController : Controller
{
    public IActionResult Index()
    {
        // Get a specific claim
        var departmentClaim = User.FindFirst("Department");
        var department = departmentClaim?.Value ?? "Unknown";

        // Check if user has a claim
        var hasPremiumAccess = User.HasClaim(c => 
            c.Type == "Subscription" && c.Value == "Premium");

        // Get all claims
        var allClaims = User.Claims.Select(c => $"{c.Type}: {c.Value}");

        // Get specific claim types using ClaimTypes constants
        var email = User.FindFirst(ClaimTypes.Email)?.Value;
        var name = User.FindFirst(ClaimTypes.Name)?.Value;
        var nameIdentifier = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        return View();
    }
}
```

In Razor views:

```cshtml
@using System.Security.Claims

@{
    var department = User.FindFirst("Department")?.Value;
    var isPremium = User.HasClaim("Subscription", "Premium");
}

<div class="profile">
    <p>User: @User.Identity?.Name</p>
    <p>Department: @department</p>
    
    @if (isPremium)
    {
        <span class="badge">Premium Member</span>
    }
</div>
```

### Adding Claims During User Creation

You might want to add claims automatically when a user registers:

```csharp
public async Task<IActionResult> Register(RegisterViewModel model)
{
    // ... create user code ...

    if (result.Succeeded)
    {
        // Add default claims
        var defaultClaims = new List<Claim>
        {
            new Claim("Department", model.Department ?? "General"),
            new Claim("Subscription", "Free"),
            new Claim("AccountCreated", DateTime.UtcNow.ToString("O"))
        };

        await _userManager.AddClaimsAsync(user, defaultClaims);

        // Assign default role
        await _userManager.AddToRoleAsync(user, "User");

        // ... continue with sign-in or email confirmation ...
    }
}
```

---

## 12. Policy-Based Authorization

### Understanding Policy-Based Authorization

Policy-based authorization provides a more flexible and expressive way to define authorization requirements. Instead of hardcoding role names or claim values in attributes, you define named policies with specific requirements. These requirements can be based on roles, claims, custom logic, or any combination. The policy name is then used in `[Authorize]` attributes, decoupling authorization logic from controller code.

A policy consists of one or more requirements, and each requirement has an associated handler that determines whether the current user meets the requirement. This architecture allows for complex authorization scenarios while keeping the code maintainable. Requirements are reusable across policies, and handlers can be unit tested independently.

### Creating Custom Requirements

A requirement is a class that implements `IAuthorizationRequirement`—typically just a data container:

```csharp
// Age requirement
public class MinimumAgeRequirement : IAuthorizationRequirement
{
    public int MinimumAge { get; }

    public MinimumAgeRequirement(int minimumAge)
    {
        MinimumAge = minimumAge;
    }
}

// Time-based requirement
public class BusinessHoursRequirement : IAuthorizationRequirement
{
    public int StartHour { get; } = 9;
    public int EndHour { get; } = 17;
}

// Subscription requirement
public class SubscriptionRequirement : IAuthorizationRequirement
{
    public string[] RequiredTiers { get; }

    public SubscriptionRequirement(params string[] requiredTiers)
    {
        RequiredTiers = requiredTiers;
    }
}
```

### Creating Authorization Handlers

Handlers contain the logic to evaluate requirements. A handler inherits from `AuthorizationHandler<TRequirement>`:

```csharp
public class MinimumAgeHandler : AuthorizationHandler<MinimumAgeRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        MinimumAgeRequirement requirement)
    {
        var dateOfBirthClaim = context.User.FindFirst("DateOfBirth");

        if (dateOfBirthClaim == null)
        {
            return Task.CompletedTask;
        }

        if (DateTime.TryParse(dateOfBirthClaim.Value, out var dateOfBirth))
        {
            var age = CalculateAge(dateOfBirth);

            if (age >= requirement.MinimumAge)
            {
                context.Succeed(requirement);
            }
        }

        return Task.CompletedTask;
    }

    private static int CalculateAge(DateTime dateOfBirth)
    {
        var today = DateTime.Today;
        var age = today.Year - dateOfBirth.Year;
        if (dateOfBirth.Date > today.AddYears(-age))
        {
            age--;
        }
        return age;
    }
}

public class BusinessHoursHandler : AuthorizationHandler<BusinessHoursRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        BusinessHoursRequirement requirement)
    {
        var currentHour = DateTime.Now.Hour;

        if (currentHour >= requirement.StartHour && currentHour < requirement.EndHour)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

public class SubscriptionHandler : AuthorizationHandler<SubscriptionRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        SubscriptionRequirement requirement)
    {
        var subscriptionClaim = context.User.FindFirst("Subscription");

        if (subscriptionClaim != null && 
            requirement.RequiredTiers.Contains(subscriptionClaim.Value, StringComparer.OrdinalIgnoreCase))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
```

### Registering Policies and Handlers

In Program.cs, register your policies and handlers:

```csharp
builder.Services.AddAuthorization(options =>
{
    // Role-based policies
    options.AddPolicy("RequireAdminRole", policy =>
        policy.RequireRole("Admin"));

    // Claim-based policies
    options.AddPolicy("RequireEmailVerified", policy =>
        policy.RequireClaim("EmailVerified", "true"));

    // Custom requirement policies
    options.AddPolicy("AtLeast18", policy =>
        policy.Requirements.Add(new MinimumAgeRequirement(18)));

    options.AddPolicy("AtLeast21", policy =>
        policy.Requirements.Add(new MinimumAgeRequirement(21)));

    options.AddPolicy("BusinessHoursOnly", policy =>
        policy.Requirements.Add(new BusinessHoursRequirement()));

    options.AddPolicy("PremiumContent", policy =>
        policy.Requirements.Add(new SubscriptionRequirement("Premium", "Enterprise")));

    // Complex policy combining multiple requirements
    options.AddPolicy("AdminOrManager", policy =>
        policy.RequireRole("Admin", "Manager"));

    options.AddPolicy("AdminDuringBusinessHours", policy =>
    {
        policy.RequireRole("Admin");
        policy.Requirements.Add(new BusinessHoursRequirement());
    });

    // Policy using RequireAssertion for inline logic
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
builder.Services.AddSingleton<IAuthorizationHandler, BusinessHoursHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, SubscriptionHandler>();
```

### Using Policies in Controllers

```csharp
public class ContentController : Controller
{
    [Authorize(Policy = "AtLeast18")]
    public IActionResult AdultContent()
    {
        return View();
    }

    [Authorize(Policy = "PremiumContent")]
    public IActionResult PremiumVideos()
    {
        return View();
    }

    [Authorize(Policy = "BusinessHoursOnly")]
    public IActionResult AdminDashboard()
    {
        return View();
    }

    [Authorize(Policy = "AdminDuringBusinessHours")]
    public IActionResult SensitiveOperation()
    {
        return View();
    }
}
```

### Resource-Based Authorization

Sometimes authorization depends on the specific resource being accessed. Use imperative authorization checks:

```csharp
public class DocumentsController : Controller
{
    private readonly IAuthorizationService _authorizationService;
    private readonly IDocumentService _documentService;

    public DocumentsController(
        IAuthorizationService authorizationService,
        IDocumentService documentService)
    {
        _authorizationService = authorizationService;
        _documentService = documentService;
    }

    public async Task<IActionResult> Edit(int id)
    {
        var document = await _documentService.GetByIdAsync(id);
        if (document == null)
        {
            return NotFound();
        }

        // Resource-based authorization
        var result = await _authorizationService.AuthorizeAsync(
            User, document, "EditDocumentPolicy");

        if (!result.Succeeded)
        {
            return Forbid();
        }

        return View(document);
    }
}
```

Create a handler for resource-based authorization:

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

        // Check if user owns the document
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (resource.OwnerId == userId)
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        // Check if document is shared with user
        if (resource.SharedWith.Any(s => s.UserId == userId))
        {
            if (requirement.Name == DocumentOperations.Read.Name ||
                (requirement.Name == DocumentOperations.Edit.Name && 
                 resource.SharedWith.First(s => s.UserId == userId).CanEdit))
            {
                context.Succeed(requirement);
            }
        }

        return Task.CompletedTask;
    }
}

public class DocumentOperationRequirement : IAuthorizationRequirement
{
    public string Name { get; }

    public DocumentOperationRequirement(string name)
    {
        Name = name;
    }
}

public static class DocumentOperations
{
    public static DocumentOperationRequirement Read => 
        new DocumentOperationRequirement("Read");
    public static DocumentOperationRequirement Edit => 
        new DocumentOperationRequirement("Edit");
    public static DocumentOperationRequirement Delete => 
        new DocumentOperationRequirement("Delete");
}
```

---

## 13. Password Policies and Validation

### Built-in Password Validation

Identity provides configurable password validation through `PasswordOptions`. The default settings provide reasonable security, but you can customize them based on your requirements:

```csharp
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password settings
    options.Password.RequireDigit = true;           // Require at least one digit (0-9)
    options.Password.RequireLowercase = true;       // Require at least one lowercase letter
    options.Password.RequireUppercase = true;       // Require at least one uppercase letter
    options.Password.RequireNonAlphanumeric = true; // Require at least one special character
    options.Password.RequiredLength = 8;            // Minimum password length
    options.Password.RequiredUniqueChars = 1;       // Minimum number of distinct characters
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();
```

### Creating Custom Password Validators

For more complex password requirements, implement `IPasswordValidator<TUser>`:

```csharp
public class CustomPasswordValidator : IPasswordValidator<ApplicationUser>
{
    public Task<IdentityResult> ValidateAsync(
        UserManager<ApplicationUser> manager, 
        ApplicationUser user, 
        string? password)
    {
        var errors = new List<IdentityError>();

        if (string.IsNullOrEmpty(password))
        {
            return Task.FromResult(IdentityResult.Failed(
                new IdentityError { Code = "PasswordEmpty", Description = "Password is required" }));
        }

        // Check minimum length
        if (password.Length < 10)
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordTooShort",
                Description = "Password must be at least 10 characters long"
            });
        }

        // Check for common passwords
        var commonPasswords = new[] { "password", "123456", "qwerty", "letmein", "admin" };
        if (commonPasswords.Any(p => password.ToLower().Contains(p)))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordTooCommon",
                Description = "Password contains a common word or sequence"
            });
        }

        // Check for user information in password
        if (!string.IsNullOrEmpty(user.UserName) && 
            password.ToLower().Contains(user.UserName.ToLower()))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordContainsUsername",
                Description = "Password cannot contain your username"
            });
        }

        // Check for email in password
        if (!string.IsNullOrEmpty(user.Email))
        {
            var emailPrefix = user.Email.Split('@')[0];
            if (password.ToLower().Contains(emailPrefix.ToLower()))
            {
                errors.Add(new IdentityError
                {
                    Code = "PasswordContainsEmail",
                    Description = "Password cannot contain your email"
                });
            }
        }

        // Check for sequential characters
        if (HasSequentialChars(password, 3))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordHasSequence",
                Description = "Password cannot contain sequential characters like 'abc' or '123'"
            });
        }

        // Check for repeated characters
        if (HasRepeatedChars(password, 3))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordHasRepetition",
                Description = "Password cannot contain repeated characters like 'aaa' or '111'"
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

Register the custom validator:

```csharp
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password options...
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders()
.AddPasswordValidator<CustomPasswordValidator>();
```

### Password Strength Meter

For a better user experience, provide real-time password strength feedback on the frontend. Create an API endpoint:

```csharp
[HttpPost("check-password-strength")]
[AllowAnonymous]
public IActionResult CheckPasswordStrength([FromBody] PasswordStrengthRequest request)
{
    var score = 0;
    var feedback = new List<string>();

    if (request.Password.Length >= 8) score += 1;
    if (request.Password.Length >= 12) score += 1;
    if (request.Password.Any(char.IsLower)) score += 1;
    if (request.Password.Any(char.IsUpper)) score += 1;
    if (request.Password.Any(char.IsDigit)) score += 1;
    if (request.Password.Any(c => "!@#$%^&*()_+-=[]{}|;:,.<>?".Contains(c))) score += 2;

    // Deductions
    if (HasSequentialChars(request.Password, 3))
    {
        score -= 1;
        feedback.Add("Avoid sequential characters");
    }

    if (HasRepeatedChars(request.Password, 3))
    {
        score -= 1;
        feedback.Add("Avoid repeated characters");
    }

    var strength = score switch
    {
        <= 2 => "Weak",
        <= 4 => "Fair",
        <= 6 => "Good",
        _ => "Strong"
    };

    return Ok(new
    {
        Score = Math.Max(0, score),
        Strength = strength,
        Feedback = feedback
    });
}
```

---

## 14. Account Lockout and Security Features

### Configuring Account Lockout

Account lockout protects against brute force password attacks by temporarily disabling accounts after multiple failed login attempts:

```csharp
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();
```

The lockout settings control how Identity responds to failed login attempts:

- **DefaultLockoutTimeSpan**: How long the account remains locked after exceeding the failed attempt threshold. Common values are 5-30 minutes, balancing security against the risk of denial-of-service attacks.

- **MaxFailedAccessAttempts**: The number of failed attempts before lockout. Five attempts is a common default—low enough to prevent brute force attacks but high enough that legitimate users won't accidentally lock themselves out.

- **AllowedForNewUsers**: Whether lockout is enabled for newly created accounts. This should typically be true to protect all accounts from the moment they're created.

### Implementing Lockout in Login

The `PasswordSignInAsync` method handles lockout automatically when `lockoutOnFailure` is true:

```csharp
public async Task<IActionResult> Login(LoginViewModel model)
{
    // ... validation ...

    var result = await _signInManager.PasswordSignInAsync(
        model.Email,
        model.Password,
        model.RememberMe,
        lockoutOnFailure: true); // Enable lockout

    if (result.IsLockedOut)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
        var remainingTime = lockoutEnd - DateTimeOffset.UtcNow;

        ModelState.AddModelError(string.Empty,
            $"Account locked. Try again in {remainingTime?.Minutes ?? 0} minutes.");

        return View(model);
    }

    // ... handle other results ...
}
```

### Managing Lockout Programmatically

Admin operations for managing lockout:

```csharp
public class LockoutService
{
    private readonly UserManager<ApplicationUser> _userManager;

    public LockoutService(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    // Check if user is locked out
    public async Task<bool> IsLockedOutAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        return await _userManager.IsLockedOutAsync(user);
    }

    // Get remaining lockout time
    public async Task<TimeSpan?> GetRemainingLockoutTimeAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);

        if (lockoutEnd == null || lockoutEnd <= DateTimeOffset.UtcNow)
        {
            return null;
        }

        return lockoutEnd - DateTimeOffset.UtcNow;
    }

    // Manually lock a user account
    public async Task<IdentityResult> LockUserAsync(string userId, TimeSpan? duration = null)
    {
        var user = await _userManager.FindByIdAsync(userId);

        // Enable lockout if not already enabled
        if (!user.LockoutEnabled)
        {
            await _userManager.SetLockoutEnabledAsync(user, true);
        }

        // Reset failed attempts count
        await _userManager.ResetAccessFailedCountAsync(user);

        // Set lockout end time
        var lockoutEnd = duration.HasValue
            ? DateTimeOffset.UtcNow.Add(duration.Value)
            : DateTimeOffset.MaxValue; // Permanent lock

        return await _userManager.SetLockoutEndDateAsync(user, lockoutEnd);
    }

    // Unlock a user account
    public async Task<IdentityResult> UnlockUserAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);

        // Clear lockout
        var result = await _userManager.SetLockoutEndDateAsync(user, null);

        if (result.Succeeded)
        {
            // Reset failed attempts
            await _userManager.ResetAccessFailedCountAsync(user);
        }

        return result;
    }

    // Get failed attempt count
    public async Task<int> GetFailedAttemptCountAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        return await _userManager.GetAccessFailedCountAsync(user);
    }

    // Reset failed attempts
    public async Task<IdentityResult> ResetFailedAttemptsAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        return await _userManager.ResetAccessFailedCountAsync(user);
    }
}
```

### Security Stamp

The security stamp is a crucial security feature that enables immediate sign-out when important user properties change:

```csharp
// When password is changed
await _userManager.UpdateSecurityStampAsync(user);

// When roles are changed
await _userManager.UpdateSecurityStampAsync(user);

// When two-factor is enabled/disabled
await _userManager.UpdateSecurityStampAsync(user);
```

Configure security stamp validation in the cookie options:

```csharp
builder.Services.Configure<SecurityStampValidatorOptions>(options =>
{
    // How often to re-validate the security stamp
    options.ValidationInterval = TimeSpan.FromMinutes(30);
    
    // Path to redirect to when stamp validation fails
    options.OnRefreshingPrincipal = (context) =>
    {
        // Custom logic when principal is refreshed
        return Task.CompletedTask;
    };
});
```

When `UpdateSecurityStampAsync` is called, all existing authentication cookies become invalid because the stamp in the cookie no longer matches the stamp in the database. This provides a mechanism for immediate sign-out across all devices when security-critical changes occur.

---

## 15. Two-Factor Authentication (2FA)

### Understanding Two-Factor Authentication

Two-factor authentication adds an additional layer of security by requiring users to provide a second form of verification beyond their password. ASP.NET Core Identity supports multiple 2FA methods: authenticator apps (TOTP), SMS, and email codes. The TOTP (Time-based One-Time Password) method using authenticator apps like Google Authenticator or Microsoft Authenticator is the most secure and commonly used approach.

When 2FA is enabled for a user, the login flow changes. After successfully entering their password, the user is redirected to a 2FA verification page where they must enter a code from their authenticator app or receive a code via SMS/email. Only after providing the correct code is the sign-in completed. This dramatically improves security—even if an attacker obtains a user's password, they cannot access the account without also having access to the second factor.

### Setting Up 2FA

Add the Authenticator UI to your project:

```csharp
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

    [HttpGet]
    [Authorize]
    public async Task<IActionResult> EnableAuthenticator()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        // Load the authenticator key & generate QR code
        var authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(authenticatorKey))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        var model = new EnableAuthenticatorViewModel
        {
            SharedKey = FormatKey(authenticatorKey),
            AuthenticatorUri = GenerateQrCodeUri(user.Email, authenticatorKey)
        };

        return View(model);
    }

    [HttpPost]
    [Authorize]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EnableAuthenticator(EnableAuthenticatorViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        // Strip spaces and hyphens from the verification code
        var verificationCode = model.Code.Replace(" ", string.Empty)
                                         .Replace("-", string.Empty);

        var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
            user,
            _userManager.Options.Tokens.AuthenticatorTokenProvider,
            verificationCode);

        if (!is2faTokenValid)
        {
            ModelState.AddModelError("Code", "Verification code is invalid.");
            return View(model);
        }

        // Enable 2FA
        await _userManager.SetTwoFactorEnabledAsync(user, true);

        // Generate recovery codes
        var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);

        _logger.LogInformation("User enabled 2FA for account: {UserId}", user.Id);

        return RedirectToAction("ShowRecoveryCodes", new { recoveryCodes = string.Join(",", recoveryCodes) });
    }

    [HttpGet]
    [Authorize]
    public IActionResult ShowRecoveryCodes(string recoveryCodes)
    {
        if (string.IsNullOrEmpty(recoveryCodes))
        {
            return RedirectToAction("Index", "Home");
        }

        var model = new ShowRecoveryCodesViewModel
        {
            RecoveryCodes = recoveryCodes.Split(',').ToArray()
        };

        return View(model);
    }

    [HttpGet]
    [Authorize]
    public async Task<IActionResult> Disable2fa()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        if (!await _userManager.GetTwoFactorEnabledAsync(user))
        {
            return BadRequest("Cannot disable 2FA as it's not currently enabled.");
        }

        return View();
    }

    [HttpPost]
    [Authorize]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Disable2faConfirmed()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        var result = await _userManager.SetTwoFactorEnabledAsync(user, false);
        if (!result.Succeeded)
        {
            return BadRequest("Failed to disable 2FA.");
        }

        _logger.LogInformation("User disabled 2FA for account: {UserId}", user.Id);

        return RedirectToAction("Index", "Manage");
    }

    private static string FormatKey(string unformattedKey)
    {
        var result = new StringBuilder();
        int currentPosition = 0;
        while (currentPosition + 4 < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition, 4)).Append(' ');
            currentPosition += 4;
        }
        if (currentPosition < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition));
        }

        return result.ToString().ToLowerInvariant();
    }

    private string GenerateQrCodeUri(string email, string secretKey)
    {
        var issuer = UrlEncoder.Encode("YourAppName");
        var userEmail = UrlEncoder.Encode(email);
        return $"otpauth://totp/{issuer}:{userEmail}?secret={secretKey}&issuer={issuer}&digits=6";
    }
}
```

### Handling 2FA During Login

Modify the login process to handle 2FA:

```csharp
[HttpPost]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
{
    // ... existing validation ...

    var result = await _signInManager.PasswordSignInAsync(
        model.Email,
        model.Password,
        model.RememberMe,
        lockoutOnFailure: true);

    if (result.RequiresTwoFactor)
    {
        // Redirect to 2FA verification
        return RedirectToAction("LoginWith2fa", new { returnUrl, model.RememberMe });
    }

    // ... handle other results ...
}

[HttpGet]
[AllowAnonymous]
public async Task<IActionResult> LoginWith2fa(bool rememberMe, string? returnUrl = null)
{
    // Ensure the user has gone through the username & password screen first
    var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

    if (user == null)
    {
        throw new InvalidOperationException("Unable to load two-factor authentication user.");
    }

    var model = new LoginWith2faViewModel { RememberMe = rememberMe };
    ViewData["ReturnUrl"] = returnUrl;

    return View(model);
}

[HttpPost]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public async Task<IActionResult> LoginWith2fa(LoginWith2faViewModel model, bool rememberMe, string? returnUrl = null)
{
    if (!ModelState.IsValid)
    {
        return View(model);
    }

    var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
    if (user == null)
    {
        throw new InvalidOperationException("Unable to load two-factor authentication user.");
    }

    var authenticatorCode = model.TwoFactorCode.Replace(" ", string.Empty)
                                                .Replace("-", string.Empty);

    var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(
        authenticatorCode,
        rememberMe,
        model.RememberMachine);

    if (result.Succeeded)
    {
        _logger.LogInformation("User with ID '{UserId}' logged in with 2fa.", user.Id);
        return RedirectToLocal(returnUrl);
    }

    if (result.IsLockedOut)
    {
        _logger.LogWarning("User with ID '{UserId}' account locked out.", user.Id);
        return RedirectToAction("Lockout");
    }

    _logger.LogWarning("Invalid authenticator code entered for user with ID '{UserId}'.", user.Id);
    ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
    return View(model);
}

[HttpGet]
[AllowAnonymous]
public async Task<IActionResult> LoginWithRecoveryCode(string? returnUrl = null)
{
    var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
    if (user == null)
    {
        throw new InvalidOperationException("Unable to load two-factor authentication user.");
    }

    ViewData["ReturnUrl"] = returnUrl;
    return View();
}

[HttpPost]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public async Task<IActionResult> LoginWithRecoveryCode(
    LoginWithRecoveryCodeViewModel model, 
    string? returnUrl = null)
{
    if (!ModelState.IsValid)
    {
        return View(model);
    }

    var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
    if (user == null)
    {
        throw new InvalidOperationException("Unable to load two-factor authentication user.");
    }

    var recoveryCode = model.RecoveryCode.Replace(" ", string.Empty);

    var result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

    if (result.Succeeded)
    {
        _logger.LogInformation("User with ID '{UserId}' logged in with a recovery code.", user.Id);
        return RedirectToLocal(returnUrl);
    }

    if (result.IsLockedOut)
    {
        _logger.LogWarning("User with ID '{UserId}' account locked out.", user.Id);
        return RedirectToAction("Lockout");
    }

    _logger.LogWarning("Invalid recovery code entered for user with ID '{UserId}'.", user.Id);
    ModelState.AddModelError(string.Empty, "Invalid recovery code.");
    return View(model);
}
```

---

## 16. External Authentication Providers

### Setting Up External Login Providers

ASP.NET Core Identity supports external authentication providers like Google, Facebook, Microsoft, Twitter, and others. This allows users to sign in using their existing accounts on these platforms, simplifying the registration and login process while providing a more secure authentication method (since these providers have sophisticated security measures).

First, register your application with the external provider to obtain client ID and secret:

```csharp
// In Program.cs
builder.Services.AddAuthentication()
    .AddGoogle(options =>
    {
        options.ClientId = builder.Configuration["Authentication:Google:ClientId"]!;
        options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"]!;
        options.CallbackPath = "/signin-google";
        
        // Request additional scopes
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

Store credentials in `appsettings.json` (or better, in user secrets or environment variables):

```json
{
  "Authentication": {
    "Google": {
      "ClientId": "your-google-client-id",
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

### Handling External Login

Create controller actions to handle external login:

```csharp
[HttpPost]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public IActionResult ExternalLogin(string provider, string? returnUrl = null)
{
    // Request a redirect to the external login provider
    var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { returnUrl });
    var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
    return Challenge(properties, provider);
}

[HttpGet]
[AllowAnonymous]
public async Task<IActionResult> ExternalLoginCallback(string? returnUrl = null, string? remoteError = null)
{
    if (remoteError != null)
    {
        ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
        return RedirectToAction("Login");
    }

    var info = await _signInManager.GetExternalLoginInfoAsync();
    if (info == null)
    {
        return RedirectToAction("Login");
    }

    // Sign in the user with this external login provider if they already have an account
    var result = await _signInManager.ExternalLoginSignInAsync(
        info.LoginProvider,
        info.ProviderKey,
        isPersistent: false,
        bypassTwoFactor: true);

    if (result.Succeeded)
    {
        _logger.LogInformation("User logged in with {Name} provider.", info.LoginProvider);
        return RedirectToLocal(returnUrl);
    }

    if (result.IsLockedOut)
    {
        return RedirectToAction("Lockout");
    }

    // If the user does not have an account, show registration form
    var email = info.Principal.FindFirstValue(ClaimTypes.Email);
    var name = info.Principal.FindFirstValue(ClaimTypes.Name);

    var model = new ExternalLoginViewModel
    {
        Email = email,
        Name = name,
        Provider = info.LoginProvider,
        ReturnUrl = returnUrl
    };

    return View("ExternalLoginConfirmation", model);
}

[HttpPost]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginViewModel model, string? returnUrl = null)
{
    if (!ModelState.IsValid)
    {
        return View(model);
    }

    var info = await _signInManager.GetExternalLoginInfoAsync();
    if (info == null)
    {
        return RedirectToAction("Login");
    }

    // Check if email already exists
    var existingUser = await _userManager.FindByEmailAsync(model.Email);
    if (existingUser != null)
    {
        // Add external login to existing account
        var addLoginResult = await _userManager.AddLoginAsync(existingUser, info);
        if (addLoginResult.Succeeded)
        {
            await _signInManager.SignInAsync(existingUser, isPersistent: false);
            return RedirectToLocal(returnUrl);
        }

        AddErrors(addLoginResult);
        return View(model);
    }

    // Create new user
    var user = new ApplicationUser
    {
        UserName = model.Email,
        Email = model.Email,
        FirstName = model.Name?.Split(' ').FirstOrDefault(),
        LastName = model.Name?.Split(' ').Skip(1).FirstOrDefault(),
        EmailConfirmed = true, // External providers verify email
        CreatedAt = DateTime.UtcNow
    };

    var createResult = await _userManager.CreateAsync(user);
    if (createResult.Succeeded)
    {
        // Add external login
        var addLoginResult = await _userManager.AddLoginAsync(user, info);
        if (addLoginResult.Succeeded)
        {
            // Add default role
            await _userManager.AddToRoleAsync(user, "User");

            await _signInManager.SignInAsync(user, isPersistent: false);
            _logger.LogInformation("User created account using {Provider} provider.", info.LoginProvider);
            return RedirectToLocal(returnUrl);
        }

        // If adding login fails, delete the created user
        await _userManager.DeleteAsync(user);
        AddErrors(addLoginResult);
    }
    else
    {
        AddErrors(createResult);
    }

    return View(model);
}
```

### Managing External Logins

Users may want to add or remove external logins from their account:

```csharp
[HttpGet]
[Authorize]
public async Task<IActionResult> ExternalLogins()
{
    var user = await _userManager.GetUserAsync(User);
    if (user == null)
    {
        return NotFound();
    }

    var currentLogins = await _userManager.GetLoginsAsync(user);
    var otherLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync())
        .Where(auth => currentLogins.All(ul => auth.Name != ul.LoginProvider))
        .ToList();

    var model = new ExternalLoginsViewModel
    {
        CurrentLogins = currentLogins,
        OtherLogins = otherLogins,
        ShowRemoveButton = user.PasswordHash != null || currentLogins.Count > 1
    };

    return View(model);
}

[HttpPost]
[Authorize]
[ValidateAntiForgeryToken]
public async Task<IActionResult> LinkLogin(string provider)
{
    // Request a redirect to the external login provider to link a login
    var redirectUrl = Url.Action("LinkLoginCallback");
    var properties = _signInManager.ConfigureExternalAuthenticationProperties(
        provider, 
        redirectUrl, 
        _userManager.GetUserId(User));
    
    return Challenge(properties, provider);
}

[HttpGet]
[Authorize]
public async Task<IActionResult> LinkLoginCallback()
{
    var user = await _userManager.GetUserAsync(User);
    if (user == null)
    {
        return NotFound();
    }

    var info = await _signInManager.GetExternalLoginInfoAsync(_userManager.GetUserId(User));
    if (info == null)
    {
        return RedirectToAction("ExternalLogins", new { Message = ManageMessageId.Error });
    }

    var result = await _userManager.AddLoginAsync(user, info);
    if (!result.Succeeded)
    {
        return RedirectToAction("ExternalLogins", new { Message = ManageMessageId.Error });
    }

    // Clear the existing external cookie
    await _signInManager.SignOutAsync();

    // Sign in the user with the new external login
    await _signInManager.SignInAsync(user, isPersistent: false);

    return RedirectToAction("ExternalLogins", new { Message = ManageMessageId.AddLoginSuccess });
}

[HttpPost]
[Authorize]
[ValidateAntiForgeryToken]
public async Task<IActionResult> RemoveLogin(RemoveLoginViewModel model)
{
    var user = await _userManager.GetUserAsync(User);
    if (user == null)
    {
        return NotFound();
    }

    var result = await _userManager.RemoveLoginAsync(user, model.LoginProvider, model.ProviderKey);
    if (!result.Succeeded)
    {
        return RedirectToAction("ExternalLogins", new { Message = ManageMessageId.Error });
    }

    await _signInManager.SignInAsync(user, isPersistent: false);
    return RedirectToAction("ExternalLogins", new { Message = ManageMessageId.RemoveLoginSuccess });
}
```

---

## 17. Token Providers and Usage

### Understanding Token Providers

Identity uses token providers for generating and validating tokens used in various security-sensitive operations: email confirmation, password reset, phone number change, and two-factor authentication. The default token provider uses the Data Protection API to generate tokens that are cryptographically secure and bound to a specific purpose and user.

Token providers implement `IUserTwoFactorTokenProvider<TUser>` and are registered in Identity configuration. When you call methods like `GenerateEmailConfirmationTokenAsync` or `GeneratePasswordResetTokenAsync`, Identity uses the appropriate registered provider to create a token. The token is then validated using the same provider when the user submits it.

### Default Token Providers

Identity includes several built-in token providers:

- **DataProtectorTokenProvider**: The default provider for email confirmation, password reset, and similar tokens. Uses ASP.NET Core Data Protection to encrypt and sign tokens.

- **AuthenticatorTokenProvider**: Used for TOTP-based two-factor authentication with authenticator apps.

- **PhoneNumberTokenProvider**: Generates numeric tokens suitable for SMS-based two-factor authentication.

- **EmailTokenProvider**: Generates short tokens suitable for email-based two-factor authentication.

### Configuring Token Lifetimes

Configure token lifetimes based on the security requirements of each operation:

```csharp
builder.Services.Configure<DataProtectorTokenProviderOptions>(options =>
{
    // Default token lifetime for password reset, email confirmation, etc.
    options.TokenLifespan = TimeSpan.FromHours(3);
});

builder.Services.Configure<EmailConfirmationTokenProviderOptions>(options =>
{
    // Longer lifetime for email confirmation (users might not check email immediately)
    options.TokenLifespan = TimeSpan.FromDays(7);
});

builder.Services.Configure<PasswordResetTokenProviderOptions>(options =>
{
    // Shorter lifetime for password reset (security-sensitive)
    options.TokenLifespan = TimeSpan.FromHours(1);
});
```

### Creating a Custom Token Provider

For specialized requirements, create a custom token provider:

```csharp
public class ShortLivedTokenProvider : IUserTwoFactorTokenProvider<ApplicationUser>
{
    public const string ProviderName = "ShortLived";

    public Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<ApplicationUser> manager, ApplicationUser user)
    {
        return Task.FromResult(true);
    }

    public Task<string> GenerateAsync(string purpose, UserManager<ApplicationUser> manager, ApplicationUser user)
    {
        // Generate a 6-digit numeric token
        var random = new Random();
        var token = random.Next(100000, 999999).ToString();
        
        // In production, you'd store this securely associated with the user and purpose
        // and set an expiration time
        
        return Task.FromResult(token);
    }

    public Task<bool> ValidateAsync(string purpose, string token, UserManager<ApplicationUser> manager, ApplicationUser user)
    {
        // Validate the token against stored value
        // This is a simplified example - production code would use secure storage
        
        return Task.FromResult(!string.IsNullOrEmpty(token) && token.Length == 6);
    }
}

// Register the provider
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders()
    .AddTokenProvider<ShortLivedTokenProvider>(ShortLivedTokenProvider.ProviderName);

// Use the custom provider
var token = await _userManager.GenerateUserTokenAsync(
    user, 
    ShortLivedTokenProvider.ProviderName, 
    "MyPurpose");

var isValid = await _userManager.VerifyUserTokenAsync(
    user,
    ShortLivedTokenProvider.ProviderName,
    "MyPurpose",
    token);
```

---

## 18. Customizing Identity

### Extending IdentityUser and IdentityRole

We've covered creating custom user and role classes earlier, but let's explore more advanced customization scenarios. When you extend IdentityUser, your custom properties are automatically included in the database schema. You can also add validation, computed properties, and navigation properties:

```csharp
public class ApplicationUser : IdentityUser<int>
{
    // Personal Information
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    
    // Computed property (not stored in database)
    [NotMapped]
    public string FullName => $"{FirstName} {LastName}".Trim();
    
    // User preferences
    public string? TimeZone { get; set; } = "UTC";
    public string? Language { get; set; } = "en";
    public string? Theme { get; set; } = "light";
    
    // Notification preferences
    public bool EmailNotificationsEnabled { get; set; } = true;
    public bool SmsNotificationsEnabled { get; set; } = false;
    
    // Profile information
    public string? AvatarUrl { get; set; }
    public string? Bio { get; set; }
    
    // Account status
    public AccountStatus Status { get; set; } = AccountStatus.Active;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }
    public DateTime? EmailConfirmedAt { get; set; }
    
    // Subscription information
    public SubscriptionTier SubscriptionTier { get; set; } = SubscriptionTier.Free;
    public DateTime? SubscriptionExpiresAt { get; set; }
    
    // Navigation properties
    public virtual ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    public virtual ICollection<UserClaim> Claims { get; set; } = new List<UserClaim>();
    public virtual ICollection<UserLogin> Logins { get; set; } = new List<UserLogin>();
    public virtual ICollection<UserToken> Tokens { get; set; } = new List<UserToken>();
    public virtual ICollection<UserActivity> Activities { get; set; } = new List<UserActivity>();
}

public enum AccountStatus
{
    Active,
    Suspended,
    Deleted,
    PendingVerification
}

public enum SubscriptionTier
{
    Free,
    Basic,
    Premium,
    Enterprise
}

// Activity tracking
public class UserActivity
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public ApplicationUser User { get; set; } = null!;
    public string ActivityType { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}
```

### Custom User Store

For advanced scenarios where you need complete control over data access, implement custom stores:

```csharp
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

    public async Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        _context.Users.Add(user);
        await _context.SaveChangesAsync(cancellationToken);
        return IdentityResult.Success;
    }

    public async Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        _context.Users.Update(user);
        await _context.SaveChangesAsync(cancellationToken);
        return IdentityResult.Success;
    }

    public async Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        _context.Users.Remove(user);
        await _context.SaveChangesAsync(cancellationToken);
        return IdentityResult.Success;
    }

    public Task<ApplicationUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
    {
        return _context.Users.FindAsync(new object[] { int.Parse(userId) }, cancellationToken).AsTask();
    }

    public Task<ApplicationUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        return _context.Users
            .FirstOrDefaultAsync(u => u.NormalizedUserName == normalizedUserName, cancellationToken);
    }

    public Task<string?> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        return Task.FromResult(user.NormalizedUserName);
    }

    public Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        return Task.FromResult(user.Id.ToString());
    }

    public Task<string?> GetUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        return Task.FromResult(user.UserName);
    }

    public Task SetNormalizedUserNameAsync(ApplicationUser user, string? normalizedName, CancellationToken cancellationToken)
    {
        user.NormalizedUserName = normalizedName;
        return Task.CompletedTask;
    }

    public Task SetUserNameAsync(ApplicationUser user, string? userName, CancellationToken cancellationToken)
    {
        user.UserName = userName;
        return Task.CompletedTask;
    }

    // Implement other interface methods similarly...

    public void Dispose()
    {
        // Clean up resources if needed
    }
}
```

### Custom SignInManager

Override SignInManager to customize sign-in behavior:

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
        : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
    {
        _logger = logger;
    }

    public override async Task<SignInResult> PasswordSignInAsync(
        string userName, 
        string password,
        bool isPersistent, 
        bool lockoutOnFailure)
    {
        var user = await UserManager.FindByNameAsync(userName);
        if (user == null)
        {
            return SignInResult.Failed;
        }

        // Custom check: Account status
        if (user.Status != AccountStatus.Active)
        {
            _logger.LogWarning("Login attempt for inactive account: {UserId}", user.Id);
            return SignInResult.NotAllowed;
        }

        // Check subscription status for premium features
        if (user.SubscriptionTier != SubscriptionTier.Free && 
            user.SubscriptionExpiresAt.HasValue && 
            user.SubscriptionExpiresAt < DateTime.UtcNow)
        {
            // Subscription expired - could downgrade to free tier
            user.SubscriptionTier = SubscriptionTier.Free;
            await UserManager.UpdateAsync(user);
        }

        return await base.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure);
    }

    public override async Task SignInAsync(
        ApplicationUser user, 
        bool isPersistent, 
        string? authenticationMethod = null)
    {
        // Update last login time
        user.LastLoginAt = DateTime.UtcNow;
        await UserManager.UpdateAsync(user);

        // Log the sign-in
        _logger.LogInformation("User signed in: {UserId} at {Time}", user.Id, DateTime.UtcNow);

        await base.SignInAsync(user, isPersistent, authenticationMethod);
    }
}

// Register in Program.cs
builder.Services.AddScoped<SignInManager<ApplicationUser>, CustomSignInManager>();
```

---

## 19. Best Practices and Security

### Security Best Practices

**Password Security:**
- Use strong password policies but don't make them overly complex (NIST recommends minimum 8 characters, checking against known breached passwords)
- Implement password hashing automatically through Identity (PBKDF2 with HMAC-SHA256)
- Consider using breach password checking services
- Never store or log passwords in plain text

**Account Security:**
- Enable account lockout to prevent brute force attacks
- Implement two-factor authentication for sensitive operations
- Use security stamps to invalidate sessions on security-relevant changes
- Implement password reset with short-lived tokens

**Session Security:**
- Use secure, HttpOnly cookies for authentication
- Set appropriate cookie expiration times
- Implement sliding expiration for active users
- Consider implementing concurrent session limits

**General Security:**
- Always use HTTPS in production
- Validate all user inputs
- Implement rate limiting on authentication endpoints
- Log security-relevant events (login attempts, password changes, etc.)
- Keep Identity packages updated

### Configuration for Production

```csharp
// Production-ready Identity configuration
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

    // User settings
    options.User.RequireUniqueEmail = true;

    // Sign-in settings
    options.SignIn.RequireConfirmedEmail = true;
    options.SignIn.RequireConfirmedPhoneNumber = false;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Secure cookie configuration
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // HTTPS only
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.ExpireTimeSpan = TimeSpan.FromHours(1);
    options.SlidingExpiration = true;
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
});

// Security stamp validation
builder.Services.Configure<SecurityStampValidatorOptions>(options =>
{
    options.ValidationInterval = TimeSpan.FromMinutes(30);
});
```

### Audit Logging

Implement comprehensive audit logging for security events:

```csharp
public class AuditLogService
{
    private readonly ApplicationDbContext _context;

    public AuditLogService(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task LogAsync(string userId, string action, string description, 
        string? ipAddress = null, string? userAgent = null)
    {
        var log = new AuditLog
        {
            UserId = userId,
            Action = action,
            Description = description,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Timestamp = DateTime.UtcNow
        };

        _context.AuditLogs.Add(log);
        await _context.SaveChangesAsync();
    }
}

public class AuditLog
{
    public int Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public DateTime Timestamp { get; set; }
}

// Use in AccountController
public async Task<IActionResult> Login(LoginViewModel model)
{
    // ... validation ...

    if (result.Succeeded)
    {
        await _auditLogService.LogAsync(
            user.Id,
            "LOGIN",
            "User logged in successfully",
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            Request.Headers.UserAgent);

        // ... continue with login ...
    }
    else
    {
        await _auditLogService.LogAsync(
            user?.Id ?? "UNKNOWN",
            "LOGIN_FAILED",
            $"Failed login attempt for {model.Email}",
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            Request.Headers.UserAgent);
    }
}
```

---

## 20. Troubleshooting Common Issues

### Common Errors and Solutions

**"No authentication handler is configured"**
```
Error: No authentication handler is configured to authenticate for the scheme: Identity.Application

Solution: Ensure app.UseAuthentication() is called before app.UseAuthorization() in Program.cs.
The middleware order matters: Authentication must precede Authorization.
```

**"The entity type 'IdentityUserLogin<string>' requires a primary key"**
```
Error: The entity type 'IdentityUserLogin<string>' requires a primary key to be defined.

Solution: Ensure your DbContext inherits from IdentityDbContext, not just DbContext.
IdentityDbContext configures all the required keys and relationships.
```

**User is not authenticated after successful login**
```
Possible causes:
1. Authentication middleware missing: Add app.UseAuthentication()
2. Wrong middleware order: Authentication must come before Authorization
3. Cookie not being created: Check browser settings for cookie blocking
4. Scheme mismatch: Ensure default scheme is configured

Solution:
app.UseRouting();
app.UseAuthentication(); // Must come before Authorization
app.UseAuthorization();
```

**Role authorization not working**
```
Possible causes:
1. User doesn't actually have the role: Check database with _userManager.IsInRoleAsync()
2. Cookie doesn't include role claims: Sign out and sign in again to refresh cookie
3. Role name mismatch: Check case sensitivity (role names are typically stored uppercase)

Debug steps:
var roles = await _userManager.GetRolesAsync(user);
var isInRole = await _userManager.IsInRoleAsync(user, "Admin");
var cookieRoles = User.Claims.Where(c => c.Type == ClaimTypes.Role);
```

**Email confirmation token invalid**
```
Possible causes:
1. Token already used: Tokens are single-use
2. Token expired: Check TokenLifespan configuration
3. Security stamp changed: User's security stamp was updated after token generation
4. URL encoding issues: Token contains special characters that need proper encoding

Solution:
var decodedToken = WebUtility.UrlDecode(token);
var result = await _userManager.ConfirmEmailAsync(user, decodedToken);
```

**"Cannot resolve scoped service from root provider"**
```
Error when trying to access UserManager or other scoped services from singleton services.

Solution: Inject IServiceProvider and create a scope:
using var scope = _serviceProvider.CreateScope();
var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
```

### Debugging Tips

Enable detailed error messages in development:

```csharp
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseDatabaseErrorPage(); // For EF Core errors
}
```

Add logging to track authentication events:

```csharp
builder.Services.Configure<SecurityStampValidatorOptions>(options =>
{
    options.OnRefreshingPrincipal = (context) =>
    {
        var logger = context.HttpContext.RequestServices
            .GetRequiredService<ILogger<Program>>();
        logger.LogInformation("Security stamp validation for user: {UserId}",
            context.NewPrincipal?.FindFirst(ClaimTypes.NameIdentifier)?.Value);
        return Task.CompletedTask;
    };
});
```

Use middleware to log authentication events:

```csharp
app.Use(async (context, next) =>
{
    var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
    
    logger.LogInformation("Request: {Path} User: {User} Authenticated: {IsAuth}",
        context.Request.Path,
        context.User?.Identity?.Name ?? "Anonymous",
        context.User?.Identity?.IsAuthenticated ?? false);

    await next();

    logger.LogInformation("Response: {StatusCode}", context.Response.StatusCode);
});
```

---

## Summary

This comprehensive guide has covered ASP.NET Core Identity from fundamentals to advanced implementation:

- **Core Concepts**: Understanding Identity architecture, users, roles, claims, and the managers that orchestrate them
- **Setup and Configuration**: Installing packages, configuring services, and setting up database persistence
- **User Management**: Registration, authentication, profile management, and administrative operations
- **Role-Based Access Control**: Creating roles, assigning users to roles, and implementing RBAC
- **Claims and Policies**: Fine-grained authorization using claims and custom policy requirements
- **Security Features**: Password validation, account lockout, two-factor authentication, and external providers
- **Customization**: Extending Identity entities, implementing custom stores and managers
- **Best Practices**: Security configuration, audit logging, and production deployment

By mastering these concepts, you can implement robust, secure authentication and authorization for any .NET application. Identity provides a solid foundation that handles the complexities of authentication, allowing you to focus on your application's unique requirements while following industry best practices.

---

*Created for educational purposes. Made With Love ❤️*
