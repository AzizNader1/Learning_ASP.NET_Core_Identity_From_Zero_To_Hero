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

*(Continuing with Videos 13-19 in the next response to keep each chunk manageable. The structure remains identical: Theory + 🎬 Recording Notes + Complete Commented Code + Postman Tests for every video.)*
