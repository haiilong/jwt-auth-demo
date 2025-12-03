using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Scalar.AspNetCore;

var builder = WebApplication.CreateSlimBuilder(args);

// --- CONFIG ---
var jwtSettings = new
{
    Key = "SuperSecretKey1234567890123456789012345", 
    Issuer = "MyApi",
    Audience = "MyClient",
    AccessTokenMinutes = 1, // Short time to test auto-refresh
    RefreshTokenDays = 7
};

// --- AUTH SERVICES ---
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtSettings.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtSettings.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key)),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
        };
        
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                // 1. Check Header first (Middleware might put it here)
                // 2. Check Cookie second
                if (context.Request.Cookies.TryGetValue("X-Access-Token", out var token))
                {
                    context.Token = token;
                }
                return Task.CompletedTask;
            }
        };
    });
builder.Services.AddAuthorization();

// --- OPENAPI ---
builder.Services.AddOpenApi("v1", options =>
{
    options.AddDocumentTransformer((document, _, _) =>
    {
        document.Info = new OpenApiInfo { Title = "Auto-Refresh API", Version = "v1" };
        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes.Add("CookieAuth", new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.ApiKey, In = ParameterLocation.Cookie, Name = "X-Access-Token", 
            Description = "Auth handled automatically via Cookies"
        });
        return Task.CompletedTask;
    });

    options.AddOperationTransformer((operation, context, _) =>
    {
        if (context.Description.ActionDescriptor.EndpointMetadata.OfType<IAuthorizeData>().Any())
        {
            operation.Security = new List<OpenApiSecurityRequirement>
            {
                new() { { new OpenApiSecurityScheme { Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "CookieAuth" } }, Array.Empty<string>() } }
            };
        }
        return Task.CompletedTask;
    });
});

var app = builder.Build();

// --- DATA ---
var users = new List<User> 
{ 
    new(1, "admin", "password", "Admin"),
    new(2, "bob", "password", "User") 
};

var userRefreshTokenDict = new Dictionary<string, string>();

// --- MIDDLEWARE PIPELINE ---

app.MapOpenApi();
app.MapGet("/", () => Results.Redirect("/scalar")).ExcludeFromDescription();
app.MapScalarApiReference(options =>
{
    options.Title = "API";
    options.Layout = ScalarLayout.Classic;
    options.HideModels = true;
    options.HideSearch = true;
    options.ShowDeveloperTools = DeveloperToolsVisibility.Never;
    options.AddPreferredSecuritySchemes("CookieAuth");
});

// ============================================================================
// 1. AUTO-REFRESH MIDDLEWARE (Inserted BEFORE UseAuthentication)
// ============================================================================
app.Use(async (context, next) =>
{
    var accessToken = context.Request.Cookies["X-Access-Token"];
    
    // If we have a token, and it is expired (or missing), but we have a Refresh Cookie...
    if (IsTokenExpired(accessToken) && context.Request.Cookies.TryGetValue("X-Refresh-Token", out var refreshToken) && context.Request.Cookies.TryGetValue("X-Username", out var username))
    {
        // Validate Refresh Token
        if (userRefreshTokenDict.TryGetValue(username!, out var storedRefreshToken) && storedRefreshToken == refreshToken)
        {
            var user = users.FirstOrDefault(u => u.Username == username);
            if (user != null)
            {
                // 1. Generate NEW Tokens
                var newAccessToken = GenerateAccessToken(user, jwtSettings.Key, jwtSettings.Issuer, jwtSettings.Audience, jwtSettings.AccessTokenMinutes);
                var newRefreshToken = GenerateRefreshToken();

                // 2. Update DB
                userRefreshTokenDict[username!] = newRefreshToken;

                // 3. Update Response Cookies (So browser stays logged in)
                context.Response.Cookies.Append("X-Access-Token", newAccessToken, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Expires = DateTime.UtcNow.AddMinutes(jwtSettings.AccessTokenMinutes) });
                context.Response.Cookies.Append("X-Refresh-Token", newRefreshToken, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Expires = DateTime.UtcNow.AddDays(jwtSettings.RefreshTokenDays) });
                
                // 4. IMPORTANT: Update the CURRENT REQUEST Header
                // We inject the new token into the header so the 'UseAuthentication' middleware below 
                // sees a valid token immediately and doesn't fail the request.
                context.Request.Headers.Append("Authorization", "Bearer " + newAccessToken);
            }
        }
    }

    await next();
});

// ============================================================================

app.UseAuthentication();
app.UseAuthorization();

// --- ENDPOINTS ---

app.MapPost("/login", (LoginDto loginData, HttpContext http) =>
{
    var user = users.FirstOrDefault(u => u.Username == loginData.Username && u.Password == loginData.Password);
    if (user is null) return Results.Unauthorized();

    var accessToken = GenerateAccessToken(user, jwtSettings.Key, jwtSettings.Issuer, jwtSettings.Audience, jwtSettings.AccessTokenMinutes);
    var refreshToken = GenerateRefreshToken();
    
    userRefreshTokenDict[user.Username] = refreshToken;
    
    var cookieOpts = new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict };
    
    http.Response.Cookies.Append("X-Access-Token", accessToken, 
        new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Expires = DateTime.UtcNow.AddMinutes(jwtSettings.AccessTokenMinutes) });
    
    http.Response.Cookies.Append("X-Refresh-Token", refreshToken, 
        new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Expires = DateTime.UtcNow.AddDays(jwtSettings.RefreshTokenDays) });
    
    http.Response.Cookies.Append("X-Username", user.Username, cookieOpts);

    return Results.Ok(new { message = "Logged in via Cookies" });
});

app.MapPost("/refresh", (HttpContext http) =>
{
    // Manual refresh endpoint is still useful for explicit calls
    http.Request.Cookies.TryGetValue("X-Refresh-Token", out var cookieRefreshToken);
    http.Request.Cookies.TryGetValue("X-Username", out var cookieUsername);

    if (string.IsNullOrEmpty(cookieRefreshToken) || string.IsNullOrEmpty(cookieUsername)) return Results.Unauthorized();
    if (!userRefreshTokenDict.TryGetValue(cookieUsername, out var storedRefreshToken) || storedRefreshToken != cookieRefreshToken) return Results.Forbid();

    var user = users.FirstOrDefault(u => u.Username == cookieUsername);
    if (user is null) return Results.Forbid();
        
    var newAccessToken = GenerateAccessToken(user, jwtSettings.Key, jwtSettings.Issuer, jwtSettings.Audience, jwtSettings.AccessTokenMinutes);
    var newRefreshToken = GenerateRefreshToken();
    userRefreshTokenDict[user.Username] = newRefreshToken;
    
    http.Response.Cookies.Append("X-Access-Token", newAccessToken, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Expires = DateTime.UtcNow.AddMinutes(jwtSettings.AccessTokenMinutes) });
    http.Response.Cookies.Append("X-Refresh-Token", newRefreshToken, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Expires = DateTime.UtcNow.AddDays(jwtSettings.RefreshTokenDays) });

    return Results.Ok(new { message = "Refreshed via Cookies" });
});

app.MapGet("/dashboard", () => "Hello User!").RequireAuthorization();
app.MapGet("/admin-only", () => "Hello Admin!").RequireAuthorization(new AuthorizeAttribute { Roles = "Admin" });

app.Run();
return;

// --- HELPERS ---

// NEW HELPER: Checks if token string is expired
bool IsTokenExpired(string? token)
{
    if (string.IsNullOrEmpty(token)) return true;
    var handler = new JwtSecurityTokenHandler();
    if (!handler.CanReadToken(token)) return true;
    
    try
    {
        var jwt = handler.ReadJwtToken(token);
        // Check if ValidTo is in the past
        return jwt.ValidTo < DateTime.UtcNow;
    }
    catch
    {
        return true;
    }
}

string GenerateAccessToken(User user, string key, string issuer, string audience, int minutes)
{
    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
    var creds = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
    var claims = new[] { new Claim(ClaimTypes.Name, user.Username), new Claim(ClaimTypes.Role, user.Role) };
    var token = new JwtSecurityToken(issuer, audience, claims, expires: DateTime.UtcNow.AddMinutes(minutes), signingCredentials: creds);
    return new JwtSecurityTokenHandler().WriteToken(token);
}
string GenerateRefreshToken()
{
    var randomNumber = new byte[32];
    using var rng = RandomNumberGenerator.Create();
    rng.GetBytes(randomNumber);
    return Convert.ToBase64String(randomNumber);
}

internal record User(int Id, string Username, string Password, string Role);
internal record LoginDto(string Username, string Password);