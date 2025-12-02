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
    AccessTokenMinutes = 1,
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
                if (context.Request.Cookies.TryGetValue("X-Access-Token", out var token))
                {
                    context.Token = token;
                }
                return Task.CompletedTask;
            }
        };
    });
builder.Services.AddAuthorization();

// --- OPENAPI (Cookie Definition) ---
builder.Services.AddOpenApi("v1", options =>
{
    // 1. Define "Cookie" Scheme
    options.AddDocumentTransformer((document, _, _) =>
    {
        document.Info = new OpenApiInfo { Title = "Cookie API", Version = "v1" };
        document.Components ??= new OpenApiComponents();

        document.Components.SecuritySchemes.Add("CookieAuth", new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.ApiKey,
            In = ParameterLocation.Cookie,
            Name = "X-Access-Token", 
            Description = "Auth handled automatically via Cookies"
        });
        return Task.CompletedTask;
    });

    // 2. Apply "Lock" Icon ONLY to protected endpoints
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

app.UseAuthentication();
app.UseAuthorization();

// --- DATA ---
var users = new List<User> 
{ 
    new(1, "admin", "password", "Admin"),
    new(2, "bob", "password", "User") 
};

var userRefreshTokenDict = new Dictionary<string, string>();

// --- ENDPOINTS ---

// 1. Login (Sets Cookies)
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

// 2. Refresh (Reads Cookies)
app.MapPost("/refresh", (HttpContext http) =>
{
    // CHANGED: Read from Cookies instead of Body DTO
    http.Request.Cookies.TryGetValue("X-Refresh-Token", out var cookieRefreshToken);
    http.Request.Cookies.TryGetValue("X-Username", out var cookieUsername);

    if (string.IsNullOrEmpty(cookieRefreshToken) || string.IsNullOrEmpty(cookieUsername))
    {
        return Results.Unauthorized();
    }

    // Validate logic (Same as before)
    if (!userRefreshTokenDict.TryGetValue(cookieUsername, out var storedRefreshToken) || storedRefreshToken != cookieRefreshToken)
    {
        return Results.Forbid();
    }

    var user = users.FirstOrDefault(u => u.Username == cookieUsername);
    if (user is null) return Results.Forbid();
        
    var newAccessToken = GenerateAccessToken(user, jwtSettings.Key, jwtSettings.Issuer, jwtSettings.Audience, jwtSettings.AccessTokenMinutes);
    var newRefreshToken = GenerateRefreshToken();

    userRefreshTokenDict[user.Username] = newRefreshToken;
    
    http.Response.Cookies.Append("X-Access-Token", newAccessToken, 
        new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Expires = DateTime.UtcNow.AddMinutes(jwtSettings.AccessTokenMinutes) });

    http.Response.Cookies.Append("X-Refresh-Token", newRefreshToken, 
        new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Expires = DateTime.UtcNow.AddDays(jwtSettings.RefreshTokenDays) });

    return Results.Ok(new { message = "Refreshed via Cookies" });
});

// 3. User Endpoint
app.MapGet("/dashboard", () => "Hello User!").RequireAuthorization();

// 4. Admin Endpoint
app.MapGet("/admin-only", () => "Hello Admin!").RequireAuthorization(new AuthorizeAttribute { Roles = "Admin" });

app.Run();
return;

// --- HELPERS ---
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