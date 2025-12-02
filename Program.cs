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
    });
builder.Services.AddAuthorization();

// --- OPENAPI (Bearer Definition) ---
builder.Services.AddOpenApi("v1", options =>
{
    // 1. Define "Bearer" Scheme
    options.AddDocumentTransformer((document, _, _) =>
    {
        document.Info = new OpenApiInfo { Title = "Bearer API", Version = "v1" };
        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes.Add("Bearer", new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            Description = "Enter access token here"
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
                new() { { new OpenApiSecurityScheme { Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" } }, Array.Empty<string>() } }
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
});

app.UseAuthentication();
app.UseAuthorization();

// --- DATA ---
var users = new List<User> 
{ 
    new("admin", "password", "Admin"),
    new("bob", "password", "User") 
};

var userRefreshTokenDict = new Dictionary<string, string>();

// --- ENDPOINTS ---

// 1. Login (Returns Token in Body)
app.MapPost("/login", (LoginDto loginData) =>
{
    var user = users.FirstOrDefault(u => u.Username == loginData.Username && u.Password == loginData.Password);
    if (user is null) return Results.Unauthorized();

    var accessToken = GenerateAccessToken(user, jwtSettings.Key, jwtSettings.Issuer, jwtSettings.Audience, jwtSettings.AccessTokenMinutes);
    var refreshToken = GenerateRefreshToken();
    
    userRefreshTokenDict[user.Username] = refreshToken;
    
    // In Bearer flow, we return tokens in the body. Client must save them.
    return Results.Ok(new { accessToken, refreshToken });
});

// 2. Refresh (Requires Refresh Token in Body)
app.MapPost("/refresh", (RefreshTokenDto refreshData) =>
{
    // Validate refresh logic here (simplified)
    if (!userRefreshTokenDict.TryGetValue(refreshData.Username, out var refreshToken) || refreshToken != refreshData.RefreshToken)
    {
        return Results.Forbid();
    }

    var user = users.FirstOrDefault(u => u.Username == refreshData.Username);
    if (user is null) return Results.Forbid();
        
    var newAccessToken = GenerateAccessToken(user, jwtSettings.Key, jwtSettings.Issuer, jwtSettings.Audience, jwtSettings.AccessTokenMinutes);
    var newRefreshToken = GenerateRefreshToken();

    userRefreshTokenDict[user.Username] = newRefreshToken;

    return Results.Ok(new { accessToken = newAccessToken, refreshToken = newRefreshToken });

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

internal record User(string Username, string Password, string Role);

internal record LoginDto(string Username, string Password);

internal record RefreshTokenDto(string Username, string RefreshToken);