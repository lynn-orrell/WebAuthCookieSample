using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;

var builder = WebApplication.CreateBuilder(args);

var dpp = DataProtectionProvider.Create(new DirectoryInfo(@"c:\temp\keys"));

builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
       .AddMicrosoftIdentityWebApp(
            options =>
            {
                // Bind the AzureAd portion of app.settings
                builder.Configuration.GetSection("AzureAd").Bind(options);

                // Subscribe to OnTokenValidated events which will occur when we receive a validated response from the IdP (AzureAD in this case)
                options.Events.OnTokenValidated += OnTokenValidated;
            },
            options =>
            {
                // Specify the name of the cookie we want written with the cookie auth value
                options.Cookie.Name = "SharedAuthCookie";

                // Specify the DataProtectionProvider -- This has to point to the same set of keys used for decryption
                options.DataProtectionProvider = dpp;

                // Specify that the auth cookie can't be read from the client
                options.Cookie.HttpOnly = true;

                // Don't allow this cookie to be sent over unencrypted transports
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            },
            // Let's log the OpenIdConnect events as they happen
            subscribeToOpenIdConnectMiddlewareDiagnosticsEvents: true);

async Task OnTokenValidated(TokenValidatedContext arg)
{
    // Grab the raw JWT
    var jwt = arg.SecurityToken.RawData;

    // Write it to a cookie named "JWT" -- the value is unencrypted but cryptographically signed
    // Only transport this cookie over secure transports
    // We specifically didn't specify HttpOnly as a cookie option here (in case you want to read it and use it from the client)
    // But, if you are worried about attack vectors from the client, you could make it HttpOnly
    arg.Response.Cookies.Append("JWT", jwt, new CookieOptions { Secure = true });

    // Protect the JWT using the DataProtectionProvider with a single purpose named "jwt". This will need to match on the decryption side!
    string encryptedJwt = dpp.CreateProtector("jwt").Protect(jwt);

    // Write the protected JWT to a cookie named "EncryptedJWT"
    // We specify HttpOnly as a cookie option to ensure this cookie can't be read from the client
    // We specify Secure = true to ensure this cookie is only sent over secure transports
    arg.Response.Cookies.Append("EncryptedJWT", encryptedJwt, new CookieOptions { HttpOnly = true, Secure = true });

    // We are done!
    await Task.CompletedTask;
}

builder.Services.AddAuthorization(options =>
{
    // By default, all incoming requests will be authorized according to the default policy.
    options.FallbackPolicy = options.DefaultPolicy;
});

builder.Services.AddRazorPages().AddMicrosoftIdentityUI();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

app.Run();
