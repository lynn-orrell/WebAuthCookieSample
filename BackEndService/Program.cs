using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapGet("/crackCookie", async (HttpContext context, HttpRequest request, HttpResponse response) =>
{
    // Snag the auth cookie
    string sharedAuthCookie = request.Cookies["SharedAuthCookie"];

    // Snag the encrypted JWT
    string encryptedJwt = request.Cookies["EncryptedJWT"];

    // Snag the plain JWT -- nothing left to do with this as it's already unencrypted
    string jwt = request.Cookies["JWT"]; 

    // Create the DataProtectionProvider pointing the the same keys that were used to encrypt
    var provider = DataProtectionProvider.Create(new DirectoryInfo(@"c:\temp\keys"));

    // Create an IDataProtector using the known purposes for cookie auth
    var cookieDataProtector = provider.CreateProtector("Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", "Cookies", "v2");

    // Create an IDataProtector using the purpose for which we encrypted the JWT. In this case we just used a single purpose named "jwt"
    var jwtDataProtector = provider.CreateProtector("jwt");

    // Use the TicketDataFormat (instantiated with the cookieDataProtector) to unprotect the auth cookie and populate an AuthenticationTicket
    var authenticationTicket = new TicketDataFormat(cookieDataProtector).Unprotect(sharedAuthCookie);

    // Use the jwtDataProtector to unprotect the encrypted JWT
    var unprotectedJwt = jwtDataProtector.Unprotect(encryptedJwt);

    response.ContentType = "text/plain";
    await response.WriteAsync($"--Authentication Ticket (Principal.Identity.Name)--\n{authenticationTicket.Principal.Identity.Name}\n\n");
    await response.WriteAsync($"--Raw JWT--\n{jwt}\n\n");
    await response.WriteAsync($"--Protected JWT--\n{encryptedJwt}\n\n");
    await response.WriteAsync($"--Protected (unprotected) JWT--\n{unprotectedJwt}\n\n");
    await response.WriteAsync($"--JWTs are equal?--\n{jwt.Equals(unprotectedJwt)}\n\n");
})
.WithName("CrackCookie");

app.Run();
