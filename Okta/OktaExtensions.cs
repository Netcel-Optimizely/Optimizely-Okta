using EPiServer.Security;
using EPiServer.ServiceLocation;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Okta.AspNetCore;
using System.Security.Claims;
using System.Text;

namespace Optimizely_Okta.Okta
{
    public static class OktaExtensions
    {
        /// <summary>
        /// Okta Authentication
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        /// <param name="forceHttpsRedirect"></param>
        public static void ConfigureOkta(this IServiceCollection services, IConfiguration configuration, bool forceHttpsRedirect)
        {
            services
                    .AddAuthentication(options =>
                    {
                        options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                        options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                        options.DefaultSignOutScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                    })
                    .AddCookie()
            #region using Okta
            .AddOktaMvc(new OktaMvcOptions
            {
                OktaDomain = configuration["Okta:OktaDomain"],
                ClientId = configuration["Okta:ClientId"],
                ClientSecret = configuration["Okta:ClientSecret"],
                Scope = new List<string> { "openid", "profile", "email" },
                CallbackPath = "/authorization-code/callback",
                GetClaimsFromUserInfoEndpoint = true,
                PostLogoutRedirectUri = "https://localhost:5000/",
                OpenIdConnectEvents = new OpenIdConnectEvents
                {
                    OnAuthenticationFailed = async (context) =>
                    {
                        context.HandleResponse();
                        await context.Response.BodyWriter.WriteAsync(Encoding.ASCII.GetBytes(context.Exception.Message));
                        await Task.FromResult(0);
                    },
                    OnTokenValidated = async (ctx) =>
                    {
                        TokenValidationParameters validationParameters = 
                            new TokenValidationParameters(
                            
                            );

                        if (ctx?.Principal == null)
                        {
                            await Task.FromResult(0);
                            return;
                        }

                        if (!string.IsNullOrEmpty(ctx.Properties.RedirectUri))
                        {
                            var redirectUri = new Uri(ctx.Properties.RedirectUri, UriKind.RelativeOrAbsolute);
                            if (redirectUri.IsAbsoluteUri)
                            {
                                ctx.Properties.RedirectUri = redirectUri.PathAndQuery;
                            }
                        }

                        // adding in manually for now should ideally read from Okta than Map 
                        var claims = new List<Claim> { new Claim(ClaimTypes.Role, "WebAdmins", ClaimValueTypes.String) };
                        ctx?.Principal.AddIdentity(new ClaimsIdentity(claims));


                        // this needs changing to Okta based claims 
                        await ServiceLocator.Current.GetInstance<ISynchronizingUserService>().SynchronizeAsync(ctx.Principal?.Identity as ClaimsIdentity);
                    },
                    OnRedirectToIdentityProvider = async (context) =>
                    {
                        if (forceHttpsRedirect)
                        {
                            context.ProtocolMessage.RedirectUri =
                                context.ProtocolMessage.RedirectUri.Replace("http:", "https:");
                        }

                        // To avoid a redirect loop to the federation server send 403
                        // when user is authenticated but does not have access
                        if (context.Response.StatusCode == 401 &&
                        context.HttpContext.User.Identity.IsAuthenticated)
                        {
                            context.Response.StatusCode = 403;
                            context.HandleResponse();
                        }


                        await Task.FromResult(0);
                    }
                }
            });

            //AddOktaMvc() does not allow to set the TokenValidationParameters in its parameters, so we need to do it afterwards
            services.PostConfigureAll<OpenIdConnectOptions>(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    RoleClaimType = ClaimTypes.Role,
                    NameClaimType = "name",
                    ValidateIssuer = false,
                    ValidateAudience = false,
                };
            });
            #endregion
        }


    }


}


