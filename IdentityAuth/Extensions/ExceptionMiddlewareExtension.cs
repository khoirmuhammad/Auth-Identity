using Microsoft.AspNetCore.Diagnostics;
using System.Net;

namespace IdentityAuth.Extensions
{
    public static class ExceptionMiddlewareExtension
    {
        public static void ConfigureExceptionHandler(this IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler(
                    options => {
                        options.Run(
                            async contex => {
                                contex.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                                var ex = contex.Features.Get<IExceptionHandlerFeature>();

                                if (ex != null)
                                {
                                    await contex.Response.WriteAsync(ex.Error.Message);
                                }
                            }
                        );
                    }
                );
            }
        }
    }
}
