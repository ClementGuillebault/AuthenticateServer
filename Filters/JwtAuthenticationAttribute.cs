using System;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Filters;

namespace AuthenticateZeroServer.Filter {
    /// <summary>
    /// Attribute for jwt authentication.
    /// Using: you must add [jwtAuthenticate] attribute on method
    /// or class you want to protect.
    /// </summary>
    public class JwtAuthenticationAttribute: Attribute, IAuthenticationFilter {
        public bool AllowMultiple => false;
        public string Realm { get; set; }

        /// <summary>
        /// Third step of authenticate and jwt control.
        /// </summary>
        /// <param name="token">string</param>
        /// <param name="principal">ClaimsPrincipal</param>
        /// <returns></returns>
        private static bool ValidateToken(string token, out ClaimsPrincipal principal) {
            principal = JwtManager.GetPrincipal(token);

            if (!(principal?.Identity is ClaimsIdentity identity)) {
                return false;
            }

            if (!identity.IsAuthenticated) {
                return false;
            }

            /* naive check */
            var username = identity.FindFirst(ClaimTypes.Name)?.Value;

            if (string.IsNullOrEmpty(username)) {
                return false;
            }

            /* Add check if you want more control on user (bdd, etc.) */

            return true;
        }

        /// <summary>
        /// Challenge. Checked before authentication begin.
        /// Sync version.
        /// </summary>
        /// <param name="context">HttpAuthenticationChallengeContext</param>
        private void Challenge(HttpAuthenticationChallengeContext context) {
            string parameter = null;

            if (!string.IsNullOrEmpty(Realm))
                parameter = "realm=\"" + Realm + "\"";

            context.ChallengeWith("Bearer", parameter);
        }

        /// <summary>
        /// Second step of authenticate.
        /// </summary>
        /// <param name="token">string</param>
        /// <returns></returns>
        protected Task<IPrincipal> AuthenticateJwtToken(string token) {
            if (ValidateToken(token, out var principal)) {
                /* Build local identity here if you need it */

                IPrincipal user = principal;

                return Task.FromResult(user);
            }

            return Task.FromResult<IPrincipal>(null);
        }

        /// <summary>
        /// First step of jwt control.
        /// </summary>
        /// <param name="context">HttpAuthenticationContext</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns></returns>
        public async Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken) {
            var request = context.Request;
            var authorization = request.Headers.Authorization;

            if (authorization == null || authorization.Scheme != "Bearer")
                return;

            if (string.IsNullOrEmpty(authorization.Parameter)) {
                context.ErrorResult = new AuthenticationFailureResult("Missing Jwt Token", request);
                return;
            }

            var principal = await AuthenticateJwtToken(authorization.Parameter);

            if (principal is null) {
                context.ErrorResult = new AuthenticationFailureResult("Invalid token", request);
            }
            else {
                context.Principal = principal;
            }
        }

        /// <summary>
        /// Challenge. Checked before authentication begin.
        /// Async version
        /// </summary>
        /// <param name="context">HttpAuthenticationChallengeContext</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns></returns>
        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken) {
            Challenge(context);
            return Task.FromResult(0);
        }
    }
}
