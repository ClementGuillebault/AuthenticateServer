using System;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Web.Http.Cors;

using AuthenticateZeroServer.Models;
using AuthenticateZeroServer.Repository;

namespace AuthenticateZeroServer.Controllers {
    [EnableCors(origins: "*", headers: "*", methods: "*")]
    public class TokenController: ApiController {
        private AuthRepository authRepository { get; set; }

        private bool CheckUser(Authentication authenticationModel) {
            authRepository = new AuthRepository {
                AuthenticationModel = authenticationModel
            };
            return authRepository.Authenticate();
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("api/v1/GetToken")]
        [EnableCors(origins: "*", headers: "*", methods: "*")]
        public HttpResponseMessage Post([FromBody] Authentication authenticationModel) {
            try {
                if (authenticationModel is null || authenticationModel.HasError) {
                    throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.Unauthorized) {
                        ReasonPhrase = "Access is denied due to invalid credentials."
                    });
                }

                if (CheckUser(authenticationModel)) {
                    IUser user;
                    if (authenticationModel.IsStaff) {
                        user = authRepository.GetStaff();
                    }
                    else {
                        user = authRepository.GetCustomer();
                    }

                    return new HttpResponseMessage(HttpStatusCode.OK) {
                        Content = new StringContent(JwtManager.GenerateToken(user))
                    };
                }
            }
            catch (Exception ex) {
                throw ex;
            }

            throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.Unauthorized) {
                ReasonPhrase = "Access is denied due to invalid credentials."
            });
        }
    }
}
