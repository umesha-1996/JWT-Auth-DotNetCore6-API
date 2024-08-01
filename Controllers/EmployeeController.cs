using JwtAuthentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthentication.Controllers
{

    [Route("api/employee")]
    [ApiController]
    public class EmployeeController : Controller
    {
        [Authorize]
        [HttpGet("GetDate")]
        public string GetData()
        {
            return "Authenticated with JWT";
        }

        [HttpGet("GetDetails")]
        public string GetDetails()
        {
            return "Not Authenticated";
        }

        [Authorize]
        [HttpPost("AddUser")]
        public string AddUser(User user)
        {
            return "User Added with username " + user.UserName;
        }
    }
}
