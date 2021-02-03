using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EmployeeManagement.Controllers
{
    public class ErrorController : Controller
    {
        [Route("Error/{statusCode}")]
        public IActionResult HttpStatusCodeHandler(int statusCode)
        {
            var code = HttpContext.Features.Get<IStatusCodeReExecuteFeature>();
            return View();
        }
        [Route("error")]
        [AllowAnonymous]
        public IActionResult Error()
        {
            var expDetails = HttpContext.Features.Get<IExceptionHandlerPathFeature>();
            ViewBag.ExpPath = expDetails.Path;
            ViewBag.ExpMessaje = expDetails.Error.Message;
            ViewBag.StackTrace = expDetails.Error.StackTrace;
            return View("_Error");
        }
    }
}
