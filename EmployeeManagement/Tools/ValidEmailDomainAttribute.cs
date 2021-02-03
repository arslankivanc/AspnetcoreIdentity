using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace EmployeeManagement.Tools
{
    public class ValidEmailDomainAttribute:ValidationAttribute
    {
        public override bool IsValid(object value)
        {
            var deger = value.ToString();
            bool sonuc= deger.Contains("@");
            return sonuc;
        }
    }
}
