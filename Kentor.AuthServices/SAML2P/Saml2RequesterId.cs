using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Kentor.AuthServices.Saml2P
{
    public class Saml2RequesterId
    {
        public string Id { get; set; }

        public Saml2RequesterId(string id)
        {
            this.Id = id;
        }

    }
}
