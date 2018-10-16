var jwk2pem = require('jwk-to-pem');
var fs = require('fs');

// mmIseI/cJsv5WPy7gGyLZKpbxUu/blaUbxlle9XRvg0=
const firstKey = {
    "alg": "RS256",
    "e": "AQAB",
    "kid": "mmIseI/cJsv5WPy7gGyLZKpbxUu/blaUbxlle9XRvg0=",
    "kty": "RSA",
    "n": "hqeT_KVBtrNg88SQ8F2YEvoIVWBJ0IUe9B19TNZHjZHO5xBO-a8XLvakmvaaxW93nK8ADjoO9UgNytw_gb-oZvbpF0jUEq-PoFBClgB0TMkaocxleDPm2rBT22C0VeZKC6DITndjIkUrDxLkeVX5i05kWnZ1DzE3-Ci9IDfzxNixyJ1U4fnisY2cfz4oc07ktwfHDmpaKKA3eUKvGsiB75Sxm6tfNbt6siwxPDrJGWJQvmsa_kcsMksR3uk2qpHU-sEThHPL7WHrR7rI7MwkGDLMRiAqC3BqCyCrAnZk-6LQ-G84N-REbkkgTkRA3UIbVxrzKGiTcF-scAYGBavTMQ",
    "use": "sig"
}
let pem = jwk2pem(firstKey);
fs.writeFileSync("./first.pem", pem);
console.log(pem);

// MfJpVn++oYNDNB+4ybhYPq+/mbI6/zGfAfWi3RV6LZo=
const secondKey = {
    "alg": "RS256",
    "e": "AQAB",
    "kid": "MfJpVn++oYNDNB+4ybhYPq+/mbI6/zGfAfWi3RV6LZo=",
    "kty": "RSA",
    "n": "xGc4IptmK7_7iV0BTVfPk9tFili6B6serFtoRZq4aa0ImO-D7efG8z-wPHiy4Bcfnpbr0umFzVkgubJH7CV4TM2hIGjbV9wIociQNooMziRhcOxbdrPpCQ4MR1IFGmG_hu6kO_DIx9lgl7SvikK9O66vhWtB5KUSdhyBhZc51OeminlwDV5dg8XmFTpYeDu8GJnW5mxGCWqYKbLiIyBZXRDwn33KUJCaM8cV5WrztRe2o1vLPr0TloKsw_X-loHiFZRPfakAEW7htfj6g1aM_EckV5eGlUn2cdBwKW-gOhilsEetdV-9kvHG0mdX3PpFpbQXMTX5G9B9tDGT-o4RmQ",
    "use": "sig"
}
pem = jwk2pem(secondKey);
fs.writeFileSync("./second.pem", pem);
console.log(pem)