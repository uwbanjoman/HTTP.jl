module DigestAuthenticationRequest

using .. Base64

import ..Layer, ..request
using URIs
using ..Pairs: getkv, setkv
import ..@debug, ..DEBUG_LEVEL

"""
    request(DigestAuthLayer, method, ::URI, headers, body) -> HTTP.Response
Add `Authorization: Digest` header using credentials from url userinfo.
"""
abstract type DigestAuthLayer{Next <: Layer} <: Layer{Next} end
export DigestAuthLayer

abstract type DigestAuthLayer{Next <: Layer} <: Layer{Next} end
export DigestAuthLayer

function request(::Type{DigestAuthLayer{Next}},
                 method::String, url::URI, headers, body; kw...) where Next

    userinfo = unescapeuri(url.userinfo)

    if !isempty(userinfo) && getkv(headers, "Authorization", "") == ""
        @debug 1 "Adding Authorization: Digest header."
        setkv(headers, "Authorization", "Digest $(base64encode(userinfo))")
    end

    return request(Next, method, url, headers, body; kw...)
end

function sign_digest!(algorithm::Any,
                    method::String,
                    url::URI,
                    headers::Headers,
                    body::Vector{UInt8};
    )
end

end # module DigestAuthenticationRequest
