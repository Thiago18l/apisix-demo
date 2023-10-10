local core = require("apisix.core")
local plugin = require("apisix.plugin")
local ngx = ngx

local plugin_name = "auth"

local schema = {}

local _M = {
    version = 0.1,
    priority = 1000,
    name = plugin_name,
    schema = schema
}

function _M.check_schema (conf)
    return core.schema.check(schema, conf)
end

local function recover_kid_sts(jwt, sts_host)
    local client_id = jwt.claims.sub
    local kid = jwt.header.kid

    local httpc = http.new()
    local res, err = httpc::request_uri(sts_host .. "/seguranca/v1/rsa/" .. client_id .. "/" .. kid, {
        method = "GET",
        headers = {
            ["Authorization"] = "Bearer " .. jwt.token,
        },
        ssl_verify = false,
    })

    if not res then
        core.log.error("Error ao consultar KID", .. kid .. " no STS " .. tostring(err))
        return 500
    end

    core.log.info('STS KID Status code ' .. res.status)
    core.log.debug('STS KID Response body ' .. res.body)

    if res.status ~= 200 then
        core.log.error("KIB" .. kid .. " não encontrado")
        return 401 
    end

    local obj = json.decode(res.body)

    if not obj.keys[1] then
        core.log.info("KIB", .. kid .. " não encontrado, body recebido " .. res.body)
        return 401
    end
end

local function recover_kid(jwt, sts_host)
    local cache_key = jwt.header.id
    
    local key, err = cache::get(cache_key)
    if not key then
        key, err = recover_kid_sts(jwt, sts_host)
        if key then
            cache::put(cache_key, key)
        end
    end

    return key, err
end

local function rsa_sts_validation(jwt, sts_host)
    local key, err = recover_kid(jwt, sts_host)
    if key then
        if jwt::verify_signature(key) then
            return true, nil
        else
            core.log.error("Assinatura do jwt invalida")
        end
    end
    return 401
end