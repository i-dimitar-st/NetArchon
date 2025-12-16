function extract_hostname(host)
    return host and string.lower(tostring(host)) or ""
end

-- utils.lua
function generate_pac_content(proxy_host, proxy_port)
    local content = string.format([[
function FindProxyForURL(url, host)
    if isPlainHostName(host) or
       shExpMatch(host, "localhost") or
       shExpMatch(host, "127.*") or
       shExpMatch(host, "192.168.20.*") then
        return "DIRECT"
    end
    return "PROXY %s:%d";
end
]], proxy_host, proxy_port)
    return content
end
