package.path = "src/?.lua;" .. package.path
local H = require("hunter")
local n, failed = 0, 0
local function check(name, cond) n = n + 1; if not cond then failed = failed + 1; print("FAIL: " .. name) end end
local BR = "Mozilla/5.0 Chrome"
local function req(path, ua, status) return H.parse_line(string.format('1.2.3.4 - - [14/Mar/2026:10:00:00 +0000] "GET %s HTTP/1.1" %d 10 "-" "%s"', path, status or 200, ua or BR)) end
local function cats(path, ua) local c = H.classify(req(path, ua)); table.sort(c); return table.concat(c, ",") end

check("parses a combined log line", req("/a?b=c").ip == "1.2.3.4" and req("/a?b=c").status == 200 and req("/a").method == "GET")
check("rejects garbage", H.parse_line("not a log line") == nil)
check("urldecode", H.urldecode("a%20b+c%2F") == "a b c/")
check("clean request has no hits", cats("/products/42") == "")
check("apostrophe in a search is not sqli", cats("/search?q=it's+a+test") == "")
check("union select", cats("/p?id=1%20UNION%20SELECT%20a") == "sqli")
check("or 1=1", cats("/p?id=1%20or%201=1") == "sqli")
check("time based sqli", cats("/p?id=1;select%20sleep(5)") == "sqli")
check("script tag xss", cats("/s?q=%3Cscript%3E") == "xss")
check("traversal", cats("/d?f=../../../../etc/passwd") == "traversal")
check("double encoded traversal", cats("/d?f=%252e%252e%252f%252e%252e%252fetc%252fpasswd") == "traversal")
check("log4shell", cats("/?x=${jndi:ldap://x/a}") == "rce")
check("recon of dotfiles", cats("/.env") == "recon")
check("scanner user agent", cats("/", "sqlmap/1.7") == "scanner")
check("uppercase payload still matches", cats("/p?id=1%20UnIoN%20SeLeCt%20a") == "sqli")

local function lines(t) local i = 0; return function() i = i + 1; return t[i] end end
local f = io.open("examples/access.log")
if f then
  local all = {}; for l in f:lines() do all[#all + 1] = l end; f:close()
  local r = H.analyze(lines(all))
  check("sample: 172 requests", r.total == 172)
  check("sample: five offenders", #r.offenders == 5)
  check("sample: log4shell IP is critical and first", r.offenders[1].ip == "192.0.2.77" and r.offenders[1].severity == "critical")
  local seen = {}; for _, e in ipairs(r.offenders) do seen[e.ip] = true end
  check("sample: legitimate user never flagged", not seen["198.51.100.55"])
  check("sample: ordinary visitors never flagged", not seen["198.51.100.10"] and not seen["198.51.100.11"])
  check("sample: scanner gets error-storm", (function() for _, e in ipairs(r.offenders) do if e.ip == "198.51.100.99" then for _, c in ipairs(e.cats) do if c == "error-storm" then return true end end end end end)())
  check("min-score filters", #H.analyze(lines(all), { min_score = 30 }).offenders < #r.offenders)
  local evil = { total = 1, flagged = 1, offenders = { { ip = "<b>", score = 9, severity = "high", reqs = 1, errors = 0, cats = { "<i>" }, samples = { "<script>alert(1)</script>" } } } }
  local html = H.render_html(evil)
  check("html escapes everything from the log", not html:find("<script>alert", 1, true) and html:find("&lt;script&gt;", 1, true) ~= nil)
  check("html has strict CSP", html:find("default-src 'none'", 1, true) ~= nil)
  -- robustness: random garbage never crashes
  math.randomseed(7)
  local junk = {}
  for i = 1, 2000 do local t = {}; for j = 1, math.random(1, 120) do t[j] = string.char(math.random(1, 255)) end; junk[i] = table.concat(t) end
  check("fuzz: 2000 random lines, no crash", pcall(H.analyze, lines(junk)))
else print("skipped sample tests (run from repo root)") end
print(failed == 0 and ("all " .. n .. " passed") or (failed .. " of " .. n .. " failed"))
os.exit(failed == 0 and 0 or 1)
