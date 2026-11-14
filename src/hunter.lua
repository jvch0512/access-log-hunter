-- access-log-hunter: web attack detection in combined-format access logs. Pure Lua 5.x, no dependencies.
local M = {}

local RULES = {
  { cat = "sqli", weight = 3, pats = { "union[%s%+]+all[%s%+]+select", "union[%s%+]+select", "or[%s%+]+1%s*=%s*1", "'[%s%+]*or[%s%+]+'", "information_schema", "sleep%s*%(%d+%)", "benchmark%s*%(", "waitfor[%s%+]+delay", "extractvalue%s*%(", "%-%-[%s%+]*$" } },
  { cat = "xss", weight = 2, pats = { "<script", "javascript:", "onerror%s*=", "onload%s*=", "<img[%s%+]", "<svg" } },
  { cat = "traversal", weight = 3, pats = { "%.%./%.%./", "%.%.\\", "/etc/passwd", "/etc/shadow", "boot%.ini", "win%.ini", "/proc/self/environ" } },
  { cat = "rce", weight = 5, pats = { "%${jndi:", "cmd=", "%?exec=", ";%s*wget[%s%+]", ";%s*curl[%s%+]", "|%s*sh", "`id`", "%$%(id%)", "/bin/sh", "powershell" } },
  { cat = "recon", weight = 1, pats = { "/%.env", "/%.git/config", "/wp%-admin/install%.php", "/phpmyadmin", "/server%-status", "/actuator/", "/%.aws/credentials", "/xmlrpc%.php" } },
}
local SCANNERS = { "sqlmap", "nikto", "nmap", "masscan", "nuclei", "gobuster", "dirbuster", "wfuzz", "acunetix", "nessus", "zgrab", "feroxbuster" }

function M.urldecode(s)
  s = s:gsub("%+", " ")
  s = s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
  return s
end

-- 203.0.113.9 - - [12/Mar/2026:10:00:01 +0000] "GET /a?b=c HTTP/1.1" 200 512 "-" "UA"
function M.parse_line(line)
  local ip, ts, method, path, status, ua = line:match('^(%S+) %S+ %S+ %[([^%]]+)%] "(%u+) (%S+)[^"]*" (%d%d%d) %S+ "[^"]*" "([^"]*)"')
  if not ip then return nil end
  return { ip = ip, ts = ts, method = method, path = path, status = tonumber(status), ua = ua }
end

function M.classify(req)
  local hits = {}
  local raw = M.urldecode(M.urldecode(req.path)):lower()   -- twice: catches double encoding
  for _, r in ipairs(RULES) do
    for _, p in ipairs(r.pats) do
      if raw:find(p) then hits[#hits + 1] = r.cat; break end
    end
  end
  local ua = req.ua:lower()
  for _, s in ipairs(SCANNERS) do
    if ua:find(s, 1, true) then hits[#hits + 1] = "scanner"; break end
  end
  return hits
end

local WEIGHT = { sqli = 3, xss = 2, traversal = 3, rce = 5, recon = 1, scanner = 2 }

function M.analyze(lines, opts)
  opts = opts or {}
  local min_score = opts.min_score or 4
  local by, order, total, bad = {}, {}, 0, 0
  for line in lines do
    local req = M.parse_line(line)
    if req then
      total = total + 1
      local e = by[req.ip]
      if not e then e = { ip = req.ip, reqs = 0, errors = 0, cats = {}, samples = {}, paths = {} }; by[req.ip] = e; order[#order + 1] = e end
      e.reqs = e.reqs + 1
      if req.status >= 400 then e.errors = e.errors + 1 end
      e.paths[req.path] = true
      local hits = M.classify(req)
      if #hits > 0 then
        bad = bad + 1
        for _, c in ipairs(hits) do e.cats[c] = (e.cats[c] or 0) + 1 end
        if #e.samples < 3 then e.samples[#e.samples + 1] = req.method .. " " .. req.path:sub(1, 90) end
      end
    end
  end
  local out = {}
  for _, e in ipairs(order) do
    local score, cats = 0, {}
    for c, n in pairs(e.cats) do score = score + WEIGHT[c] * math.min(n, 5); cats[#cats + 1] = c end
    table.sort(cats)
    if e.reqs >= 20 and e.errors / e.reqs > 0.8 then score = score + 5; cats[#cats + 1] = "error-storm" end
    if score >= min_score then
      local sev = (score >= 30 or (e.cats.rce and score >= 20)) and "critical" or score >= 15 and "high" or "medium"
      out[#out + 1] = { ip = e.ip, score = score, severity = sev, reqs = e.reqs, errors = e.errors, cats = cats, samples = e.samples }
    end
  end
  local RANK = { critical = 1, high = 2, medium = 3 }
  table.sort(out, function(a, b) if a.severity ~= b.severity then return RANK[a.severity] < RANK[b.severity] end if a.score ~= b.score then return a.score > b.score end return a.ip < b.ip end)
  return { total = total, flagged = bad, offenders = out }
end

function M.render_text(r)
  local o = { string.format("%d requests, %d suspicious, %d offending IPs\n", r.total, r.flagged, #r.offenders) }
  for _, e in ipairs(r.offenders) do
    o[#o + 1] = string.format("%-8s %-15s score %-3d %d requests, %d errors  [%s]\n", e.severity:upper(), e.ip, e.score, e.reqs, e.errors, table.concat(e.cats, ", "))
    for _, s in ipairs(e.samples) do o[#o + 1] = "         " .. s .. "\n" end
  end
  return table.concat(o)
end

local function esc(s) return (s:gsub("[&<>\"]", { ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;", ['"'] = "&quot;" })) end

function M.render_html(r)
  local rows = {}
  for _, e in ipairs(r.offenders) do
    local samples = {}
    for _, s in ipairs(e.samples) do samples[#samples + 1] = "<code>" .. esc(s) .. "</code>" end
    rows[#rows + 1] = string.format('<tr><td class="%s">%s</td><td>%s</td><td>%d</td><td>%d / %d</td><td>%s</td><td>%s</td></tr>', e.severity, e.severity, esc(e.ip), e.score, e.errors, e.reqs, esc(table.concat(e.cats, ", ")), table.concat(samples, "<br>"))
  end
  return [[<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>access-log-hunter</title><style>:root{color-scheme:dark}body{margin:0;padding:28px;background:#0e1319;color:#e8eef5;font:14px/1.5 system-ui,sans-serif}h1{margin:0 0 4px}.sub{color:#8b98a8}table{border-collapse:collapse;width:100%;margin-top:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a3441;vertical-align:top}th{color:#8b98a8}.critical{color:#f85149;font-weight:700}.high{color:#f0883e;font-weight:700}.medium{color:#e3b341;font-weight:700}code{color:#7ee787;word-break:break-all}</style></head><body><h1>access-log-hunter</h1><p class="sub">Web attack hunter for access logs. Lua, no dependencies. Synthetic log, ]] .. r.total .. " requests, " .. r.flagged .. " suspicious.</p><table><tr><th>Severity</th><th>IP</th><th>Score</th><th>Errors</th><th>Categories</th><th>Samples</th></tr>" .. table.concat(rows) .. [[</table><p class="sub">Pattern based: expect false positives on security scanners you run yourself and on unusual but legitimate query strings.</p></body></html>
]]
end

return M
