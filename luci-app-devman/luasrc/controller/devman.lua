module("luci.controller.devman", package.seeall)

function index()
	page = entry({"admin", "network", "devman"}, template("devman/overview"), _("设备管理"), 5)
	page.i18n = "devman"
	entry({"admin", "network", "devman", "api_devices"}, call("api_devices")).sysauth = false
	entry({"admin", "network", "devman", "api_block"}, call("api_block")).sysauth = false
	entry({"admin", "network", "devman", "api_limit"}, call("api_limit")).sysauth = false
end

function api_devices()
	local http = require "luci.http"
	local f = io.popen("curl -s http://127.0.0.1:9999/api/devices")
	local data = f:read("*a") or "[]"
	f:close()
	http.prepare_content("application/json")
	http.write(data)
end

function api_block()
	local http = require "luci.http"
	local dev = http.formvalue("device_id")
	local block = http.formvalue("block")
	if dev then
		os.execute('curl -s -X POST http://127.0.0.1:9999/api/block -d \'{"device_id":'..dev..',"block":'..(block=="1" and "true" or "false")..'}\' &')
	end
	http.prepare_content("application/json")
	http.write('{"ok":true}')
end

function api_limit()
	local http = require "luci.http"
	local dev = http.formvalue("device_id")
	local limit = http.formvalue("rate_limit") or "0"
	local limit_dn = http.formvalue("rate_limit_down") or "-1"
	local alias = http.formvalue("alias")
	if dev then
		local body = '{"device_id":'..dev..',"rate_limit":'..limit..',"rate_limit_down":'..limit_dn
		if alias then body = body..',"alias":"'..alias..'"' end
		body = body..'}'
		os.execute("curl -s -X POST http://127.0.0.1:9999/api/limit -d '"..body.."'")
	end
	http.prepare_content("application/json")
	http.write('{"ok":true}')
end
