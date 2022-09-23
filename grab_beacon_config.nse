-- Head
local shortport = require "shortport"
local http = require "http"
local string = require "string"
local rand = require "rand"
local openssl = require "openssl"
local stdnse = require "stdnse"
local json = require "json"

description = [[ 
	Simple PoC script to scan and acquire CobaltStrike Beacon configurations.
	Based on :
		JPCERT :: cobaltstrikescan.py
		Sentinel-One :: parse_beacon_config.py
		Didier Stevens :: 1768.py
		Roman Emelynaov :: L8_get_beacon.py
]] 

categories = {"safe"}
author = "Wade Hickey, Zach Stanford"

-- Rule
portrule = function(host, port)
	return port.protocol == "tcp"
		and port.state == "open"
end

-- Action
local function generate_checksum(input)
--	92 and 93 are options
	local trial = ""
	local total = 0
	local i = 1
	while (total ~= input) do
		total = 0
		trial = rand.random_string(4,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
		for i = 1, 4 do
			total = (total + string.byte(string.sub(trial,i,i))) % 256
			i = i + 1
		end
	end
	return "/" .. trial

end

local function xor_finder()

end

local function extract_value(key_name, format, hex_identifier, content)
	local port_index = string.find(content,"\x00\x02\x00\x01\x00\x02",1,true)
	if (port_index) then
		local port = string.unpack(">H",content,port_index + 6)
		return port
	end


end

local function parse_field(key_name,contents,hex_flag,format)
	local index = ""

	local beacon_types = {}
	beacon_types[0] = "0 (HTTP)"
	beacon_types[1] = "1 (Hybrid HTTP DNS)"
	beacon_types[2] = "2 (SMB)"
	beacon_types[3] = "3 (Unknown)"
	beacon_types[4] = "4 (TCP)"
	beacon_types[5] = "5 (Unknown)"
	beacon_types[6] = "6 (Unknown)"
	beacon_types[7] = "7 (Unknown)"
	beacon_types[8] = "8 (HTTPS)"
	beacon_types[9] = "9 (Unkown)"
	beacon_types[10] = "10 (Bind TCP)"

	local access_types = {}
	access_types[0] = "0 (Unknown)"
	access_types[1] = "1 (Use direct connection)"
	access_types[2] = "2 (Use IE settings)"
	access_types[3] = "3 (Unknown)"
	access_types[4] = "4 (Use proxy server)"

	if key_name == "Beacon Type" then
		index = string.find(contents,hex_flag,1,true)
		if index == nil then
			return nil
		end
		return beacon_types[string.unpack(format,contents,index + string.len(hex_flag))]

	elseif key_name == "Proxy Access Type" then
		index = string.find(contents,hex_flag,1,true)

		if index == nil then
			return nil
		end
		return access_types[string.unpack(format,contents,index + string.len(hex_flag))]
	
	elseif key_name == "DNS Idle" then
		index = string.find(contents,hex_flag,1,true)
		
		if index == nil then
			return nil
		end

		local address = ""
		address = address .. string.unpack(format,contents,index + string.len(hex_flag) + 0) .. "."
		address = address .. string.unpack(format,contents,index + string.len(hex_flag) + 1) .. "."
		address = address .. string.unpack(format,contents,index + string.len(hex_flag) + 2) .. "."
		address = address .. string.unpack(format,contents,index + string.len(hex_flag) + 3)
		return address
	
	else
		index = string.find(contents,hex_flag,1,true)

		if index == nil then
			return nil
		end
		return string.unpack(format,contents,index + string.len(hex_flag))
	end
end


local function grab_beacon(response)

	local output = {}

	local test_string = string.char(0xFF) .. string.char(0xFF) .. string.char(0xFF)
	local return_string = ""
	if (response.status == 200) then
		if (http.response_contains(response, test_string, true)) then
			local offset = string.find(response.rawbody, test_string) + 3
			local endian = "<I"
			local key = string.unpack(endian,response.rawbody,offset)
			local size = string.unpack(endian,response.rawbody,offset+4) ~ key
			local c = string.unpack(endian,response.rawbody,offset+8) ~ key
			local mz = c & 0xffff
			local x = math.floor(2 + (offset / 4))
			local y = math.floor((string.len(response.rawbody)/4)-4)
			local repacked  = ""
            		xorkey_array = {0, 46, 105, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255}
            		for xorkey_index=1, #xorkey_array do
				xorkey = xorkey_array[xorkey_index]
				hexxorkey = string.format("0x%.2x%.2x%.2x%.2x", xorkey, xorkey, xorkey, xorkey)
				repacked = ""

				for var=x,y do
					a = string.unpack(endian,response.rawbody,var*4)
					b = string.unpack(endian,response.rawbody,var*4+4)
					z = tonumber(a) ~ tonumber(b)
					repacked = repacked .. string.pack(endian,z ~ tonumber(hexxorkey)) 

				end 
				output["Beacon Type"] = parse_field("Beacon Type",repacked,"\x00\x01\x00\x01\x00\x02",">H")
				if output["Beacon Type"] then
					output["Used Xor Key"] = string.format("0x%.2x", xorkey)
					break
				end
			end

			output["Port"] = parse_field("Port",repacked,"\x00\x02\x00\x01\x00\x02",">H")
			output["Polling"] = parse_field("Polling",repacked,"\x00\x03\x00\x02\x00\x04",">I")
			output["Jitter"] = parse_field("Jitter",repacked,"\x00\x05\x00\x01\x00\x02",">H")
			output["Max DNS"] = parse_field("Max DNS",repacked,"\x00\x06\x00\x01\x00\x02",">H")
			output["C2 Server"] = parse_field("C2 Server",repacked,"\x00\x08\x00\x03\x01\x00","z")
			output["User Agent"] = parse_field("User Agent",repacked,"\x00\x09\x00\x03\x00\x80","z")
			output["HTTP Method Path 2"] = parse_field("HTTP Method Path 2",repacked,"\x00\x0a\x00\x03\x00\x40","z")
			output["Header 1"] = parse_field("Header 1",repacked,"\x00\x0c\x00\x03\x01\x00","z")
			output["Header 2"] = parse_field("Header 2",repacked,"\x00\x0d\x00\x03\x01\x00","z")
			output["Injection Process"] = parse_field("Injection Process",repacked,"\x00\x0e\x00\x03\x00\x40","z")
			output["Pipe Name"] = parse_field("Pipe Name",repacked,"\x00\x0f\x00\x03\x00\x80","z")
			output["Year"] = parse_field("Year",repacked,"\x00\x10\x00\x01\x00\x02",">H")
			output["Month"] = parse_field("Month",repacked,"\x00\x11\x00\x01\x00\x02",">H")
			output["Day"] = parse_field("Day",repacked,"\x00\x12\x00\x01\x00\x02",">H")
			output["DNS Idle"] = parse_field("DNS Idle",repacked,"\x00\x13\x00\x02\x00\x04","B")
			output["DNS Sleep"] = parse_field("DNS Sleep",repacked,"\x00\x14\x00\x02\x00\x04",">H")
			output["Method 1"] = parse_field("Method 1",repacked,"\x00\x1a\x00\x03\x00\x10","z")
			output["Method 2"] = parse_field("Method 2",repacked,"\x00\x1b\x00\x03\x00\x10","z")
			output["Spawn To x86"] = parse_field("Spawn To x86",repacked,"\x00\x1d\x00\x03\x00\x40","z")
			output["Spawn To x64"] = parse_field("Spawn To x64",repacked,"\x00\x1e\x00\x03\x00\x40","z")
			output["Proxy Hostname"] = parse_field("Proxy Hostname",repacked,"\x00\x20\x00\x03\x00\x80","z")
			output["Proxy Username"] = parse_field("Proxy Username",repacked,"\x00\x21\x00\x03\x00\x40","z")
			output["Proxy Password"] = parse_field("Proxy Password",repacked,"\x00\x22\x00\x03\x00\x40","z")
			output["Proxy Access Type"] = parse_field("Proxy Access Type",repacked,"\x00\x23\x00\x01\x00\x02","z")
			output["CreateRemoteThread"] = parse_field("CreateRemoteThread",repacked,"\x00\x24\x00\x01\x00\x02","z")

			
			output["Watermark"] = parse_field("Watermark",repacked,"\x00\x25\x00\x02\x00\x04",">I")
			output["C2 Host Header"] = parse_field("C2 Host Header",repacked,"\x00\x36\x00\x03\x00\x80","z")



			if (stdnse.get_script_args("save")) == "true" then
				local write_out = io.open(stdnse.tohex(openssl.digest("sha256",response.body)) .. ".bin","w")
				io.output(write_out)
				io.write(response.body)
			end
		end	
	end
	return output
end


action = function(host,port)
	local json_output = {}

	local uri_x86 = generate_checksum(92)
	local uri_x64 = generate_checksum(93)

	local response_x86 = http.get(host,port,uri_x86)
	if response_x86.body == nil then
		return "No Valid Response"
	end

	json_output['x86'] = {}
	json_output['x86']['uri_queried'] = uri_x86
	json_output['x86']['sha256'] = stdnse.tohex(openssl.digest("sha256",response_x86.body))
	json_output['x86']['sha1'] = stdnse.tohex(openssl.digest("sha1",response_x86.body))
	json_output['x86']['md5'] = stdnse.tohex(openssl.digest("md5",response_x86.body))
	json_output['x86']['time'] = stdnse.clock_ms()
	json_output['x86']['config'] = grab_beacon(response_x86)

	local response_x64 = http.get(host,port,uri_x64)

	if response_x64.body == nil then
		return "No Valid Response"
	end

	json_output['x64'] = {}
	json_output['x64']['uri_queried'] = uri_x64
	json_output['x64']['sha256'] = stdnse.tohex(openssl.digest("sha256",response_x64.body))
	json_output['x64']['sha1'] = stdnse.tohex(openssl.digest("sha1",response_x64.body))
	json_output['x64']['md5'] = stdnse.tohex(openssl.digest("md5",response_x64.body))
	json_output['x64']['time'] = stdnse.clock_ms()
	json_output['x64']['config'] = grab_beacon(response_x64)



	json_output = json.generate(json_output)
	return json_output
end
