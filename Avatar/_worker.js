const Version = '2026-09-22 20:01:17';
let config_JSON, 缓存SOCKS5白名单 = null, 调试日志打印 = false;
let SOCKS5白名单 = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];
///////////////////////////////////////////////////////全局常量和工具函数///////////////////////////////////////////////
const WS早期数据最大字节 = 8 * 1024, WS早期数据最大头长度 = Math.ceil(WS早期数据最大字节 * 4 / 3) + 4;
const 上行合包目标字节 = 20 * 1024, 上行队列最大字节 = 16 * 1024 * 1024, 上行队列最大条目 = 4096;
const 下行Grain包字节 = 32 * 1024, 下行Grain尾部阈值 = 512, 下行Grain低水位字节 = Math.max(4096, 下行Grain尾部阈值 * 12), 下行Grain最大等待轮次 = 4;
let TCP并发拨号数 = 2, 反代并发拨号数 = 1, 预加载竞速拨号 = false;
///////////////////////////////////////////////////////查杀特征码///////////////////////////////////////////////
const 特征码字典 = [
	(Proxy.name + "IP").toUpperCase(),
	(String.fromCharCode(67, 109) + URL.name[2] + 'i' + URL.name[0]).toLowerCase(),
	String(2407 * 300 - 10).split('').reverse().join('')
];
const 默认订阅转换后端 = `https://SUBAPI.${特征码字典[1]}ssss.net`;
const 默认订阅转换规则 = `https://raw.githubusercontent.com/${特征码字典[1]}/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini`;
const 汇聚订阅_UA = 'v2rayN/edge' + 'tunnel (https://github.com/' + 特征码字典[1] + '/edge' + 'tunnel)';// شناسهٔ سازگاری با تولیدکننده‌های اشتراک بیرونی؛ تغییر ندهید
///////////////////////////////////////////////////////امنیت ورود · Avatar///////////////////////////////////////////////
const 登录失败记录 = new Map(), 登录失败上限 = 5, 登录锁定毫秒 = 15 * 60 * 1000;
function 登录锁定剩余秒(IP) {
	const 记录 = 登录失败记录.get(IP);
	if (!记录) return 0;
	if (Date.now() - 记录.首次 > 登录锁定毫秒) { 登录失败记录.delete(IP); return 0; }
	return 记录.次数 >= 登录失败上限 ? Math.ceil((记录.首次 + 登录锁定毫秒 - Date.now()) / 1000) : 0;
}
function 记录登录失败(IP) {
	const 现在 = Date.now(), 记录 = 登录失败记录.get(IP);
	if (!记录 || 现在 - 记录.首次 > 登录锁定毫秒) 登录失败记录.set(IP, { 次数: 1, 首次: 现在 });
	else 记录.次数++;
	if (登录失败记录.size > 2000) 登录失败记录.delete(登录失败记录.keys().next().value);
}
function 安全比较(a, b) {
	a = String(a ?? ''); b = String(b ?? '');
	let 差异 = a.length ^ b.length;
	for (let i = 0; i < Math.max(a.length, b.length); i++) 差异 |= (a.charCodeAt(i % (a.length || 1)) || 0) ^ (b.charCodeAt(i % (b.length || 1)) || 0);
	return 差异 === 0;
}
function HTML转义(文本) {
	return String(文本 ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}
function JSON响应(数据, 状态码 = 200, 额外头 = {}) {
	return new Response(JSON.stringify(数据, null, 2), { status: 状态码, headers: { 'Content-Type': 'application/json;charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...额外头 } });
}
///////////////////////////////////////////////////////主程序入口 · Avatar///////////////////////////////////////////////
export default {
	async fetch(request, env, ctx) {
		let 请求URL文本 = request.url.replace(/%5[Cc]/g, '').replace(/\\/g, '');
		const 请求URL锚点索引 = 请求URL文本.indexOf('#');
		const 请求URL主体部分 = 请求URL锚点索引 === -1 ? 请求URL文本 : 请求URL文本.slice(0, 请求URL锚点索引);
		if (!请求URL主体部分.includes('?') && /%3f/i.test(请求URL主体部分)) {
			const 请求URL锚点部分 = 请求URL锚点索引 === -1 ? '' : 请求URL文本.slice(请求URL锚点索引);
			请求URL文本 = 请求URL主体部分.replace(/%3f/i, '?') + 请求URL锚点部分;
		}
		const url = new URL(请求URL文本);
		const UA = request.headers.get('User-Agent') || 'null';
		const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase(), contentType = (request.headers.get('content-type') || '').toLowerCase();
		const 管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
		const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
		const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);
		const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
		const envUUID = env.UUID || env.uuid;
		const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');
		const hosts = env.HOST ? (await 整理成数组(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]) : [url.hostname];
		const host = hosts[0];
		const 访问路径 = url.pathname.slice(1).toLowerCase();
		调试日志打印 = ['1', 'true'].includes(env.DEBUG) || 调试日志打印;
		预加载竞速拨号 = ['1', 'true'].includes(env.PRELOAD_RACE_DIAL) || 预加载竞速拨号;
		反代并发拨号数 = Math.max(1, Number(env.PROXY_CONCURRENT_DIAL) || 反代并发拨号数);
		TCP并发拨号数 = Math.max(1, Number(env.TCP_CONCURRENT_DIAL) || TCP并发拨号数);
		if (!env.TCP_CONCURRENT_DIAL && TCP并发拨号数 !== 1 && 识别运营商(request) === 'cmcc') TCP并发拨号数 = 1;
		let 默认反代IP = (`${request.cf.colo}.${特征码字典[0]}.${特征码字典[1]}SsSs.nEt`).toLowerCase(), 默认反代兜底 = true;
		if (env.PROXYIP) {
			const proxyIPs = await 整理成数组(env.PROXYIP);
			默认反代IP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
			默认反代兜底 = false;
		};
		const 访问IP = request.headers.get('CF-Connecting-IP') || request.headers.get('True-Client-IP') || request.headers.get('X-Real-IP') || request.headers.get('X-Forwarded-For') || request.headers.get('Fly-Client-IP') || request.headers.get('X-Appengine-Remote-Addr') || request.headers.get('X-Cluster-Client-IP') || 'نامشخص';
		if (缓存SOCKS5白名单 === null) {
			if (env.GO2SOCKS5) SOCKS5白名单 = [...new Set(SOCKS5白名单.concat(await 整理成数组(env.GO2SOCKS5)))];
			缓存SOCKS5白名单 = SOCKS5白名单;
		} else SOCKS5白名单 = 缓存SOCKS5白名单;
		if (访问路径 === 'version') {// 版本信息接口
			const 请求UUID = (url.searchParams.get('uuid') || '').toLowerCase();
			if (uuidRegex.test(请求UUID)) {
				const 目标UUID = String(userID).toLowerCase();
				let 请求前8总和 = 0, 目标前8总和 = 0;
				for (let i = 0; i < 8; i++) {
					const 请求码 = 请求UUID.charCodeAt(i);
					请求前8总和 += 请求码 <= 57 ? 请求码 - 48 : 请求码 - 87;
					const 目标码 = 目标UUID.charCodeAt(i);
					目标前8总和 += 目标码 <= 57 ? 目标码 - 48 : 目标码 - 87;
				}
				if (请求前8总和 === 目标前8总和 && 请求UUID.slice(-12) === 目标UUID.slice(-12)) return new Response(JSON.stringify({ Version: Number(String(Version).replace(/\D+/g, '')) }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
			}
		} else if (管理员密码 && upgradeHeader === 'websocket') {// WebSocket代理
			const 反代上下文 = await 反代参数获取(url, userID, 默认反代IP, 默认反代兜底);
			log(`[WebSocket] درخواست دریافت شد: ${url.pathname}${url.search}`);
			return await 处理WS请求(request, userID, url, 反代上下文);
		} else if (管理员密码 && !访问路径.startsWith('admin/') && 访问路径 !== 'login' && request.method === 'POST') {// gRPC/叉HTTP代理
			const 反代上下文 = await 反代参数获取(url, userID, 默认反代IP, 默认反代兜底);
			const { 头: 本机Padding头, 键: 本机Padding键 } = 获取叉HTTPPadding标识(userID);
			const 命中叉HTTP特征 = !!request.headers.get(本机Padding头) || !!url.searchParams.get(本机Padding键);
			if (!命中叉HTTP特征 && contentType.startsWith('application/grpc')) {
				log(`[gRPC] درخواست دریافت شد: ${url.pathname}${url.search}`);
				return await 处理gRPC请求(request, userID, 反代上下文);
			}
			log(`[XHTTP] درخواست دریافت شد: ${url.pathname}${url.search}`);
			return await 处理叉HTTP请求(request, userID, 反代上下文);
		} else {
			if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
			if (!管理员密码) return Avatar页面('noADMIN', 404);
			if (env.KV && typeof env.KV.get === 'function') {
				const 区分大小写访问路径 = url.pathname.slice(1);
				if (区分大小写访问路径 === 加密秘钥 && 加密秘钥 !== '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改') {//快速订阅
					const params = new URLSearchParams(url.search);
					params.set('token', await MD5MD5(host + userID));
					return new Response('در حال انتقال…', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
				} else if (访问路径 === 'login') {//处理登录页面和登录请求
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					if (authCookie == await MD5MD5(UA + 加密秘钥 + 管理员密码)) return new Response('در حال انتقال…', { status: 302, headers: { 'Location': '/admin' } });
					if (request.method === 'POST') {
						const 锁定秒 = 登录锁定剩余秒(访问IP);
						if (锁定秒 > 0) return JSON响应({ success: false, error: 'تلاش‌های ناموفق زیاد بود؛ کمی بعد دوباره امتحان کنید.', retryAfter: 锁定秒 }, 429, { 'Retry-After': String(锁定秒) });
						const formData = await request.text();
						const params = new URLSearchParams(formData);
						const 输入密码 = params.get('password');
						if (安全比较(输入密码, typeof 管理员密码 === 'string' ? 管理员密码.replace(/[\r\n]/g, '') : 管理员密码)) {
							登录失败记录.delete(访问IP);
							// 密码正确，设置cookie并返回成功标记
							const 响应 = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							响应.headers.set('Set-Cookie', `auth=${await MD5MD5(UA + 加密秘钥 + 管理员密码)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax`);
							return 响应;
						}
						记录登录失败(访问IP);
						await new Promise(r => setTimeout(r, 350));
						const 剩余次数 = Math.max(0, 登录失败上限 - (登录失败记录.get(访问IP)?.次数 || 0));
						return JSON响应({ success: false, error: 'رمز عبور نادرست است', remaining: 剩余次数 });
					}
					return Avatar页面('login');
				} else if (访问路径 === 'admin' || 访问路径.startsWith('admin/')) {//验证cookie后响应管理页面
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					// 没有cookie或cookie错误，跳转到/login页面
					if (!authCookie || !安全比较(authCookie, await MD5MD5(UA + 加密秘钥 + 管理员密码))) return new Response('در حال انتقال…', { status: 302, headers: { 'Location': '/login', 'Cache-Control': 'no-store' } });
					const 请求来源 = request.headers.get('Origin');
					if (request.method !== 'GET' && request.method !== 'HEAD' && 请求来源 && 请求来源 !== url.origin) return JSON响应({ error: 'درخواست از مبدأ نامعتبر رد شد' }, 403);
					if (访问路径 === 'admin/log.json') {// 读取日志内容
						const 读取日志内容 = await env.KV.get('log.json') || '[]';
						return new Response(读取日志内容, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8', 'Cache-Control': 'no-store' } });
					} else if (区分大小写访问路径 === 'admin/getCloudflareUsage') {// 查询请求量
						try {
							const Usage_JSON = await getCloudflareUsage(url.searchParams.get('Email'), url.searchParams.get('GlobalAPIKey'), url.searchParams.get('AccountID'), url.searchParams.get('APIToken'));
							return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
						} catch (err) {
							const errorResponse = { msg: 'دریافت آمار درخواست‌ها ناموفق بود. علت: ' + err.message, error: err.message };
							return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
					} else if (区分大小写访问路径 === 'admin/getADDAPI') {// 验证优选API
						if (url.searchParams.get('url')) {
							const 待验证优选URL = url.searchParams.get('url');
							try {
								new URL(待验证优选URL);
								const 请求优选API内容 = await 请求优选API([待验证优选URL], url.searchParams.get('port') || '443');
								let 优选API的IP = 请求优选API内容[0].length > 0 ? 请求优选API内容[0] : 请求优选API内容[1];
								优选API的IP = 优选API的IP.map(item => item.replace(/#(.+)$/, (_, remark) => '#' + decodeURIComponent(remark)));
								return new Response(JSON.stringify({ success: true, data: 优选API的IP }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (err) {
								const errorResponse = { msg: 'بررسی API آی‌پی بهینه ناموفق بود. علت: ' + err.message, error: err.message };
								return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						}
						return new Response(JSON.stringify({ success: false, data: [] }, null, 2), { status: 403, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (访问路径 === 'admin/check') {// 代理检查
						const 代理协议 = ['socks5', 'http', 'https', 'turn', 'sstp'].find(类型 => url.searchParams.has(类型)) || null;
						if (!代理协议) return new Response(JSON.stringify({ error: 'پارامتر پراکسی ارسال نشده است' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						const 代理参数 = url.searchParams.get(代理协议);
						const startTime = Date.now();
						let 检测代理响应;
						try {
							const checkParsed = await 获取SOCKS5账号(代理参数, 获取代理默认端口(代理协议));
							const { username, password, hostname, port } = checkParsed;
							const 完整代理参数 = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
							try {
								const 检测主机 = 'cloudflare.com', 检测端口 = 443, encoder = new TextEncoder(), decoder = new TextDecoder();
								const TCP连接 = 创建请求TCP连接器(request);
								let tcpSocket = null, tlsSocket = null;
								try {
									tcpSocket = 代理协议 === 'socks5'
										? await socks5Connect(检测主机, 检测端口, new Uint8Array(0), TCP连接, checkParsed)
										: 代理协议 === 'turn'
											? await turnConnect(checkParsed, 检测主机, 检测端口, TCP连接)
											: 代理协议 === 'sstp'
												? await sstpConnect(checkParsed, 检测主机, 检测端口, TCP连接)
												: (代理协议 === 'https' && isIPHostname(hostname)
													? await httpsConnect(检测主机, 检测端口, new Uint8Array(0), TCP连接, checkParsed)
													: await httpConnect(检测主机, 检测端口, new Uint8Array(0), 代理协议 === 'https', TCP连接, checkParsed));
									if (!tcpSocket) throw new Error('اتصال به سرور پراکسی برقرار نشد');
									tlsSocket = new TlsClient(tcpSocket, { serverName: 检测主机, insecure: true });
									await tlsSocket.handshake();
									await tlsSocket.write(encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: ${检测主机}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`));
									let responseBuffer = new Uint8Array(0), headerEndIndex = -1, contentLength = null, chunked = false;
									const 最大响应字节 = 64 * 1024;
									while (responseBuffer.length < 最大响应字节) {
										const value = await tlsSocket.read();
										if (!value) break;
										if (value.byteLength === 0) continue;
										responseBuffer = 拼接字节数据(responseBuffer, value);
										if (headerEndIndex === -1) {
											const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
											if (crlfcrlf !== -1) {
												headerEndIndex = crlfcrlf + 4;
												const headers = decoder.decode(responseBuffer.slice(0, headerEndIndex));
												const statusLine = headers.split('\r\n')[0] || '';
												const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
												const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
												if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`درخواست آزمایشی پراکسی ناموفق بود: ${statusLine || 'پاسخ نامعتبر'}`);
												const lengthMatch = headers.match(/\r\nContent-Length:\s*(\d+)/i);
												if (lengthMatch) contentLength = parseInt(lengthMatch[1], 10);
												chunked = /\r\nTransfer-Encoding:\s*chunked/i.test(headers);
											}
										}
										if (headerEndIndex !== -1 && contentLength !== null && responseBuffer.length >= headerEndIndex + contentLength) break;
										if (headerEndIndex !== -1 && chunked && decoder.decode(responseBuffer).includes('\r\n0\r\n\r\n')) break;
									}
									if (headerEndIndex === -1) throw new Error('سرآیند پاسخ آزمایش پراکسی بیش از حد طولانی یا نامعتبر است');
									const response = decoder.decode(responseBuffer);
									const ip = response.match(/(?:^|\n)ip=(.*)/)?.[1];
									const loc = response.match(/(?:^|\n)loc=(.*)/)?.[1];
									if (!ip || !loc) throw new Error('پاسخ آزمایش پراکسی نامعتبر است');
									检测代理响应 = { success: true, proxy: 代理协议 + "://" + 完整代理参数, ip, loc, responseTime: Date.now() - startTime };
								} finally {
									try { tlsSocket ? tlsSocket.close() : await tcpSocket?.close?.() } catch (e) { }
								}
							} catch (error) {
								检测代理响应 = { success: false, error: error.message, proxy: 代理协议 + "://" + 完整代理参数, responseTime: Date.now() - startTime };
							}
						} catch (err) {
							检测代理响应 = { success: false, error: err.message, proxy: 代理协议 + "://" + 代理参数, responseTime: Date.now() - startTime };
						}
						return new Response(JSON.stringify(检测代理响应, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					}

					config_JSON = await 读取config_JSON(env, host, userID, UA);

					if (访问路径 === 'admin/init') {// 重置配置为默认值
						if (request.method !== 'POST') return JSON响应({ error: 'بازنشانی فقط با درخواست POST انجام می‌شود' }, 405, { 'Allow': 'POST' });
						try {
							config_JSON = await 读取config_JSON(env, host, userID, UA, true);
							ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Init_Config', config_JSON));
							config_JSON.init = 'تنظیمات به حالت پیش‌فرض بازگشت';
							return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						} catch (err) {
							const errorResponse = { msg: 'بازنشانی تنظیمات ناموفق بود. علت: ' + err.message, error: err.message };
							return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
					} else if (request.method === 'POST') {// 处理 KV 操作（POST 请求）
						if (访问路径 === 'admin/config.json') { // 保存config.json配置
							try {
								const newConfig = await request.json();
								// 验证配置完整性
								if (!newConfig.UUID || !newConfig.HOST) return new Response(JSON.stringify({ error: 'اطلاعات تنظیمات کامل نیست' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });

								// 保存到 KV
								await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
								ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: 'تنظیمات ذخیره شد' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('ذخیرهٔ تنظیمات ناموفق بود:', error);
								return new Response(JSON.stringify({ error: 'ذخیرهٔ تنظیمات ناموفق بود: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (访问路径 === 'admin/cf.json') { // 保存cf.json配置
							try {
								const newConfig = await request.json();
								const CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
								if (!newConfig.init || newConfig.init !== true) {
									if (newConfig.Email && newConfig.GlobalAPIKey) {
										CF_JSON.Email = newConfig.Email;
										CF_JSON.GlobalAPIKey = newConfig.GlobalAPIKey;
									} else if (newConfig.AccountID && newConfig.APIToken) {
										CF_JSON.AccountID = newConfig.AccountID;
										CF_JSON.APIToken = newConfig.APIToken;
									} else if (newConfig.UsageAPI) {
										CF_JSON.UsageAPI = newConfig.UsageAPI;
									} else {
										return new Response(JSON.stringify({ error: 'اطلاعات تنظیمات کامل نیست' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
									}
								}

								// 保存到 KV
								await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
								ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: 'تنظیمات ذخیره شد' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('ذخیرهٔ تنظیمات ناموفق بود:', error);
								return new Response(JSON.stringify({ error: 'ذخیرهٔ تنظیمات ناموفق بود: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (访问路径 === 'admin/tg.json') { // 保存tg.json配置
							try {
								const newConfig = await request.json();
								if (newConfig.init && newConfig.init === true) {
									const TG_JSON = { BotToken: null, ChatID: null };
									await env.KV.put('tg.json', JSON.stringify(TG_JSON, null, 2));
								} else {
									if (!newConfig.BotToken || !newConfig.ChatID) return new Response(JSON.stringify({ error: 'اطلاعات تنظیمات کامل نیست' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
									await env.KV.put('tg.json', JSON.stringify(newConfig, null, 2));
								}
								ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: 'تنظیمات ذخیره شد' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('ذخیرهٔ تنظیمات ناموفق بود:', error);
								return new Response(JSON.stringify({ error: 'ذخیرهٔ تنظیمات ناموفق بود: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (区分大小写访问路径 === 'admin/ADD.txt') { // 保存自定义优选IP
							try {
								const customIPs = await request.text();
								await env.KV.put('ADD.txt', customIPs);// 保存到 KV
								ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Custom_IPs', config_JSON));
								return new Response(JSON.stringify({ success: true, message: 'فهرست سفارشی ذخیره شد' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('ذخیرهٔ فهرست سفارشی ناموفق بود:', error);
								return new Response(JSON.stringify({ error: 'ذخیرهٔ فهرست سفارشی ناموفق بود: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else return new Response(JSON.stringify({ error: 'این مسیر از درخواست POST پشتیبانی نمی‌کند' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (访问路径 === 'admin/config.json') {// 处理 admin/config.json 请求，返回JSON
						return JSON响应(config_JSON);
					} else if (区分大小写访问路径 === 'admin/ADD.txt') {// 处理 admin/ADD.txt 请求，返回本地优选IP
						let 本地优选IP = await env.KV.get('ADD.txt') || 'null';
						if (本地优选IP == 'null') 本地优选IP = (await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口))[1];
						return new Response(本地优选IP, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Cache-Control': 'no-store', 'asn': String(request.cf?.asn ?? '') } });
					} else if (访问路径 === 'admin/cf.json') {// CF配置文件
						return JSON响应(request.cf || {});
					}

					ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Admin_Login', config_JSON));
					return Avatar页面('admin');
				} else if (访问路径 === 'logout' || uuidRegex.test(访问路径)) {//清除cookie并跳转到登录页面
					const 响应 = new Response('در حال انتقال…', { status: 302, headers: { 'Location': '/login' } });
					响应.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax');
					return 响应;
				} else if (访问路径 === 'sub') {//处理订阅请求
					const 订阅TOKEN = await MD5MD5(host + userID), 作为优选订阅生成器 = ['1', 'true'].includes(env.BEST_SUB) && url.searchParams.get('host') === 'example.com' && url.searchParams.get('uuid') === '00000000-0000-4000-8000-000000000000' && UA.toLowerCase().includes('tunnel (https://github.com/' + 特征码字典[1] + '/edge');
					const 请求TOKEN = url.searchParams.get('token');
					const 用户客户端请求订阅 = 请求TOKEN === 订阅TOKEN;
					const 当前日序号 = Math.floor(Date.now() / 86400000);
					const 订阅转换后端TOKEN种子 = base64SecretEncode(订阅TOKEN, userID);
					const [今日订阅转换后端专属TOKEN, 昨日订阅转换后端专属TOKEN] = await Promise.all([
						MD5MD5(订阅转换后端TOKEN种子 + 当前日序号),
						MD5MD5(订阅转换后端TOKEN种子 + (当前日序号 - 1)),
					]);
					const 订阅转换后端请求订阅 = 请求TOKEN === 今日订阅转换后端专属TOKEN || 请求TOKEN === 昨日订阅转换后端专属TOKEN;
					if (用户客户端请求订阅 || 订阅转换后端请求订阅 || 作为优选订阅生成器) {
						config_JSON = await 读取config_JSON(env, host, userID, UA);
						if (作为优选订阅生成器) ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Get_Best_SUB', config_JSON, false));
						else ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Get_SUB', config_JSON));
						const ua = UA.toLowerCase();
						const responseHeaders = {
							"content-type": "text/plain; charset=utf-8",
							"Profile-Update-Interval": config_JSON.优选订阅生成.SUBUpdateTime,
							"Profile-web-page-url": url.protocol + '//' + url.host + '/admin',
							"Cache-Control": "no-store",
						};
						if (config_JSON.CF.Usage.success) {
							const pagesSum = config_JSON.CF.Usage.pages;
							const workersSum = config_JSON.CF.Usage.workers;
							const total = Number.isFinite(config_JSON.CF.Usage.max) ? (config_JSON.CF.Usage.max / 1000) * 1024 : 1024 * 100;
							responseHeaders["Subscription-Userinfo"] = `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=4102329600`; // 2099-12-31 到期时间
						}
						const isSubConverterRequest = url.searchParams.has('b64') || url.searchParams.has('base64') || request.headers.get('subconverter-request') || request.headers.get('subconverter-version') || ua.includes('subconverter') || ua.includes(('CF-Workers-SUB').toLowerCase()) || 作为优选订阅生成器;
						const 订阅类型 = isSubConverterRequest
							? 'mixed'
							: url.searchParams.has('target')
								? url.searchParams.get('target')
								: url.searchParams.has('clash') || ua.includes('clash') || ua.includes('meta') || ua.includes('mihomo')
									? 'clash'
									: url.searchParams.has('sb') || url.searchParams.has('singbox') || ua.includes('singbox') || ua.includes('sing-box')
										? 'singbox'
										: url.searchParams.has('surge') || ua.includes('surge')
											? 'surge&ver=4'
											: url.searchParams.has('quanx') || ua.includes('quantumult')
												? 'quanx'
												: url.searchParams.has('loon') || ua.includes('loon')
													? 'loon'
													: 'mixed';

						if (!ua.includes('mozilla')) responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`;
						const 协议类型 = ((url.searchParams.has('surge') || ua.includes('surge')) && config_JSON.协议类型 !== 'ss') ? 'tro' + 'jan' : config_JSON.协议类型;
						let 订阅内容 = '';
						if (订阅类型 === 'mixed') {
							const TLS分片参数 = config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
							let 完整优选IP = [], 其他节点LINK = '', 反代IP池 = [];

							if (!url.searchParams.has('sub') && config_JSON.优选订阅生成.local) { // 本地生成订阅
								const 完整优选列表 = config_JSON.优选订阅生成.本地IP库.随机IP ? (
									await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口)
								)[0] : await env.KV.get('ADD.txt') ? await 整理成数组(await env.KV.get('ADD.txt')) : (
									await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口)
								)[0];
								const 优选API = [], 优选IP = [], 其他节点 = [];
								for (const 元素 of 完整优选列表) {
									if (元素.toLowerCase().startsWith('sub://')) {
										优选API.push(元素);
									} else {
										const 备注位置 = 元素.indexOf('#');
										const 地址部分 = 备注位置 > -1 ? 元素.slice(0, 备注位置) : 元素;
										const 备注部分 = 备注位置 > -1 ? 元素.slice(备注位置) : '';
										const subMatch = 元素.match(/sub\s*=\s*([^\s&#]+)/i);
										if (subMatch && subMatch[1].trim().includes('.')) {
											const 优选IP作为反代IP = 元素.toLowerCase().includes('proxyip=true');
											if (优选IP作为反代IP) 优选API.push('sub://' + subMatch[1].trim() + "?proxyip=true" + (元素.includes('#') ? ('#' + 元素.split('#')[1]) : ''));
											else 优选API.push('sub://' + subMatch[1].trim() + (元素.includes('#') ? ('#' + 元素.split('#')[1]) : ''));
										} else if (地址部分.toLowerCase().startsWith('https://')) {
											优选API.push(元素);
										} else if (地址部分.toLowerCase().includes('://')) {
											if (元素.includes('#')) {
												const 地址备注分离 = 元素.split('#');
												其他节点.push(地址备注分离[0] + '#' + encodeURIComponent(decodeURIComponent(地址备注分离[1])));
											} else 其他节点.push(元素);
										} else {
											if (地址部分.includes('*')) {
												优选IP.push(替换星号为随机字符(地址部分) + 备注部分);
											} else 优选IP.push(元素);
										}
									}
								}
								const 请求优选API内容 = await 请求优选API(优选API, '443');
								const 合并其他节点数组 = [...new Set(其他节点.concat(请求优选API内容[1]))];
								其他节点LINK = 合并其他节点数组.length > 0 ? 合并其他节点数组.join('\n') + '\n' : '';
								const 优选API的IP = 请求优选API内容[0];
								反代IP池 = 请求优选API内容[3] || [];
								完整优选IP = [...new Set(优选IP.concat(优选API的IP))];
							} else { // 优选订阅生成器
								let 优选订阅生成器HOST = url.searchParams.get('sub') || config_JSON.优选订阅生成.SUB;
								const [优选生成器IP数组, 优选生成器其他节点] = await 获取优选订阅生成器数据(优选订阅生成器HOST);
								完整优选IP = 完整优选IP.concat(优选生成器IP数组);
								其他节点LINK += 优选生成器其他节点;
							}
							const ECHLINK参数 = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
							const isLoonOrSurge = ua.includes('loon') || ua.includes('surge');
							const { type: 传输协议, 路径字段名, 域名字段名 } = 获取传输协议配置(config_JSON);
							订阅内容 = 其他节点LINK + 完整优选IP.map(原始地址 => {
								// 统一正则: 匹配 域名/IPv4/IPv6地址 + 可选端口 + 可选备注
								// 示例:
								//   - 域名: hj.xmm1993.top:2096#备注 或 example.com
								//   - IPv4: 166.0.188.128:443#Los Angeles 或 166.0.188.128
								//   - IPv6: [2606:4700::]:443#CMCC 或 [2606:4700::]
								const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
								const match = 原始地址.match(regex);

								let 节点地址, 节点端口 = "443", 节点备注;

								if (match) {
									节点地址 = match[1];  // IP地址或域名(可能带方括号)
									节点端口 = match[2] ? match[2] : '443';  // 端口默认443，SS noTLS在生成链接时再映射
									节点备注 = match[3] || 节点地址;  // 备注,默认为地址本身
								} else {
									// 不规范的格式，跳过处理返回null
									console.warn(`[محتوای اشتراک] قالب نادرست آی‌پی نادیده گرفته شد: ${原始地址}`);
									return null;
								}

								let 完整节点路径 = config_JSON.完整节点路径;

								const 链式代理匹配 = 节点备注.match(/\$(socks5|http|https|turn|sstp):\/\/([^#\s]+)/i);
								if (链式代理匹配) {
									try {
										const 代理协议 = 链式代理匹配[1].toLowerCase(), 代理参数 = 链式代理匹配[2];
										const 链式代理数据 = { type: 代理协议, ...获取SOCKS5账号(代理参数, 获取代理默认端口(代理协议)) };
										完整节点路径 = `/video/${base64SecretEncode(JSON.stringify(链式代理数据), userID) + (config_JSON.启用0RTT ? '?ed=2560' : '')}`;
										节点备注 = 节点备注.replace(链式代理匹配[0], '').trim() || 节点地址;
									} catch (error) {
										console.warn(`[محتوای اشتراک] تجزیهٔ پراکسی زنجیره‌ای ناموفق بود و نادیده گرفته شد: ${链式代理匹配[0]} (${error && error.message ? error.message : error})`);
									}
								} else if (反代IP池.length > 0) {
									const 匹配到的反代IP = 反代IP池.find(p => p.includes(节点地址));
									if (匹配到的反代IP) 完整节点路径 = (`${config_JSON.PATH}/proxyip=${匹配到的反代IP}`).replace(/\/\//g, '/') + (config_JSON.启用0RTT ? '?ed=2560' : '');
								}
								if (isLoonOrSurge) 完整节点路径 = 完整节点路径.replace(/,/g, '%2C');

								if (协议类型 === 'ss' && !作为优选订阅生成器) {
									if (!config_JSON.SS.TLS) {
										const TLS端口 = [443, 2053, 2083, 2087, 2096, 8443];
										const NOTLS端口 = [80, 2052, 2082, 2086, 2095, 8080];
										节点端口 = String(NOTLS端口[TLS端口.indexOf(Number(节点端口))] ?? 节点端口);
									}
									完整节点路径 = (完整节点路径.includes('?') ? 完整节点路径.replace('?', '?enc=' + config_JSON.SS.加密方式 + '&') : (完整节点路径 + '?enc=' + config_JSON.SS.加密方式)).replace(/([=,])/g, '\\$1');
									if (!isSubConverterRequest) 完整节点路径 = 完整节点路径 + ';mux=0';
									return `${协议类型}://${btoa(config_JSON.SS.加密方式 + ':00000000-0000-4000-8000-000000000000')}@${节点地址}:${节点端口}?plugin=v2${encodeURIComponent('ray-plugin;mode=websocket;host=example.com;path=' + (config_JSON.随机路径 ? 随机路径(完整节点路径) : 完整节点路径) + (config_JSON.SS.TLS ? ';tls' : '')) + ECHLINK参数 + TLS分片参数}#${encodeURIComponent(节点备注)}`;
								} else {
									const 传输路径参数值 = 获取传输路径参数值(config_JSON, 完整节点路径, 作为优选订阅生成器);
									return `${协议类型}://00000000-0000-4000-8000-000000000000@${节点地址}:${节点端口}?security=tls&type=${传输协议 + ECHLINK参数}&${域名字段名}=example.com&fp=${config_JSON.Fingerprint}&sni=example.com&${路径字段名}=${encodeURIComponent(传输路径参数值) + TLS分片参数}&encryption=none&alpn=${encodeURIComponent(config_JSON.ALPN)}#${encodeURIComponent(节点备注)}`;
								}
							}).filter(item => item !== null).join('\n');
						} else { // 订阅转换
							const 订阅转换URL = `${String(config_JSON.订阅转换配置.SUBAPI || 默认订阅转换后端).replace(/\/+$/, '')}/sub?target=${订阅类型}&url=${encodeURIComponent(url.protocol + '//' + url.host + '/sub?target=mixed&token=' + 今日订阅转换后端专属TOKEN + '&cnIspCode=' + 识别运营商(request) + (url.searchParams.has('sub') && url.searchParams.get('sub') != '' ? `&sub=${url.searchParams.get('sub')}` : ''))}&config=${encodeURIComponent(config_JSON.订阅转换配置.SUBCONFIG || 默认订阅转换规则)}&emoji=${config_JSON.订阅转换配置.SUBEMOJI}&list=${config_JSON.订阅转换配置.SUBLIST}&scv=${config_JSON.跳过证书验证}&xudp=${config_JSON.订阅转换配置.XUDP}&udp=${config_JSON.订阅转换配置.UDP}&tls13=${config_JSON.订阅转换配置.TLS13}&append_type=${config_JSON.订阅转换配置.APPEND_TYPE}&sort=${config_JSON.订阅转换配置.SORT}&expand=${config_JSON.订阅转换配置.EXPAND}`;
							try {
								const response = await fetch(订阅转换URL, { headers: { 'User-Agent': 'Subconverter for ' + 订阅类型 + ' edge' + 'tunnel (https://github.com/' + 特征码字典[1] + '/edge' + 'tunnel)' } });
								if (response.ok) {
									订阅内容 = await response.text();
									if (url.searchParams.has('surge') || ua.includes('surge')) 订阅内容 = Surge订阅配置文件热补丁(订阅内容, url.protocol + '//' + url.host + '/sub?token=' + 订阅TOKEN + '&surge', config_JSON);
								} else return new Response('خطا در سرویس تبدیل اشتراک: ' + response.statusText, { status: response.status });
							} catch (error) {
								return new Response('خطا در سرویس تبدیل اشتراک: ' + error.message, { status: 403 });
							}
						}

						if (!ua.includes('subconverter') && 用户客户端请求订阅) {
							const 打乱后HOSTS = [...config_JSON.HOSTS].sort(() => Math.random() - 0.5);
							let 替换域名计数 = 0, 当前随机HOST = null;
							订阅内容 = 订阅内容
								.replace(/00000000-0000-4000-8000-000000000000/g, config_JSON.UUID)
								.replace(/MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAw/g, btoa(config_JSON.UUID))
								.replace(/example\.com/g, () => {
									if (替换域名计数 % 2 === 0) {
										const 原始host = 打乱后HOSTS[Math.floor(替换域名计数 / 2) % 打乱后HOSTS.length];
										当前随机HOST = 替换星号为随机字符(原始host);
									}
									替换域名计数++;
									return 当前随机HOST;
								});
						}

						if (订阅类型 === 'mixed' && (!ua.includes('mozilla') || url.searchParams.has('b64') || url.searchParams.has('base64'))) 订阅内容 = btoa(订阅内容);

						if (订阅类型 === 'singbox') {
							订阅内容 = await Singbox订阅配置文件热补丁(订阅内容, config_JSON);
							responseHeaders["content-type"] = 'application/json; charset=utf-8';
						} else if (订阅类型 === 'clash') {
							订阅内容 = Clash订阅配置文件热补丁(订阅内容, config_JSON);
							responseHeaders["content-type"] = 'application/x-yaml; charset=utf-8';
						}
						return new Response(订阅内容, { status: 200, headers: responseHeaders });
					}
				} else if (访问路径 === 'locations') {//反代locations列表
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					if (authCookie && authCookie == await MD5MD5(UA + 加密秘钥 + 管理员密码)) return fetch(new Request('https://speed.cloudflare.com/locations', { headers: { 'Referer': 'https://speed.cloudflare.com/' } }));
				} else if (访问路径 === 'robots.txt') return new Response('User-agent: *\nDisallow: /', { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });
			} else if (!envUUID) return Avatar页面('noKV', 404);
		}

		let 伪装页URL = env.URL || 'nginx';
		if (伪装页URL && 伪装页URL !== 'nginx' && 伪装页URL !== '1101') {
			伪装页URL = 伪装页URL.trim().replace(/\/$/, '');
			if (!伪装页URL.match(/^https?:\/\//i)) 伪装页URL = 'https://' + 伪装页URL;
			if (伪装页URL.toLowerCase().startsWith('http://')) 伪装页URL = 'https://' + 伪装页URL.substring(7);
			try { const u = new URL(伪装页URL); 伪装页URL = u.protocol + '//' + u.host } catch (e) { 伪装页URL = 'nginx' }
		}
		if (伪装页URL === '1101') return new Response(await html1101(url.host, 访问IP), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
		try {
			const 反代URL = new URL(伪装页URL), 新请求头 = new Headers(request.headers);
			新请求头.set('Host', 反代URL.host);
			const 原始Cookie = 新请求头.get('Cookie');
			if (原始Cookie) {
				const 安全Cookie = 原始Cookie.split(';').map(c => c.trim()).filter(c => c && !c.startsWith('auth=')).join('; ');
				安全Cookie ? 新请求头.set('Cookie', 安全Cookie) : 新请求头.delete('Cookie');
			}
			新请求头.set('Referer', 反代URL.origin);
			新请求头.set('Origin', 反代URL.origin);
			if (!新请求头.has('User-Agent') && UA && UA !== 'null') 新请求头.set('User-Agent', UA);
			const 反代响应 = await fetch(反代URL.origin + url.pathname + url.search, { method: request.method, headers: 新请求头, body: request.body, cf: request.cf });
			const 内容类型 = 反代响应.headers.get('content-type') || '';
			// 只处理文本类型的响应
			if (/text|javascript|json|xml/.test(内容类型)) {
				const 响应内容 = (await 反代响应.text()).replaceAll(反代URL.host, url.host);
				return new Response(响应内容, { status: 反代响应.status, headers: { ...Object.fromEntries(反代响应.headers), 'Cache-Control': 'no-store' } });
			}
			return 反代响应;
		} catch (error) { }
		return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
	}
};
///////////////////////////////////////////////////////////////////////叉HTTP传输数据///////////////////////////////////////////////
const HPACKHuffman码长 = [
	13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
	28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
	6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
	5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
	13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
	15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
	6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
	20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
	24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
	22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
	21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
	26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
	19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
	20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
	26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
	30
];

function 获取叉HTTPPadding标识(yourUUID) {
	return { 头: yourUUID.slice(1, 7), 键: '_' + yourUUID.slice(25, 31) };
}

function 计算HPACKHuffman字节长度(字符串) {
	const 字节 = new TextEncoder().encode(字符串);
	let 总位数 = 0;
	for (let i = 0; i < 字节.length; i++) {
		总位数 += HPACKHuffman码长[字节[i]];
	}
	return Math.ceil(总位数 / 8);
}

function 提取叉HTTPPadding值(request, 本机Padding头, 本机Padding键) {
	const 头值 = request.headers.get(本机Padding头);
	if (头值) {
		try {
			const 解析URL = new URL(头值, 'https://x.invalid');
			const 查询值 = 解析URL.searchParams.get(本机Padding键);
			if (查询值) return 查询值;
		} catch (e) { }
		return 头值;
	}
	const 请求URL = new URL(request.url);
	return 请求URL.searchParams.get(本机Padding键) || '';
}

function 校验叉HTTPPadding(request, 本机Padding头, 本机Padding键) {
	const padding值 = 提取叉HTTPPadding值(request, 本机Padding头, 本机Padding键);
	if (!padding值) return true;
	const huffman长度 = 计算HPACKHuffman字节长度(padding值);
	return huffman长度 >= 98 && huffman长度 <= 1002;
}

const 叉HTTPBase62字符集 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
function 生成叉HTTPPadding串(长度) {
	const 字符集长度 = 叉HTTPBase62字符集.length;
	let 结果 = '';
	for (let i = 0; i < 长度; i++) {
		结果 += 叉HTTPBase62字符集[Math.floor(Math.random() * 字符集长度)];
	}
	return 结果;
}

async function 处理叉HTTP请求(request, yourUUID, 反代上下文 = {}) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const { 头: 本机Padding头, 键: 本机Padding键 } = 获取叉HTTPPadding标识(yourUUID);
	if (!校验叉HTTPPadding(request, 本机Padding头, 本机Padding键)) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const 首包 = await 读取叉HTTP首包(reader, yourUUID);
	if (!首包) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('Invalid request', { status: 400 });
	}
	if (isSpeedTestSite(首包.hostname) && 反代上下文.代理类型 === null) {
		try { reader.releaseLock() } catch (e) { }
		return new Response(构造本地204响应(首包.respHeader), {
			status: 200,
			headers: {
				'Content-Type': 'application/octet-stream',
				'X-Accel-Buffering': 'no',
				'Cache-Control': 'no-store'
			}
		});
	}
	if (首包.isUDP && 首包.协议 !== 'trojan' && 首包.port !== 53) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('UDP is not supported', { status: 400 });
	}

	const responseHeaders = new Headers({
		'Content-Type': 'application/octet-stream',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	try {
		const 响应URL = new URL('https://x.invalid/');
		响应URL.searchParams.set(本机Padding键, 生成叉HTTPPadding串(100 + Math.floor(Math.random() * 901)));
		responseHeaders.set(本机Padding头, 响应URL.toString());
	} catch (e) { }

	if (首包.isUDP) return 处理叉HTTPUDP请求(首包, reader, request, 反代上下文, responseHeaders);

	try { reader.releaseLock() } catch (e) { }

	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const abortController = new AbortController();
	let 已清理 = false;
	const 清理 = (reason) => {
		if (已清理) return;
		已清理 = true;
		try { abortController.abort(reason) } catch (e) { }
		失效TCP连接世代(remoteConnWrapper);
	};

	const 占位WS = { readyState: WebSocket.OPEN };

	let socket;
	try {
		socket = await forwardataTCP(首包.hostname, 首包.port, 首包.rawData, 占位WS, 首包.respHeader, remoteConnWrapper, yourUUID, request, 反代上下文, 首包.协议 === 'trojan', 首包.原始数据, true);
	} catch (err) {
		log(`[XHTTP-Pipe] اتصال ناموفق بود: ${err?.message || err}`);
		清理(err);
		return new Response('bad gateway', { status: 502 });
	}
	if (!socket) {
		清理(new Error('socket is null'));
		return new Response('bad gateway', { status: 502 });
	}

	const 上行Promise = (async () => {
		const 上行合包器 = 创建上行Grain合包流();
		const 搬运Promise = 上行合包器.readable.pipeTo(socket.writable, { signal: abortController.signal });
		void 搬运Promise.catch(清理);
		const 上行reader = request.body.getReader();
		const 取消上行reader = () => {
			try { 上行reader.cancel(abortController.signal.reason).catch(() => { }); } catch (e) { }
		};
		abortController.signal.addEventListener('abort', 取消上行reader, { once: true });
		try {
			try {
				while (true) {
					const { done, value } = await 上行reader.read();
					if (done) break;
					if (value?.byteLength) await 上行合包器.写入(value);
				}
			} finally {
				abortController.signal.removeEventListener('abort', 取消上行reader);
				try { 上行reader.releaseLock() } catch (e) { }
			}
		} finally {
			try { await 上行合包器.结束() } catch (e) { }
		}
		await 搬运Promise;
	})();

	const 响应流 = typeof IdentityTransformStream !== 'undefined'
		? new IdentityTransformStream()
		: new TransformStream();
	const 下行Promise = (async () => {
		const writer = 响应流.writable.getWriter();
		try {
			if (有效数据长度(首包.respHeader) > 0) await writer.write(首包.respHeader);
		} catch (error) {
			try { await writer.abort(error) } catch (e) { }
			throw error;
		} finally {
			try { writer.releaseLock() } catch (e) { }
		}
		await socket.readable.pipeTo(响应流.writable, { signal: abortController.signal });
	})();

	void 上行Promise.catch(清理);
	void 下行Promise.then(() => 清理(), 清理);
	void Promise.allSettled([上行Promise, 下行Promise]);

	return new Response(响应流.readable, { status: 200, headers: responseHeaders });
}

function 处理叉HTTPUDP请求(首包, reader, request, 反代上下文, responseHeaders) {
	const 木马UDP上下文 = { 缓存: new Uint8Array(0), 反代地址: 反代上下文.木马反代地址 };
	return new Response(new ReadableStream({
		async start(controller) {
			let 已关闭 = false;
			let udpRespHeader = 首包.respHeader;
			const 叉桥 = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (已关闭) return;
					try {
						const chunk = data instanceof Uint8Array
							? data
							: data instanceof ArrayBuffer
								? new Uint8Array(data)
								: ArrayBuffer.isView(data)
									? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
									: new Uint8Array(data);
						controller.enqueue(chunk);
					} catch (e) {
						已关闭 = true;
						this.readyState = WebSocket.CLOSED;
					}
				},
				close() {
					if (已关闭) return;
					已关闭 = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close() } catch (e) { }
				}
			};
			let 转发失败 = false;
			try {
				if (首包.协议 === 'trojan') {
					木马UDP上下文.目标主机 = 首包.hostname;
					木马UDP上下文.目标端口 = 首包.port;
					if (木马UDP上下文.反代地址) await 转发木马UDP数据(首包.原始数据, 叉桥, 木马UDP上下文, request);
				}
				if (!(首包.协议 === 'trojan' && 木马UDP上下文.反代地址) && 首包.rawData?.byteLength) {
					if (首包.协议 === 'trojan') await 转发木马UDP数据(首包.rawData, 叉桥, 木马UDP上下文, request);
					else await forwardataudp(首包.rawData, 叉桥, udpRespHeader, request);
					udpRespHeader = null;
				}
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					if (首包.协议 === 'trojan') await 转发木马UDP数据(value, 叉桥, 木马UDP上下文, request);
					else await forwardataudp(value, 叉桥, udpRespHeader, request);
					udpRespHeader = null;
				}
			} catch (err) {
				转发失败 = true;
				log(`[انتقال XHTTP] پردازش ناموفق بود: ${err?.message || err}`);
				closeSocketQuietly(叉桥);
			} finally {
				const 保持木马UDP反代下行 = !转发失败 && 首包.协议 === 'trojan' && 木马UDP上下文.反代地址 && 木马UDP上下文.反代Socket;
				if (!保持木马UDP反代下行) {
					try { 木马UDP上下文.反代Socket?.close() } catch (e) { }
					closeSocketQuietly(叉桥);
				}
				try { reader.releaseLock() } catch (e) { }
			}
		},
		cancel() {
			try { 木马UDP上下文.反代Socket?.close() } catch (e) { }
			try { reader.releaseLock() } catch (e) { }
		}
	}), { status: 200, headers: responseHeaders });
}

function 有效数据长度(data) {
	if (!data) return 0;
	if (typeof data.byteLength === 'number') return data.byteLength;
	if (typeof data.length === 'number') return data.length;
	return 0;
}

function 失效TCP连接世代(remoteConnWrapper) {
	if (!remoteConnWrapper) return;
	remoteConnWrapper.generation = (Number.isInteger(remoteConnWrapper.generation) ? remoteConnWrapper.generation : 0) + 1;
	const socket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	remoteConnWrapper.downlinkController = null;
	remoteConnWrapper.downlinkDrain = Promise.resolve();
	try { socket?.close?.() } catch (e) { }
}

function 开始TCP连接世代(remoteConnWrapper) {
	if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;
	const generation = ++remoteConnWrapper.generation;
	const previousSocket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	const previousDownlink = remoteConnWrapper.downlinkController;
	remoteConnWrapper.downlinkController = null;
	const previousDrain = remoteConnWrapper.downlinkDrain || Promise.resolve();
	let currentDrain;
	try { currentDrain = previousDownlink?.停止并刷新?.() || Promise.resolve() }
	catch (error) { currentDrain = Promise.reject(error) }
	const downlinkDrain = Promise.all([previousDrain, currentDrain]);
	// Installation awaits this promise; attach a handler immediately in case draining fails before dialing completes.
	downlinkDrain.catch(() => { });
	remoteConnWrapper.downlinkDrain = downlinkDrain;
	try { previousSocket?.close?.() } catch (e) { }
	return { generation, downlinkDrain };
}

async function 读取叉HTTP首包(reader, token) {
	const decoder = 魏烈思文本解码器;

	const 尝试解析魏烈思首包 = (data) => {
		const length = data.byteLength;
		if (length < 18) return { 状态: 'need_more' };
		if (!UUID字节匹配(data, 1, token)) return { 状态: 'invalid' };

		const optLen = data[17];
		const cmdIndex = 18 + optLen;
		if (length < cmdIndex + 1) return { 状态: 'need_more' };

		const cmd = data[cmdIndex];
		if (cmd !== 1 && cmd !== 2) return { 状态: 'invalid' };

		const portIndex = cmdIndex + 1;
		if (length < portIndex + 3) return { 状态: 'need_more' };

		const port = (data[portIndex] << 8) | data[portIndex + 1];
		const addressType = data[portIndex + 2];
		const addressIndex = portIndex + 3;
		let headerLen = -1;
		let hostname = '';

		if (addressType === 1) {
			if (length < addressIndex + 4) return { 状态: 'need_more' };
			hostname = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			headerLen = addressIndex + 4;
		} else if (addressType === 2) {
			if (length < addressIndex + 1) return { 状态: 'need_more' };
			const domainLen = data[addressIndex];
			if (length < addressIndex + 1 + domainLen) return { 状态: 'need_more' };
			hostname = decoder.decode(data.subarray(addressIndex + 1, addressIndex + 1 + domainLen));
			headerLen = addressIndex + 1 + domainLen;
		} else if (addressType === 3) {
			if (length < addressIndex + 16) return { 状态: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addressIndex + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			headerLen = addressIndex + 16;
		} else return { 状态: 'invalid' };

		if (!hostname) return { 状态: 'invalid' };

		return {
			状态: 'ok',
			结果: {
				协议: 'vl' + 'ess',
				hostname,
				port,
				isUDP: cmd === 2,
				rawData: data.subarray(headerLen),
				respHeader: new Uint8Array([data[0], 0]),
				原始数据: null,
			}
		};
	};

	const 尝试解析木马首包 = (data) => {
		const 密码哈希 = sha224(token);
		const 密码哈希字节 = new TextEncoder().encode(密码哈希);
		const length = data.byteLength;
		if (length < 58) return { 状态: 'need_more' };
		if (data[56] !== 0x0d || data[57] !== 0x0a) return { 状态: 'invalid' };
		for (let i = 0; i < 56; i++) {
			if (data[i] !== 密码哈希字节[i]) return { 状态: 'invalid' };
		}

		const socksStart = 58;
		if (length < socksStart + 2) return { 状态: 'need_more' };
		const cmd = data[socksStart];
		if (cmd !== 1 && cmd !== 3) return { 状态: 'invalid' };
		const isUDP = cmd === 3;

		const atype = data[socksStart + 1];
		let cursor = socksStart + 2;
		let hostname = '';

		if (atype === 1) {
			if (length < cursor + 4) return { 状态: 'need_more' };
			hostname = `${data[cursor]}.${data[cursor + 1]}.${data[cursor + 2]}.${data[cursor + 3]}`;
			cursor += 4;
		} else if (atype === 3) {
			if (length < cursor + 1) return { 状态: 'need_more' };
			const domainLen = data[cursor];
			if (length < cursor + 1 + domainLen) return { 状态: 'need_more' };
			hostname = decoder.decode(data.subarray(cursor + 1, cursor + 1 + domainLen));
			cursor += 1 + domainLen;
		} else if (atype === 4) {
			if (length < cursor + 16) return { 状态: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = cursor + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			cursor += 16;
		} else return { 状态: 'invalid' };

		if (!hostname) return { 状态: 'invalid' };
		if (length < cursor + 4) return { 状态: 'need_more' };

		const port = (data[cursor] << 8) | data[cursor + 1];
		if (data[cursor + 2] !== 0x0d || data[cursor + 3] !== 0x0a) return { 状态: 'invalid' };
		const dataOffset = cursor + 4;

		return {
			状态: 'ok',
			结果: {
				协议: 'trojan',
				hostname,
				port,
				isUDP,
				rawData: data.subarray(dataOffset),
				原始数据: data,
				respHeader: null,
			}
		};
	};

	let buffer = new Uint8Array(1024);
	let offset = 0;

	while (true) {
		const { value, done } = await reader.read();
		if (done) {
			if (offset === 0) return null;
			break;
		}

		const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
		if (offset + chunk.byteLength > buffer.byteLength) {
			const newBuffer = new Uint8Array(Math.max(buffer.byteLength * 2, offset + chunk.byteLength));
			newBuffer.set(buffer.subarray(0, offset));
			buffer = newBuffer;
		}

		buffer.set(chunk, offset);
		offset += chunk.byteLength;

		const 当前数据 = buffer.subarray(0, offset);
		const 木马结果 = 尝试解析木马首包(当前数据);
		if (木马结果.状态 === 'ok') return { ...木马结果.结果, reader };

		const 魏烈思结果 = 尝试解析魏烈思首包(当前数据);
		if (魏烈思结果.状态 === 'ok') return { ...魏烈思结果.结果, reader };

		if (木马结果.状态 === 'invalid' && 魏烈思结果.状态 === 'invalid') return null;
	}

	const 最终数据 = buffer.subarray(0, offset);
	const 最终木马结果 = 尝试解析木马首包(最终数据);
	if (最终木马结果.状态 === 'ok') return { ...最终木马结果.结果, reader };
	const 最终魏烈思结果 = 尝试解析魏烈思首包(最终数据);
	if (最终魏烈思结果.状态 === 'ok') return { ...最终魏烈思结果.结果, reader };
	return null;
}
///////////////////////////////////////////////////////////////////////gRPC传输数据///////////////////////////////////////////////
async function 处理gRPC请求(request, yourUUID, 反代上下文 = {}) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const 失效远端连接 = () => 失效TCP连接世代(remoteConnWrapper);
	let isDnsQuery = false;
	const 木马UDP上下文 = { 缓存: new Uint8Array(0), 反代地址: 反代上下文.木马反代地址 };
	let 判断是否是木马 = null;
	let 当前写入Socket = null;
	let 远端写入器 = null;
	let GRPC上行写入队列 = null;
	//log('[gRPC] پردازش جریان دوطرفه آغاز شد');
	const grpcHeaders = new Headers({
		'Content-Type': 'application/grpc',
		'grpc-status': '0',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	const 下行缓存上限 = 下行Grain包字节;
	const 下行刷新间隔 = 1;

	return new Response(new ReadableStream({
		async start(controller) {
			let 已关闭 = false;
			let 发送队列 = [];
			let 队列字节数 = 0;
			let 刷新定时器 = null;
			let 刷新Microtask已排队 = false;
			const grpcBridge = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (已关闭) return;
					const chunk = data instanceof Uint8Array ? data : new Uint8Array(data);
					const lenBytes数组 = [];
					let remaining = chunk.byteLength >>> 0;
					while (remaining > 127) {
						lenBytes数组.push((remaining & 0x7f) | 0x80);
						remaining >>>= 7;
					}
					lenBytes数组.push(remaining);
					const lenBytes = new Uint8Array(lenBytes数组);
					const protobufLen = 1 + lenBytes.length + chunk.byteLength;
					const frame = new Uint8Array(5 + protobufLen);
					frame[0] = 0;
					frame[1] = (protobufLen >>> 24) & 0xff;
					frame[2] = (protobufLen >>> 16) & 0xff;
					frame[3] = (protobufLen >>> 8) & 0xff;
					frame[4] = protobufLen & 0xff;
					frame[5] = 0x0a;
					frame.set(lenBytes, 6);
					frame.set(chunk, 6 + lenBytes.length);
					发送队列.push(frame);
					队列字节数 += frame.byteLength;
					安排刷新发送队列();
				},
				close() {
					if (this.readyState === WebSocket.CLOSED) return;
					刷新发送队列(true);
					已关闭 = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close() } catch (e) { }
				}
			};

			const 刷新发送队列 = (force = false) => {
				刷新Microtask已排队 = false;
				if (刷新定时器) {
					clearTimeout(刷新定时器);
					刷新定时器 = null;
				}
				if ((!force && 已关闭) || 队列字节数 === 0) return;
				const out = new Uint8Array(队列字节数);
				let offset = 0;
				for (const item of 发送队列) {
					out.set(item, offset);
					offset += item.byteLength;
				}
				发送队列 = [];
				队列字节数 = 0;
				try {
					controller.enqueue(out);
				} catch (e) {
					已关闭 = true;
					grpcBridge.readyState = WebSocket.CLOSED;
				}
			};

			const 安排刷新发送队列 = () => {
				if (队列字节数 >= 下行缓存上限) {
					刷新发送队列();
					return;
				}
				if (刷新Microtask已排队 || 刷新定时器) return;
				刷新Microtask已排队 = true;
				queueMicrotask(() => {
					刷新Microtask已排队 = false;
					if (已关闭 || 队列字节数 === 0 || 刷新定时器) return;
					刷新定时器 = setTimeout(刷新发送队列, 下行刷新间隔);
				});
			};

			const 关闭连接 = () => {
				if (已关闭) return;
				GRPC上行写入队列?.清空();
				失效远端连接();
				刷新发送队列(true);
				已关闭 = true;
				grpcBridge.readyState = WebSocket.CLOSED;
				if (刷新定时器) clearTimeout(刷新定时器);
				if (远端写入器) {
					try { 远端写入器.releaseLock() } catch (e) { }
					远端写入器 = null;
				}
				当前写入Socket = null;
				try { reader.releaseLock() } catch (e) { }
				try { 木马UDP上下文.反代Socket?.close() } catch (e) { }
				try { controller.close() } catch (e) { }
			};

			const 释放远端写入器 = () => {
				if (远端写入器) {
					try { 远端写入器.releaseLock() } catch (e) { }
					远端写入器 = null;
				}
				当前写入Socket = null;
			};

			const 上行写入队列 = GRPC上行写入队列 = 创建上行写入队列({
				获取写入器: () => {
					const socket = remoteConnWrapper.socket;
					if (!socket) return null;
					if (socket !== 当前写入Socket) {
						释放远端写入器();
						当前写入Socket = socket;
						远端写入器 = socket.writable.getWriter();
					}
					return 远端写入器;
				},
				获取连接任务: () => remoteConnWrapper.connectingPromise,
				释放写入器: 释放远端写入器,
				重试连接: async () => {
					if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
					await remoteConnWrapper.retryConnect();
				},
				关闭连接,
				名称: 'ارسال gRPC'
			});

			const 写入远端 = async (payload, allowRetry = true) => {
				return 上行写入队列.写入并等待(payload, allowRetry);
			};

			let 转发失败 = false;
			try {
				let pending = new Uint8Array(0);
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					const 当前块 = value instanceof Uint8Array ? value : new Uint8Array(value);
					const merged = new Uint8Array(pending.length + 当前块.length);
					merged.set(pending, 0);
					merged.set(当前块, pending.length);
					pending = merged;
					while (pending.byteLength >= 5) {
						const grpcLen = ((pending[1] << 24) >>> 0) | (pending[2] << 16) | (pending[3] << 8) | pending[4];
						const frameSize = 5 + grpcLen;
						if (pending.byteLength < frameSize) break;
						const grpcPayload = pending.subarray(5, frameSize);
						pending = pending.slice(frameSize);
						if (!grpcPayload.byteLength) continue;
						let payload = grpcPayload;
						if (payload.byteLength >= 2 && payload[0] === 0x0a) {
							let shift = 0;
							let offset = 1;
							let varint有效 = false;
							while (offset < payload.length) {
								const current = payload[offset++];
								if ((current & 0x80) === 0) {
									varint有效 = true;
									break;
								}
								shift += 7;
								if (shift > 35) break;
							}
							if (varint有效) payload = payload.subarray(offset);
						}
						if (!payload.byteLength) continue;
						if (isDnsQuery) {
							if (判断是否是木马) await 转发木马UDP数据(payload, grpcBridge, 木马UDP上下文, request);
							else await forwardataudp(payload, grpcBridge, null, request);
							continue;
						}
						if (remoteConnWrapper.socket || remoteConnWrapper.connectingPromise) {
							if (!(await 写入远端(payload))) throw new Error('Remote socket is not ready');
						} else {
							const 首包bytes = 数据转Uint8Array(payload);
							if (判断是否是木马 === null) 判断是否是木马 = 首包bytes.byteLength >= 58 && 首包bytes[56] === 0x0d && 首包bytes[57] === 0x0a;
							if (判断是否是木马) {
								const 解析结果 = 解析木马请求(首包bytes, yourUUID);
								if (解析结果?.hasError) throw new Error(解析结果.message || 'Invalid trojan request');
								const { port, hostname, rawClientData, isUDP } = 解析结果;
								log(`[gRPC] بستهٔ نخست (T): ${hostname}:${port} | UDP: ${isUDP ? 'بله' : 'خیر'}`);
								if (isSpeedTestSite(hostname) && 反代上下文.代理类型 === null) {
									grpcBridge.send(构造本地204响应());
									return;
								}
								if (isUDP) {
									isDnsQuery = true;
									木马UDP上下文.目标主机 = hostname;
									木马UDP上下文.目标端口 = port;
									if (木马UDP上下文.反代地址) await 转发木马UDP数据(首包bytes, grpcBridge, 木马UDP上下文, request);
									else if (有效数据长度(rawClientData) > 0) await 转发木马UDP数据(rawClientData, grpcBridge, 木马UDP上下文, request);
								} else {
									await forwardataTCP(hostname, port, rawClientData, grpcBridge, null, remoteConnWrapper, yourUUID, request, 反代上下文, true, 首包bytes);
								}
							} else {
								判断是否是木马 = false;
								const 解析结果 = 解析魏烈思请求(首包bytes, yourUUID);
								if (解析结果?.hasError) throw new Error(解析结果.message || 'درخواست نامعتبر');
								const { port, hostname, version, isUDP, rawClientData } = 解析结果;
								log(`[gRPC] بستهٔ نخست (V): ${hostname}:${port} | UDP: ${isUDP ? 'بله' : 'خیر'}`);
								const respHeader = new Uint8Array([version, 0]);
								if (isSpeedTestSite(hostname) && 反代上下文.代理类型 === null) {
									grpcBridge.send(构造本地204响应(respHeader));
									return;
								}
								if (isUDP) {
									if (port !== 53) throw new Error('UDP is not supported');
									isDnsQuery = true;
								}
								grpcBridge.send(respHeader);
								const rawData = rawClientData;
								if (isDnsQuery) {
									if (判断是否是木马) await 转发木马UDP数据(rawData, grpcBridge, 木马UDP上下文, request);
									else await forwardataudp(rawData, grpcBridge, null, request);
								}
								else await forwardataTCP(hostname, port, rawData, grpcBridge, null, remoteConnWrapper, yourUUID, request, 反代上下文);
							}
						}
					}
					刷新发送队列();
				}
				await 上行写入队列.等待空();
			} catch (err) {
				转发失败 = true;
				log(`[انتقال gRPC] پردازش ناموفق بود: ${err?.message || err}`);
			} finally {
				const 保持木马UDP反代下行 = !转发失败 && isDnsQuery && 判断是否是木马 && 木马UDP上下文.反代地址 && 木马UDP上下文.反代Socket;
				if (保持木马UDP反代下行) {
					上行写入队列.清空();
					失效远端连接();
					释放远端写入器();
					try { reader.releaseLock() } catch (e) { }
				} else {
					关闭连接();
				}
			}
		},
		cancel() {
			GRPC上行写入队列?.清空();
			失效远端连接();
			try { 木马UDP上下文.反代Socket?.close() } catch (e) { }
			try { reader.releaseLock() } catch (e) { }
		}
	}), { status: 200, headers: grpcHeaders });
}

function 是有效WS早期数据(bytes, token) {
	if (!bytes?.byteLength) return false;
	if (bytes.byteLength >= 18 && UUID字节匹配(bytes, 1, token)) return true;
	if (bytes.byteLength < 58 || bytes[56] !== 0x0d || bytes[57] !== 0x0a) return false;

	const trojanPassword = sha224(token);
	for (let i = 0; i < 56; i++) {
		if (bytes[i] !== trojanPassword.charCodeAt(i)) return false;
	}
	return true;
}

function 解码WS早期数据(header, token) {
	if (!header) return null;
	if (header.length > WS早期数据最大头长度) throw new Error('early data is too large');

	let bytes;
	const Uint8ArrayBase64 = /** @type {any} */ (Uint8Array);
	if (typeof Uint8ArrayBase64.fromBase64 === 'function') {
		try {
			bytes = Uint8ArrayBase64.fromBase64(header, { alphabet: 'base64url' });
		} catch (_) { }
	}
	if (!bytes) {
		let normalized = header.replace(/-/g, '+').replace(/_/g, '/');
		const padding = normalized.length % 4;
		if (padding) normalized += '='.repeat(4 - padding);
		let binaryString;
		try {
			binaryString = atob(normalized);
		} catch (_) {
			return null;
		}
		bytes = new Uint8Array(binaryString.length);
		for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
	}

	if (bytes.byteLength > WS早期数据最大字节) throw new Error('early data is too large');
	return 是有效WS早期数据(bytes, token) ? bytes : null;
}

///////////////////////////////////////////////////////////////////////WS传输数据///////////////////////////////////////////////
async function 处理WS请求(request, yourUUID, url, 反代上下文 = {}) {
	const WS套接字对 = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(WS套接字对);
	try { (/** @type {any} */ (serverSock)).accept({ allowHalfOpen: true }) }
	catch (_) { serverSock.accept() }
	serverSock.binaryType = 'arraybuffer';
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const 失效远端连接 = () => 失效TCP连接世代(remoteConnWrapper);
	let isDnsQuery = false;
	let 判断是否是木马 = null;
	const 木马UDP上下文 = { 缓存: new Uint8Array(0), 反代地址: 反代上下文.木马反代地址 };
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	const SS模式禁用EarlyData = !!url.searchParams.get('enc');
	let WS上行写入队列 = null;
	let WS显式传输链 = Promise.resolve();
	let WS显式传输停止接收 = false, WS显式传输失败 = false, WS显式传输收尾已入队 = false;
	let WS显式队列字节 = 0, WS显式队列条目 = 0;
	let 判断协议类型 = null, 当前写入Socket = null, 远端写入器 = null;
	let ss上下文 = null, ss初始化任务 = null;
	let WS本地测速模式 = false, WS本地测速回包Socket = null;
	let WS本地测速请求缓存 = new Uint8Array(0);
	let WS本地测速首包响应头 = null;
	const WS本地测速请求上限 = 64 * 1024;

	const 发送WS本地测速响应 = async () => {
		if (!WS本地测速回包Socket) return;
		const respHeader = WS本地测速首包响应头;
		WS本地测速首包响应头 = null;
		await WebSocket发送并等待(WS本地测速回包Socket, 构造WS本地204响应(respHeader));
	};

	const 查找HTTP请求头结尾 = (data) => {
		for (let i = 0; i <= data.byteLength - 4; i++) {
			if (data[i] === 0x0d && data[i + 1] === 0x0a && data[i + 2] === 0x0d && data[i + 3] === 0x0a) return i + 4;
		}
		return -1;
	};

	const 处理WS本地测速数据 = async (data) => {
		const chunk = 数据转Uint8Array(data);
		if (!chunk.byteLength) return;
		if (WS本地测速请求缓存.byteLength + chunk.byteLength > WS本地测速请求上限) throw new Error('WS local speed-test request is too large');
		WS本地测速请求缓存 = 拼接字节数据(WS本地测速请求缓存, chunk);

		while (WS本地测速请求缓存.byteLength) {
			const headerEnd = 查找HTTP请求头结尾(WS本地测速请求缓存);
			if (headerEnd === -1) return;
			const headerText = 魏烈思文本解码器.decode(WS本地测速请求缓存.subarray(0, headerEnd));
			const contentLengthMatch = headerText.match(/(?:^|\r\n)content-length\s*:\s*(\d+)/i);
			const contentLength = contentLengthMatch ? Number(contentLengthMatch[1]) : 0;
			const requestLength = headerEnd + contentLength;
			if (!Number.isSafeInteger(contentLength) || requestLength > WS本地测速请求上限) throw new Error('WS local speed-test request body is too large');
			if (WS本地测速请求缓存.byteLength < requestLength) return;
			WS本地测速请求缓存 = WS本地测速请求缓存.slice(requestLength);
			await 发送WS本地测速响应();
		}
	};

	const 启用WS本地测速模式 = async (回包Socket, respHeader = null, 首请求数据 = null) => {
		WS本地测速模式 = true;
		WS本地测速回包Socket = 回包Socket;
		WS本地测速请求缓存 = new Uint8Array(0);
		WS本地测速首包响应头 = respHeader;
		if (有效数据长度(首请求数据) > 0) await 处理WS本地测速数据(首请求数据);
	};

	const 释放远端写入器 = () => {
		if (远端写入器) {
			try { 远端写入器.releaseLock() } catch (e) { }
			远端写入器 = null;
		}
		当前写入Socket = null;
	};

	const 上行写入队列 = WS上行写入队列 = 创建上行写入队列({
		获取写入器: () => {
			const socket = remoteConnWrapper.socket;
			if (!socket) return null;
			if (socket !== 当前写入Socket) {
				释放远端写入器();
				当前写入Socket = socket;
				远端写入器 = socket.writable.getWriter();
			}
			return 远端写入器;
		},
		获取连接任务: () => remoteConnWrapper.connectingPromise,
		释放写入器: 释放远端写入器,
		重试连接: async () => {
			if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
			await remoteConnWrapper.retryConnect();
		},
		关闭连接: err => 处理WS显式传输错误(err),
		名称: 'ارسال WS'
	});

	const 写入远端 = async (chunk, allowRetry = true) => {
		return 上行写入队列.写入(chunk, allowRetry);
	};

	const 获取SS上下文 = async () => {
		if (ss上下文) return ss上下文;
		if (!ss初始化任务) {
			ss初始化任务 = (async () => {
				const 请求加密方式 = (url.searchParams.get('enc') || '').toLowerCase();
				const 首选加密配置 = SS支持加密配置[请求加密方式] || SS支持加密配置['aes-128-gcm'];
				const 入站候选加密配置 = [首选加密配置, ...Object.values(SS支持加密配置).filter(c => c.method !== 首选加密配置.method)];
				const 入站主密钥任务缓存 = new Map();
				const 取入站主密钥任务 = (config) => {
					if (!入站主密钥任务缓存.has(config.method)) 入站主密钥任务缓存.set(config.method, SS派生主密钥(yourUUID, config.keyLen));
					return 入站主密钥任务缓存.get(config.method);
				};
				const 入站状态 = {
					buffer: new Uint8Array(0),
					hasSalt: false,
					waitPayloadLength: null,
					decryptKey: null,
					nonceCounter: new Uint8Array(SSNonce长度),
					加密配置: null,
				};
				const 初始化入站解密状态 = async () => {
					const lengthCipherTotalLength = 2 + SSAEAD标签长度;
					const 最大盐长度 = Math.max(...入站候选加密配置.map(c => c.saltLen));
					const 最大对齐扫描字节 = 16;
					const 可扫描最大偏移 = Math.min(最大对齐扫描字节, Math.max(0, 入站状态.buffer.byteLength - (lengthCipherTotalLength + Math.min(...入站候选加密配置.map(c => c.saltLen)))));
					for (let offset = 0; offset <= 可扫描最大偏移; offset++) {
						for (const 加密配置 of 入站候选加密配置) {
							const 初始化最小长度 = offset + 加密配置.saltLen + lengthCipherTotalLength;
							if (入站状态.buffer.byteLength < 初始化最小长度) continue;
							const salt = 入站状态.buffer.subarray(offset, offset + 加密配置.saltLen);
							const lengthCipher = 入站状态.buffer.subarray(offset + 加密配置.saltLen, 初始化最小长度);
							const masterKey = await 取入站主密钥任务(加密配置);
							const decryptKey = await SS派生会话密钥(加密配置, masterKey, salt, ['decrypt']);
							const nonceCounter = new Uint8Array(SSNonce长度);
							try {
								const lengthPlain = await SSAEAD解密(decryptKey, nonceCounter, lengthCipher);
								if (lengthPlain.byteLength !== 2) continue;
								const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
								if (payloadLength < 0 || payloadLength > 加密配置.maxChunk) continue;
								if (offset > 0) log(`[ورودی SS] ${offset}B دادهٔ اضافی در ابتدا شناسایی و هم‌تراز شد`);
								if (加密配置.method !== 首选加密配置.method) log(`[ورودی SS] URL enc=${请求加密方式 || 首选加密配置.method} با روش واقعی ${加密配置.method} یکسان نیست؛ به‌طور خودکار جایگزین شد`);
								入站状态.buffer = 入站状态.buffer.subarray(初始化最小长度);
								入站状态.decryptKey = decryptKey;
								入站状态.nonceCounter = nonceCounter;
								入站状态.waitPayloadLength = payloadLength;
								入站状态.加密配置 = 加密配置;
								入站状态.hasSalt = true;
								return true;
							} catch (_) { }
						}
					}
					const 初始化失败判定长度 = 最大盐长度 + lengthCipherTotalLength + 最大对齐扫描字节;
					if (入站状态.buffer.byteLength >= 初始化失败判定长度) {
						throw new Error(`SS handshake decrypt failed (enc=${请求加密方式 || 'auto'}, candidates=${入站候选加密配置.map(c => c.method).join('/')})`);
					}
					return false;
				};
				const 入站解密器 = {
					async 输入(dataChunk) {
						const chunk = 数据转Uint8Array(dataChunk);
						if (chunk.byteLength > 0) 入站状态.buffer = 拼接字节数据(入站状态.buffer, chunk);
						if (!入站状态.hasSalt) {
							const 初始化成功 = await 初始化入站解密状态();
							if (!初始化成功) return [];
						}
						const plaintextChunks = [];
						while (true) {
							if (入站状态.waitPayloadLength === null) {
								const lengthCipherTotalLength = 2 + SSAEAD标签长度;
								if (入站状态.buffer.byteLength < lengthCipherTotalLength) break;
								const lengthCipher = 入站状态.buffer.subarray(0, lengthCipherTotalLength);
								入站状态.buffer = 入站状态.buffer.subarray(lengthCipherTotalLength);
								const lengthPlain = await SSAEAD解密(入站状态.decryptKey, 入站状态.nonceCounter, lengthCipher);
								if (lengthPlain.byteLength !== 2) throw new Error('SS length decrypt failed');
								const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
								if (payloadLength < 0 || payloadLength > 入站状态.加密配置.maxChunk) throw new Error(`SS payload length invalid: ${payloadLength}`);
								入站状态.waitPayloadLength = payloadLength;
							}
							const payloadCipherTotalLength = 入站状态.waitPayloadLength + SSAEAD标签长度;
							if (入站状态.buffer.byteLength < payloadCipherTotalLength) break;
							const payloadCipher = 入站状态.buffer.subarray(0, payloadCipherTotalLength);
							入站状态.buffer = 入站状态.buffer.subarray(payloadCipherTotalLength);
							const payloadPlain = await SSAEAD解密(入站状态.decryptKey, 入站状态.nonceCounter, payloadCipher);
							plaintextChunks.push(payloadPlain);
							入站状态.waitPayloadLength = null;
						}
						return plaintextChunks;
					},
				};
				let 出站加密器 = null;
				const SS单批最大字节 = 32 * 1024;
				const 获取出站加密器 = async () => {
					if (出站加密器) return 出站加密器;
					if (!入站状态.加密配置) throw new Error('SS cipher is not negotiated');
					const 出站加密配置 = 入站状态.加密配置;
					const 出站主密钥 = await SS派生主密钥(yourUUID, 出站加密配置.keyLen);
					const 出站随机字节 = crypto.getRandomValues(new Uint8Array(出站加密配置.saltLen));
					const 出站加密密钥 = await SS派生会话密钥(出站加密配置, 出站主密钥, 出站随机字节, ['encrypt']);
					const 出站Nonce计数器 = new Uint8Array(SSNonce长度);
					let 随机字节已发送 = false;
					出站加密器 = {
						async 加密并发送(dataChunk, sendChunk) {
							const plaintextData = 数据转Uint8Array(dataChunk);
							if (!随机字节已发送) {
								await sendChunk(出站随机字节);
								随机字节已发送 = true;
							}
							if (plaintextData.byteLength === 0) return;
							let offset = 0;
							while (offset < plaintextData.byteLength) {
								const end = Math.min(offset + 出站加密配置.maxChunk, plaintextData.byteLength);
								const payloadPlain = plaintextData.subarray(offset, end);
								const lengthPlain = new Uint8Array(2);
								lengthPlain[0] = (payloadPlain.byteLength >>> 8) & 0xff;
								lengthPlain[1] = payloadPlain.byteLength & 0xff;
								const lengthCipher = await SSAEAD加密(出站加密密钥, 出站Nonce计数器, lengthPlain);
								const payloadCipher = await SSAEAD加密(出站加密密钥, 出站Nonce计数器, payloadPlain);
								const frame = new Uint8Array(lengthCipher.byteLength + payloadCipher.byteLength);
								frame.set(lengthCipher, 0);
								frame.set(payloadCipher, lengthCipher.byteLength);
								await sendChunk(frame);
								offset = end;
							}
						},
					};
					return 出站加密器;
				};
				let SS发送队列 = Promise.resolve();
				const SS入队发送 = (chunk) => {
					SS发送队列 = SS发送队列.then(async () => {
						if (serverSock.readyState !== WebSocket.OPEN) return;
						const 已初始化出站加密器 = await 获取出站加密器();
						await 已初始化出站加密器.加密并发送(chunk, async (encryptedChunk) => {
							if (encryptedChunk.byteLength > 0 && serverSock.readyState === WebSocket.OPEN) {
								await WebSocket发送并等待(serverSock, encryptedChunk.buffer);
							}
						});
					}).catch((error) => {
						log(`[ارسال SS] رمزنگاری ناموفق بود: ${error?.message || error}`);
						closeSocketQuietly(serverSock);
					});
					return SS发送队列;
				};
				const 回包Socket = {
					get readyState() {
						return serverSock.readyState;
					},
					send(data) {
						const chunk = 数据转Uint8Array(data);
						if (chunk.byteLength <= SS单批最大字节) {
							return SS入队发送(chunk);
						}
						for (let i = 0; i < chunk.byteLength; i += SS单批最大字节) {
							SS入队发送(chunk.subarray(i, Math.min(i + SS单批最大字节, chunk.byteLength)));
						}
						return SS发送队列;
					},
					close() {
						closeSocketQuietly(serverSock);
					}
				};
				ss上下文 = {
					入站解密器,
					回包Socket,
					首包已建立: false,
					目标主机: '',
					目标端口: 0,
				};
				return ss上下文;
			})().finally(() => { ss初始化任务 = null });
		}
		return ss初始化任务;
	};

	const 处理SS数据 = async (chunk) => {
		const 上下文 = await 获取SS上下文();
		let 明文块数组 = null;
		try {
			明文块数组 = await 上下文.入站解密器.输入(chunk);
		} catch (err) {
			const msg = err?.message || `${err}`;
			if (msg.includes('Decryption failed') || msg.includes('SS handshake decrypt failed') || msg.includes('SS length decrypt failed')) {
				log(`[ورودی SS] رمزگشایی ناموفق بود و اتصال بسته شد: ${msg}`);
				closeSocketQuietly(serverSock);
				return;
			}
			throw err;
		}
		for (const 明文块 of 明文块数组) {
			if (WS本地测速模式) {
				await 处理WS本地测速数据(明文块);
				continue;
			}
			let 已写入 = false;
			try {
				已写入 = await 写入远端(明文块, false);
			} catch (err) {
				if ((/** @type {any} */ (err))?.isQueueOverflow) throw err;
				已写入 = false;
			}
			if (已写入) continue;
			if (上下文.首包已建立 && 上下文.目标主机 && 上下文.目标端口 > 0) {
				await forwardataTCP(上下文.目标主机, 上下文.目标端口, 明文块, 上下文.回包Socket, null, remoteConnWrapper, yourUUID, request, 反代上下文);
				continue;
			}
			const 明文数据 = 数据转Uint8Array(明文块);
			if (明文数据.byteLength < 3) throw new Error('invalid ss data');
			const addressType = 明文数据[0];
			let cursor = 1;
			let hostname = '';
			if (addressType === 1) {
				if (明文数据.byteLength < cursor + 4 + 2) throw new Error('invalid ss ipv4 length');
				hostname = `${明文数据[cursor]}.${明文数据[cursor + 1]}.${明文数据[cursor + 2]}.${明文数据[cursor + 3]}`;
				cursor += 4;
			} else if (addressType === 3) {
				if (明文数据.byteLength < cursor + 1) throw new Error('invalid ss domain length');
				const domainLength = 明文数据[cursor];
				cursor += 1;
				if (明文数据.byteLength < cursor + domainLength + 2) throw new Error('invalid ss domain data');
				hostname = SS文本解码器.decode(明文数据.subarray(cursor, cursor + domainLength));
				cursor += domainLength;
			} else if (addressType === 4) {
				if (明文数据.byteLength < cursor + 16 + 2) throw new Error('invalid ss ipv6 length');
				const ipv6 = [];
				const ipv6View = new DataView(明文数据.buffer, 明文数据.byteOffset + cursor, 16);
				for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
				hostname = ipv6.join(':');
				cursor += 16;
			} else {
				throw new Error(`invalid ss addressType: ${addressType}`);
			}
			if (!hostname) throw new Error(`invalid ss address: ${addressType}`);
			const port = (明文数据[cursor] << 8) | 明文数据[cursor + 1];
			cursor += 2;
			const rawClientData = 明文数据.subarray(cursor);
			if (isSpeedTestSite(hostname) && 反代上下文.代理类型 === null) {
				await 启用WS本地测速模式(上下文.回包Socket, null, rawClientData);
				return;
			}
			上下文.首包已建立 = true;
			上下文.目标主机 = hostname;
			上下文.目标端口 = port;
			await forwardataTCP(hostname, port, rawClientData, 上下文.回包Socket, null, remoteConnWrapper, yourUUID, request, 反代上下文);
		}
	};

	const 处理WS入站数据 = async (chunk) => {
		let 当前块字节 = null;
		if (isDnsQuery) {
			if (判断是否是木马) return await 转发木马UDP数据(chunk, serverSock, 木马UDP上下文, request);
			return await forwardataudp(chunk, serverSock, null, request);
		}
		if (判断协议类型 === 'ss') {
			await 处理SS数据(chunk);
			return;
		}
		if (WS本地测速模式) {
			await 处理WS本地测速数据(chunk);
			return;
		}
		if (await 写入远端(chunk)) return;

		if (判断协议类型 === null) {
			if (url.searchParams.get('enc')) 判断协议类型 = 'ss';
			else {
				当前块字节 = 当前块字节 || 数据转Uint8Array(chunk);
				const bytes = 当前块字节;
				判断协议类型 = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a ? '木马' : '魏烈思';
			}
			判断是否是木马 = 判断协议类型 === '木马';
			log(`[انتقال WS] پروتکل: ${判断协议类型 === '木马' ? 'T' : 判断协议类型 === 'ss' ? 'SS' : 'V'} | از: ${url.host} | UA: ${request.headers.get('user-agent') || 'نامشخص'}`);
		}

		if (判断协议类型 === 'ss') {
			await 处理SS数据(chunk);
			return;
		}
		if (await 写入远端(chunk)) return;
		if (判断协议类型 === '木马') {
			const 解析结果 = 解析木马请求(chunk, yourUUID);
			if (解析结果?.hasError) throw new Error(解析结果.message || 'Invalid trojan request');
			const { port, hostname, rawClientData, isUDP } = 解析结果;
			if (isSpeedTestSite(hostname) && 反代上下文.代理类型 === null) {
				await 启用WS本地测速模式(serverSock, null, rawClientData);
				return;
			}
			if (isUDP) {
				isDnsQuery = true;
				木马UDP上下文.目标主机 = hostname;
				木马UDP上下文.目标端口 = port;
				if (木马UDP上下文.反代地址) return 转发木马UDP数据(当前块字节 || 数据转Uint8Array(chunk), serverSock, 木马UDP上下文, request);
				if (有效数据长度(rawClientData) > 0) return 转发木马UDP数据(rawClientData, serverSock, 木马UDP上下文, request);
				return;
			}
			await forwardataTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper, yourUUID, request, 反代上下文, true, 当前块字节 || 数据转Uint8Array(chunk));
		} else {
			判断是否是木马 = false;
			当前块字节 = 当前块字节 || 数据转Uint8Array(chunk);
			const bytes = 当前块字节;
			const 解析结果 = 解析魏烈思请求(bytes, yourUUID);
			if (解析结果?.hasError) throw new Error(解析结果.message || 'درخواست نامعتبر');
			const { port, hostname, version, isUDP, rawClientData } = 解析结果;
			const respHeader = new Uint8Array([version, 0]);
			if (isSpeedTestSite(hostname) && 反代上下文.代理类型 === null) {
				await 启用WS本地测速模式(serverSock, respHeader, rawClientData);
				return;
			}
			if (isUDP) {
				if (port === 53) isDnsQuery = true;
				else throw new Error('UDP is not supported');
			}
			const rawData = rawClientData;
			if (isDnsQuery) {
				if (判断是否是木马) return 转发木马UDP数据(rawData, serverSock, 木马UDP上下文, request);
				return forwardataudp(rawData, serverSock, respHeader, request);
			}
			await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, yourUUID, request, 反代上下文);
		}
	};

	const 处理WS显式传输错误 = (err) => {
		if (WS显式传输失败) return;
		WS显式传输失败 = true;
		WS显式传输停止接收 = true;
		WS显式队列字节 = 0;
		WS显式队列条目 = 0;
		const msg = err?.message || `${err}`;
		if (msg.includes('Network connection lost') || msg.includes('ReadableStream is closed')) {
			log(`[انتقال WS] اتصال پایان یافت: ${msg}`);
		} else {
			log(`[انتقال WS] پردازش ناموفق بود: ${msg}`);
		}
		上行写入队列.清空();
		释放远端写入器();
		失效远端连接();
		try { 木马UDP上下文.反代Socket?.close() } catch (e) { }
		closeSocketQuietly(serverSock);
	};

	const 追加WS显式传输任务 = (任务) => {
		WS显式传输链 = WS显式传输链.then(任务).catch(处理WS显式传输错误);
		return WS显式传输链;
	};

	const 入队WS显式传输 = (data) => {
		if (WS显式传输停止接收 || WS显式传输失败) return;
		const chunkSize = Math.max(0, 有效数据长度(data));
		const nextBytes = WS显式队列字节 + chunkSize;
		const nextItems = WS显式队列条目 + 1;
		if (nextBytes > 上行队列最大字节 || nextItems > 上行队列最大条目) {
			处理WS显式传输错误(new Error(`[انتقال صریح WS] صف سرریز شد: ${nextBytes}B/${nextItems}`));
			return;
		}
		WS显式队列字节 = nextBytes;
		WS显式队列条目 = nextItems;
		追加WS显式传输任务(async () => {
			WS显式队列字节 = Math.max(0, WS显式队列字节 - chunkSize);
			WS显式队列条目 = Math.max(0, WS显式队列条目 - 1);
			if (WS显式传输失败) return;
			await 处理WS入站数据(data);
		});
	};

	const 收尾WS显式传输 = () => {
		if (WS显式传输收尾已入队) return;
		WS显式传输收尾已入队 = true;
		WS显式传输停止接收 = true;
		追加WS显式传输任务(async () => {
			if (WS显式传输失败) return;
			await 上行写入队列.等待空();
			释放远端写入器();
			失效远端连接();
			try { 木马UDP上下文.反代Socket?.close() } catch (e) { }
		});
	};

	serverSock.addEventListener('message', (event) => {
		入队WS显式传输(event.data);
	});
	serverSock.addEventListener('close', () => {
		closeSocketQuietly(serverSock);
		收尾WS显式传输();
	});
	serverSock.addEventListener('error', (err) => {
		处理WS显式传输错误(err);
	});

	// SS 模式下禁用 sec-websocket-protocol early-data，避免把子协议值（如 "binary"）误当作 base64 数据注入首包导致 AEAD 解密失败。
	if (!SS模式禁用EarlyData && earlyDataHeader) {
		try {
			const bytes = 解码WS早期数据(earlyDataHeader, yourUUID);
			if (bytes?.byteLength) 入队WS显式传输(bytes.buffer);
		} catch (error) {
			处理WS显式传输错误(error);
		}
	}

	return new Response(null, { status: 101, webSocket: clientSock, headers: { 'Sec-WebSocket-Extensions': '' } });
}

const 木马文本解码器 = new TextDecoder();

function 解析木马反代地址(address) {
	const raw = String(address || '').trim();
	if (!raw || raw.includes('/') || raw.includes('@') || raw.includes('://')) throw new Error('نشانی fallback فقط به شکل host:port پذیرفته می‌شود');
	let hostname = '', portText = '';
	if (raw.startsWith('[')) {
		const 匹配 = raw.match(/^(\[[^\]]+\]):(\d+)$/);
		if (!匹配) throw new Error('نشانی IPv6 برای fallback نامعتبر است');
		hostname = 匹配[1];
		portText = 匹配[2];
	} else {
		const parts = raw.split(':');
		if (parts.length !== 2) throw new Error('نشانی fallback فقط به شکل host:port پذیرفته می‌شود');
		hostname = parts[0];
		portText = parts[1];
	}
	const port = Number(portText);
	if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('درگاه fallback نامعتبر است');
	return { hostname, port };
}

async function 连接木马反代(首包数据, TCP连接, 木马反代目标) {
	if (!木马反代目标) throw new Error('trojan fallback is not configured');
	const socket = TCP连接({ hostname: stripIPv6Brackets(木马反代目标.hostname), port: 木马反代目标.port });
	let writer = null;
	try {
		if (socket.opened) await socket.opened;
		if (有效数据长度(首包数据) > 0) {
			writer = socket.writable.getWriter();
			await writer.write(数据转Uint8Array(首包数据));
		}
		return socket;
	} catch (error) {
		try { socket?.close?.() } catch (e) { }
		throw error;
	} finally {
		try { writer?.releaseLock() } catch (e) { }
	}
}

function 提取木马反代握手数据(首包数据, rawData) {
	const 首包 = 数据转Uint8Array(首包数据);
	const payload = 数据转Uint8Array(rawData);
	if (!payload.byteLength) return 首包;
	const 握手长度 = 首包.byteLength - payload.byteLength;
	if (握手长度 <= 0) return 首包;
	for (let i = 0; i < payload.byteLength; i++) {
		if (首包[握手长度 + i] !== payload[i]) return 首包;
	}
	return 首包.subarray(0, 握手长度);
}

async function 转发木马UDP反代数据(chunk, webSocket, 上下文, request) {
	const data = 数据转Uint8Array(chunk);
	if (!上下文.反代Socket) {
		const TCP连接 = 创建请求TCP连接器(request);
		const socket = await 连接木马反代(data, TCP连接, 上下文.反代地址);
		上下文.反代Socket = socket;
		socket.closed.catch(() => { }).finally(() => closeSocketQuietly(webSocket));
		connectStreams(socket, webSocket, null, null);
		return;
	}
	if (!data.byteLength) return;
	const writer = 上下文.反代Socket.writable.getWriter();
	try { await writer.write(data) }
	finally { try { writer.releaseLock() } catch (e) { } }
}

function 解析木马请求(buffer, passwordPlainText) {
	const data = 数据转Uint8Array(buffer);
	const sha224Password = sha224(passwordPlainText);
	if (data.byteLength < 58) return { hasError: true, message: "invalid data" };
	let crLfIndex = 56;
	if (data[crLfIndex] !== 0x0d || data[crLfIndex + 1] !== 0x0a) return { hasError: true, message: "invalid header format" };
	for (let i = 0; i < crLfIndex; i++) {
		if (data[i] !== sha224Password.charCodeAt(i)) return { hasError: true, message: "invalid password" };
	}

	const socks5Index = crLfIndex + 2;
	if (data.byteLength < socks5Index + 6) return { hasError: true, message: "invalid S5 request data" };

	const cmd = data[socks5Index];
	if (cmd !== 1 && cmd !== 3) return { hasError: true, message: "unsupported command, only TCP/UDP is allowed" };
	const isUDP = cmd === 3;

	const atype = data[socks5Index + 1];
	let addressLength = 0;
	let addressIndex = socks5Index + 2;
	let address = "";
	switch (atype) {
		case 1: // IPv4
			addressLength = 4;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			address = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			break;
		case 3: // Domain
			if (data.byteLength < addressIndex + 1) return { hasError: true, message: "invalid S5 request data" };
			addressLength = data[addressIndex];
			addressIndex += 1;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			address = 木马文本解码器.decode(data.subarray(addressIndex, addressIndex + addressLength));
			break;
		case 4: // IPv6
			addressLength = 16;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const partIndex = addressIndex + i * 2;
				ipv6.push(((data[partIndex] << 8) | data[partIndex + 1]).toString(16));
			}
			address = ipv6.join(":");
			break;
		default:
			return { hasError: true, message: `invalid addressType is ${atype}` };
	}

	if (!address) {
		return { hasError: true, message: `address is empty, addressType is ${atype}` };
	}

	const portIndex = addressIndex + addressLength;
	if (data.byteLength < portIndex + 4) return { hasError: true, message: "invalid S5 request data" };
	const portRemote = (data[portIndex] << 8) | data[portIndex + 1];

	return {
		hasError: false,
		addressType: atype,
		port: portRemote,
		hostname: address,
		isUDP,
		rawClientData: data.subarray(portIndex + 4)
	};
}

const UUID字节缓存 = new Map();
const 魏烈思文本解码器 = new TextDecoder();

function 读取十六进制半字节(code) {
	if (code >= 48 && code <= 57) return code - 48;
	code |= 32;
	if (code >= 97 && code <= 102) return code - 87;
	return -1;
}

function 获取UUID字节(uuid) {
	const key = String(uuid || '');
	let cached = UUID字节缓存.get(key);
	if (cached) return cached;

	const clean = key.replace(/-/g, '');
	if (clean.length !== 32) return null;

	const bytes = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		const high = 读取十六进制半字节(clean.charCodeAt(i * 2));
		const low = 读取十六进制半字节(clean.charCodeAt(i * 2 + 1));
		if (high < 0 || low < 0) return null;
		bytes[i] = (high << 4) | low;
	}

	if (UUID字节缓存.size >= 32) UUID字节缓存.clear();
	UUID字节缓存.set(key, bytes);
	return bytes;
}

function UUID字节匹配(data, offset, uuid) {
	const expected = 获取UUID字节(uuid);
	if (!expected || data.byteLength < offset + 16) return false;
	for (let i = 0; i < 16; i++) {
		if (data[offset + i] !== expected[i]) return false;
	}
	return true;
}

function 解析魏烈思请求(chunk, token) {
	const data = 数据转Uint8Array(chunk);
	const length = data.byteLength;
	if (length < 24) return { hasError: true, message: 'Invalid data' };
	const version = data[0];
	if (!UUID字节匹配(data, 1, token)) return { hasError: true, message: 'Invalid uuid' };

	const optLen = data[17];
	const cmdIndex = 18 + optLen;
	if (length < cmdIndex + 4) return { hasError: true, message: 'Invalid data' };

	const cmd = data[cmdIndex];
	let isUDP = false;
	if (cmd === 1) { } else if (cmd === 2) { isUDP = true } else { return { hasError: true, message: 'Invalid command' } }

	const portIdx = cmdIndex + 1;
	const port = (data[portIdx] << 8) | data[portIdx + 1];
	let addrValIdx = portIdx + 3, addrLen = 0, hostname = '';
	const addressType = data[portIdx + 2];
	switch (addressType) {
		case 1:
			addrLen = 4;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv4 address length' };
			hostname = `${data[addrValIdx]}.${data[addrValIdx + 1]}.${data[addrValIdx + 2]}.${data[addrValIdx + 3]}`;
			break;
		case 2:
			if (length < addrValIdx + 1) return { hasError: true, message: 'Invalid domain length' };
			addrLen = data[addrValIdx];
			addrValIdx += 1;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid domain data' };
			hostname = 魏烈思文本解码器.decode(data.subarray(addrValIdx, addrValIdx + addrLen));
			break;
		case 3:
			addrLen = 16;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv6 address length' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addrValIdx + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			break;
		default:
			return { hasError: true, message: `Invalid address type: ${addressType}` };
	}
	if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
	const rawIndex = addrValIdx + addrLen;
	return { hasError: false, addressType, port, hostname, isUDP, rawClientData: data.subarray(rawIndex), version };
}

const SS支持加密配置 = {
	'aes-128-gcm': { method: 'aes-128-gcm', keyLen: 16, saltLen: 16, maxChunk: 0x3fff, aesLength: 128 },
	'aes-256-gcm': { method: 'aes-256-gcm', keyLen: 32, saltLen: 32, maxChunk: 0x3fff, aesLength: 256 },
};

const SSAEAD标签长度 = 16, SSNonce长度 = 12;
const SS子密钥信息 = new TextEncoder().encode('ss-subkey');
const SS文本编码器 = new TextEncoder(), SS文本解码器 = new TextDecoder(), SS主密钥缓存 = new Map();

function 数据转Uint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}

function 拼接字节数据(...chunkList) {
	if (!chunkList || chunkList.length === 0) return new Uint8Array(0);
	const chunks = chunkList.map(数据转Uint8Array);
	const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) { result.set(c, offset); offset += c.byteLength }
	return result;
}

async function 转发木马UDP数据(chunk, webSocket, 上下文, request) {
	const 当前块 = 数据转Uint8Array(chunk);
	if (上下文?.反代地址) return 转发木马UDP反代数据(当前块, webSocket, 上下文, request);
	const 缓存块 = 上下文?.缓存 instanceof Uint8Array ? 上下文.缓存 : new Uint8Array(0);
	const input = 缓存块.byteLength ? 拼接字节数据(缓存块, 当前块) : 当前块;
	let cursor = 0;

	while (cursor < input.byteLength) {
		const packetStart = cursor;
		const atype = input[cursor];
		let addrCursor = cursor + 1;
		let addrLen = 0;
		if (atype === 1) addrLen = 4;
		else if (atype === 4) addrLen = 16;
		else if (atype === 3) {
			if (input.byteLength < addrCursor + 1) break;
			addrLen = 1 + input[addrCursor];
		} else throw new Error(`invalid trojan udp addressType: ${atype}`);

		const portCursor = addrCursor + addrLen;
		if (input.byteLength < portCursor + 6) break;

		const port = (input[portCursor] << 8) | input[portCursor + 1];
		const payloadLength = (input[portCursor + 2] << 8) | input[portCursor + 3];
		if (input[portCursor + 4] !== 0x0d || input[portCursor + 5] !== 0x0a) throw new Error('invalid trojan udp delimiter');

		const payloadStart = portCursor + 6;
		const payloadEnd = payloadStart + payloadLength;
		if (input.byteLength < payloadEnd) break;

		const 地址端口头 = input.slice(packetStart, portCursor + 2);
		const payload = input.slice(payloadStart, payloadEnd);
		cursor = payloadEnd;

		if (port !== 53) throw new Error('UDP is not supported');
		if (!payload.byteLength) continue;

		let tcpDNS查询 = payload;
		if (payload.byteLength < 2 || ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2) {
			tcpDNS查询 = new Uint8Array(payload.byteLength + 2);
			tcpDNS查询[0] = (payload.byteLength >>> 8) & 0xff;
			tcpDNS查询[1] = payload.byteLength & 0xff;
			tcpDNS查询.set(payload, 2);
		}

		const dns响应上下文 = { 缓存: new Uint8Array(0) };
		await forwardataudp(tcpDNS查询, webSocket, null, request, (dnsRespChunk) => {
			const 当前响应块 = 数据转Uint8Array(dnsRespChunk);
			const 响应输入 = dns响应上下文.缓存.byteLength ? 拼接字节数据(dns响应上下文.缓存, 当前响应块) : 当前响应块;
			const 响应帧列表 = [];
			let responseCursor = 0;
			while (responseCursor + 2 <= 响应输入.byteLength) {
				const dnsLen = (响应输入[responseCursor] << 8) | 响应输入[responseCursor + 1];
				const dnsStart = responseCursor + 2;
				const dnsEnd = dnsStart + dnsLen;
				if (dnsEnd > 响应输入.byteLength) break;
				const dnsPayload = 响应输入.slice(dnsStart, dnsEnd);
				const frame = new Uint8Array(地址端口头.byteLength + 4 + dnsPayload.byteLength);
				frame.set(地址端口头, 0);
				frame[地址端口头.byteLength] = (dnsPayload.byteLength >>> 8) & 0xff;
				frame[地址端口头.byteLength + 1] = dnsPayload.byteLength & 0xff;
				frame[地址端口头.byteLength + 2] = 0x0d;
				frame[地址端口头.byteLength + 3] = 0x0a;
				frame.set(dnsPayload, 地址端口头.byteLength + 4);
				响应帧列表.push(frame);
				responseCursor = dnsEnd;
			}
			dns响应上下文.缓存 = 响应输入.slice(responseCursor);
			return 响应帧列表.length ? 响应帧列表 : new Uint8Array(0);
		});
	}

	if (上下文) 上下文.缓存 = input.slice(cursor);
}

function SS递增Nonce计数器(counter) {
	for (let i = 0; i < counter.length; i++) { counter[i] = (counter[i] + 1) & 0xff; if (counter[i] !== 0) return }
}

async function SS派生主密钥(passwordText, keyLen) {
	const cacheKey = `${keyLen}:${passwordText}`;
	if (SS主密钥缓存.has(cacheKey)) return SS主密钥缓存.get(cacheKey);
	const deriveTask = (async () => {
		const pwBytes = SS文本编码器.encode(passwordText || '');
		let prev = new Uint8Array(0), result = new Uint8Array(0);
		while (result.byteLength < keyLen) {
			const input = new Uint8Array(prev.byteLength + pwBytes.byteLength);
			input.set(prev, 0); input.set(pwBytes, prev.byteLength);
			prev = new Uint8Array(await crypto.subtle.digest('MD5', input));
			result = 拼接字节数据(result, prev);
		}
		return result.slice(0, keyLen);
	})();
	SS主密钥缓存.set(cacheKey, deriveTask);
	try { return await deriveTask }
	catch (error) { SS主密钥缓存.delete(cacheKey); throw error }
}

async function SS派生会话密钥(config, masterKey, salt, usages) {
	const hmacOpts = { name: 'HMAC', hash: 'SHA-1' };
	const saltHmacKey = await crypto.subtle.importKey('raw', salt, hmacOpts, false, ['sign']);
	const prk = new Uint8Array(await crypto.subtle.sign('HMAC', saltHmacKey, masterKey));
	const prkHmacKey = await crypto.subtle.importKey('raw', prk, hmacOpts, false, ['sign']);
	const subKey = new Uint8Array(config.keyLen);
	let prev = new Uint8Array(0), written = 0, counter = 1;
	while (written < config.keyLen) {
		const input = 拼接字节数据(prev, SS子密钥信息, new Uint8Array([counter]));
		prev = new Uint8Array(await crypto.subtle.sign('HMAC', prkHmacKey, input));
		const copyLen = Math.min(prev.byteLength, config.keyLen - written);
		subKey.set(prev.subarray(0, copyLen), written);
		written += copyLen; counter += 1;
	}
	return crypto.subtle.importKey('raw', subKey, { name: 'AES-GCM', length: config.aesLength }, false, usages);
}

async function SSAEAD加密(cryptoKey, nonceCounter, plaintext) {
	const iv = nonceCounter.slice();
	const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, plaintext);
	SS递增Nonce计数器(nonceCounter);
	return new Uint8Array(ct);
}

async function SSAEAD解密(cryptoKey, nonceCounter, ciphertext) {
	const iv = nonceCounter.slice();
	const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, ciphertext);
	SS递增Nonce计数器(nonceCounter);
	return new Uint8Array(pt);
}

async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID, request = null, 反代上下文 = {}, 允许木马反代 = false, 木马反代首包数据 = null, 仅建立连接 = false) {
	const ctx反代IP = 反代上下文.反代IP || '';
	const ctx代理类型 = 反代上下文.代理类型 !== undefined ? 反代上下文.代理类型 : null;
	const ctx代理全局 = 反代上下文.代理全局 !== undefined ? 反代上下文.代理全局 : false;
	const ctx代理参数 = 反代上下文.代理参数 || {};
	const ctx反代兜底 = 反代上下文.反代兜底 !== undefined ? 反代上下文.反代兜底 : true;
	let 反代数组索引 = 0;
	log(`[انتقال TCP] مقصد: ${host}:${portNum} | آی‌پی پراکسی: ${ctx反代IP} | پشتیبان: ${ctx反代兜底 ? 'بله' : 'خیر'} | نوع: ${ctx代理类型 || 'proxyip'} | سراسری: ${ctx代理全局 ? 'بله' : 'خیر'}`);
	const 连接超时毫秒 = 1000;
	let 已通过代理发送首包 = false;
	const TCP连接 = 创建请求TCP连接器(request);
	const 使用木马反代 = 允许木马反代 && (反代上下文.木马反代地址 || null);
	const 木马反代目标 = 使用木马反代 ? 反代上下文.木马反代地址 : null;
	const 木马反代握手数据 = 使用木马反代 ? 提取木马反代握手数据(木马反代首包数据, rawData) : null;
	let 待发送响应头 = respHeader;
	const 取出响应头 = () => {
		const header = 待发送响应头;
		待发送响应头 = null;
		return header;
	};
	if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;

	const 安装当前连接 = async (socket, generation, downlinkDrain, retryFunc = null) => {
		try { await downlinkDrain } catch (e) {
			if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
			try { socket?.close?.() } catch (_) { }
			if (remoteConnWrapper.generation === generation) closeSocketQuietly(ws);
			throw e;
		}
		if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
		const 连接仍有效 = () => remoteConnWrapper.generation === generation && remoteConnWrapper.socket === socket;
		if (remoteConnWrapper.generation !== generation || ws.readyState !== WebSocket.OPEN) {
			try { socket?.close?.() } catch (e) { }
			if (remoteConnWrapper.generation === generation) remoteConnWrapper.socket = null;
			throw new Error('connection superseded or client closed');
		}
		remoteConnWrapper.socket = socket;
		if (仅建立连接) return socket;
		connectStreams(socket, ws, 取出响应头, retryFunc, 连接仍有效, remoteConnWrapper).catch(err => {
			if (!连接仍有效()) return;
			log(`[دریافت TCP] پردازش ناموفق بود: ${err?.message || err}`);
			try { socket?.close?.() } catch (e) { }
			closeSocketQuietly(ws);
		});
		return true;
	};

	async function 等待连接建立(remoteSock, timeoutMs = 连接超时毫秒) {
		await Promise.race([
			remoteSock.opened,
			new Promise((_, reject) => setTimeout(() => reject(new Error('مهلت اتصال به پایان رسید')), timeoutMs))
		]);
	}

	async function 打开TCP连接(address, port) {
		const remoteSock = TCP连接({ hostname: address, port });
		try {
			await 等待连接建立(remoteSock);
			return remoteSock;
		} catch (err) {
			try { remoteSock?.close?.() } catch (e) { }
			throw err;
		}
	}

	async function 写入首包(remoteSock, data) {
		if (有效数据长度(data) <= 0) return;
		const writer = remoteSock.writable.getWriter();
		try { await writer.write(数据转Uint8Array(data)) }
		finally { try { writer.releaseLock() } catch (e) { } }
	}

	async function 并发打开候选连接(候选列表) {
		if (候选列表.length === 1) {
			const 候选 = 候选列表[0];
			return { socket: await 打开TCP连接(候选.hostname, 候选.port), candidate: 候选 };
		}
		const attempts = 候选列表.map(候选 => 打开TCP连接(候选.hostname, 候选.port).then(socket => ({ socket, candidate: 候选 })));
		let winner = null;
		try {
			winner = await Promise.any(attempts);
			return winner;
		} finally {
			if (winner) {
				for (const attempt of attempts) {
					attempt.then(({ socket }) => {
						if (socket !== winner.socket) {
							try { socket?.close?.() } catch (e) { }
						}
					}).catch(() => { });
				}
			}
		}
	}

	async function 构建预加载竞速候选列表(address, port) {
		if (!预加载竞速拨号 || isIPHostname(address)) return null;
		log(`[اتصال مستقیم TCP] شماره‌گیری رقابتی فعال است؛ پرس‌وجوی هم‌زمان رکوردهای A/AAAA برای ${address}`);
		const [aRecords, aaaaRecords] = await Promise.all([
			DoH查询(address, 'A'),
			DoH查询(address, 'AAAA')
		]);
		const ipv4List = [...new Set(aRecords.flatMap(r => {
			const data = r.data;
			return r.type === 1 && typeof data === 'string' && isIPv4(data) ? [data] : [];
		}))];
		const ipv6List = [...new Set(aaaaRecords.flatMap(r => {
			const data = r.data;
			return r.type === 28 && typeof data === 'string' && isIPHostname(data) ? [data] : [];
		}))];
		const 拨号上限 = Math.max(1, TCP并发拨号数 | 0);
		const ipList = ipv4List.length >= 拨号上限
			? ipv4List.slice(0, 拨号上限)
			: ipv4List.concat(ipv6List.slice(0, 拨号上限 - ipv4List.length));
		const 使用记录类型 = ipv4List.length > 0
			? (ipList.length > ipv4List.length ? 'A+AAAA' : 'A')
			: 'AAAA';
		if (ipList.length === 0) {
			log(`[اتصال مستقیم TCP] برای ${address} رکورد A/AAAA قابل‌استفاده‌ای پیدا نشد؛ اتصال مستقیم با نام میزبان اصلی انجام می‌شود.`);
			return null;
		}
		const 选中IP列表 = ipList;
		log(`[اتصال مستقیم TCP] ${address} رکورد A: ${ipv4List.length} · رکورد AAAA: ${ipv6List.length} · نوع انتخابی: ${使用记录类型} · شماره‌گیری رقابتی ${选中IP列表.length}/${拨号上限}: ${选中IP列表.join(', ')}`);
		return 选中IP列表.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
	}

	async function connectDirect(address, port, data = null, 启用预加载 = false) {
		const 预加载候选列表 = 启用预加载 ? await 构建预加载竞速候选列表(address, port) : null;
		const 候选列表 = 预加载候选列表 || Array.from({ length: TCP并发拨号数 }, (_, attempt) => ({ hostname: address, port, attempt }));
		log(预加载候选列表
			? `[اتصال مستقیم TCP] تلاش هم‌زمان ${候选列表.length} مسیر: ${候选列表.map(候选 => `${候选.hostname}:${候选.port}`).join(', ')}`
			: `[اتصال مستقیم TCP] تلاش هم‌زمان ${候选列表.length} مسیر: ${address}:${port}`);
		let socket = null;
		try {
			const 连接结果 = await 并发打开候选连接(候选列表);
			socket = 连接结果.socket;
			if (预加载候选列表) {
				const winner = 连接结果.candidate;
				log(`[اتصال مستقیم TCP] برندهٔ رقابت: ${winner.hostname}:${winner.port} · دامنهٔ مبدأ: ${winner.resolvedFrom || address}`);
			}
			await 写入首包(socket, data);
			return socket;
		} catch (err) {
			try { socket?.close?.() } catch (e) { }
			if (预加载候选列表) log(`[اتصال مستقیم TCP] شماره‌گیری رقابتی ناموفق بود: ${err.message || err}`);
			throw err;
		}
	}

	async function connectProxyIP(address, port, data = null, 所有反代数组 = null, 启用反代失败兜底 = true) {
		if (所有反代数组 && 所有反代数组.length > 0) {
			const 实际并发数 = Math.max(1, Math.floor(Number(反代并发拨号数) || 1));
			for (let i = 0; i < 所有反代数组.length; i += 实际并发数) {
				const 候选列表 = [];
				for (let j = 0; j < 实际并发数 && i + j < 所有反代数组.length; j++) {
					const 索引 = (反代数组索引 + i + j) % 所有反代数组.length;
					const [反代地址, 反代端口] = 所有反代数组[索引];
					候选列表.push({ hostname: 反代地址, port: 反代端口, index: 索引 });
				}
				let socket = null, candidate = null;
				try {
					log(`[اتصال پراکسی] تلاش هم‌زمان ${候选列表.length} مسیر: ${候选列表.map(候选 => `${候选.hostname}:${候选.port}`).join(', ')}`);
					const 连接结果 = await 并发打开候选连接(候选列表);
					socket = 连接结果.socket;
					candidate = 连接结果.candidate;
					await 写入首包(socket, data);
					log(`[اتصال پراکسی] اتصال برقرار شد: ${candidate.hostname}:${candidate.port} (شماره: ${candidate.index})`);
					反代数组索引 = candidate.index;
					return socket;
				} catch (err) {
					try { socket?.close?.() } catch (e) { }
					log(`[اتصال پراکسی] این دسته از اتصال‌ها ناموفق بود: ${err.message || err}`);
				}
			}
		}

		if (启用反代失败兜底) return connectDirect(address, port, data, false);
		else {
			throw new Error('[اتصال پراکسی] همهٔ تلاش‌ها ناموفق بود و مسیر پشتیبان فعال نیست؛ اتصال خاتمه یافت.');
		}
	}

	async function connecttoPry(允许发送首包 = true) {
		if (remoteConnWrapper.connectingPromise) {
			await remoteConnWrapper.connectingPromise;
			return;
		}
		const { generation: 当前连接世代, downlinkDrain } = 开始TCP连接世代(remoteConnWrapper);

		let 本次发送首包 = false, 本次首包数据 = null;
		if (使用木马反代) {
			if (允许发送首包 && !已通过代理发送首包 && 有效数据长度(木马反代首包数据) > 0) {
				本次首包数据 = 木马反代首包数据;
				本次发送首包 = 有效数据长度(rawData) > 0;
			} else {
				本次首包数据 = 木马反代握手数据;
			}
		} else {
			本次发送首包 = 允许发送首包 && !已通过代理发送首包 && 有效数据长度(rawData) > 0;
			本次首包数据 = 本次发送首包 ? rawData : null;
		}

		const 当前连接任务 = (async () => {
			let newSocket = null;
			try {
				if (使用木马反代) {
					log(`[fallback] انتقال به: ${host}:${portNum}`);
					newSocket = await 连接木马反代(本次首包数据, TCP连接, 木马反代目标);
				} else if (ctx代理类型 === 'socks5') {
					log(`[پراکسی SOCKS5] انتقال به: ${host}:${portNum}`);
					newSocket = await socks5Connect(host, portNum, 本次首包数据, TCP连接, ctx代理参数);
				} else if (ctx代理类型 === 'http') {
					log(`[پراکسی HTTP] انتقال به: ${host}:${portNum}`);
					newSocket = await httpConnect(host, portNum, 本次首包数据, false, TCP连接, ctx代理参数);
				} else if (ctx代理类型 === 'https') {
					log(`[پراکسی HTTPS] انتقال به: ${host}:${portNum}`);
					newSocket = isIPHostname(ctx代理参数.hostname)
						? await httpsConnect(host, portNum, 本次首包数据, TCP连接, ctx代理参数)
						: await httpConnect(host, portNum, 本次首包数据, true, TCP连接, ctx代理参数);
				} else if (ctx代理类型 === 'turn') {
					log(`[پراکسی TURN] انتقال به: ${host}:${portNum}`);
					newSocket = await turnConnect(ctx代理参数, host, portNum, TCP连接);
					if (有效数据长度(本次首包数据) > 0) {
						const writer = newSocket.writable.getWriter();
						try { await writer.write(数据转Uint8Array(本次首包数据)) }
						finally { try { writer.releaseLock() } catch (e) { } }
					}
				} else if (ctx代理类型 === 'sstp') {
					log(`[پراکسی SSTP] انتقال به: ${host}:${portNum}`);
					newSocket = await sstpConnect(ctx代理参数, host, portNum, TCP连接);
					if (有效数据长度(本次首包数据) > 0) {
						const writer = newSocket.writable.getWriter();
						try { await writer.write(数据转Uint8Array(本次首包数据)) }
						finally { try { writer.releaseLock() } catch (e) { } }
					}
				} else {
					log(`[اتصال پراکسی] انتقال به: ${host}:${portNum}`);
					const 所有反代数组 = await 解析地址端口(ctx反代IP, host, yourUUID);
					newSocket = await connectProxyIP(`${特征码字典[0]}.tp1.${特征码字典[2]}.xyz`, 1, 本次首包数据, 所有反代数组, ctx反代兜底);
				}
				await 安装当前连接(newSocket, 当前连接世代, downlinkDrain);
				if (本次发送首包) 已通过代理发送首包 = true;
			} catch (err) {
				try { newSocket?.close?.() } catch (e) { }
				if (remoteConnWrapper.generation === 当前连接世代) {
					remoteConnWrapper.socket = null;
					closeSocketQuietly(ws);
					throw err;
				}
			}
		})();

		remoteConnWrapper.connectingPromise = 当前连接任务;
		try {
			await 当前连接任务;
		} finally {
			if (remoteConnWrapper.connectingPromise === 当前连接任务) {
				remoteConnWrapper.connectingPromise = null;
			}
		}
	}
	remoteConnWrapper.retryConnect = async () => connecttoPry(!已通过代理发送首包);

	if (ctx代理类型 && (ctx代理全局 || SOCKS5白名单.some(p => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(host)))) {
		log(`[انتقال TCP] پراکسی سراسری SOCKS5/HTTP/HTTPS/TURN/SSTP فعال است`);
		try {
			await connecttoPry();
			if (仅建立连接) return remoteConnWrapper.socket;
		} catch (err) {
			log(`[انتقال TCP] اتصال پراکسی SOCKS5/HTTP/HTTPS/TURN/SSTP ناموفق بود: ${err.message}`);
			throw err;
		}
	} else {
		let 直连世代 = remoteConnWrapper.generation;
		try {
			log(`[انتقال TCP] تلاش برای اتصال مستقیم به: ${host}:${portNum}`);
			const 世代连接 = 开始TCP连接世代(remoteConnWrapper);
			直连世代 = 世代连接.generation;
			const initialSocket = await connectDirect(host, portNum, rawData, true);
			await 安装当前连接(initialSocket, 直连世代, 世代连接.downlinkDrain, async () => {
				if (remoteConnWrapper.generation !== 直连世代 || remoteConnWrapper.socket !== initialSocket) return;
				await connecttoPry();
			});
			if (仅建立连接) return initialSocket;
		} catch (err) {
			log(`[انتقال TCP] اتصال مستقیم به ${host}:${portNum} ناموفق بود: ${err.message}`);
			if (remoteConnWrapper.generation !== 直连世代) throw err;
			if (err instanceof Error && err.name === '预加载解析为空') {
				closeSocketQuietly(ws);
				throw err;
			}
			if (ws.readyState !== WebSocket.OPEN) throw err;
			await connecttoPry();
			if (仅建立连接) return remoteConnWrapper.socket;
		}
	}
}

async function forwardataudp(udpChunk, webSocket, respHeader, request, 响应封装器 = null) {
	const 请求数据 = 数据转Uint8Array(udpChunk);
	const 请求字节数 = 请求数据.byteLength;
	log(`[انتقال UDP] درخواست DNS دریافت شد: ${请求字节数}B -> 8.8.4.4:53`);
	try {
		const TCP连接 = 创建请求TCP连接器(request);
		const tcpSocket = TCP连接({ hostname: '8.8.4.4', port: 53 });
		let 魏烈思Header = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(请求数据);
		log(`[انتقال UDP] درخواست DNS به سرور بالادست ارسال شد: ${请求字节数}B`);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				const 原始响应 = 数据转Uint8Array(chunk);
				log(`[انتقال UDP] پاسخ DNS دریافت شد: ${原始响应.byteLength}B`);
				const 封装结果 = 响应封装器 ? await 响应封装器(原始响应) : 原始响应;
				const 发送片段列表 = Array.isArray(封装结果) ? 封装结果 : [封装结果];
				if (!发送片段列表.length) return;
				if (webSocket.readyState !== WebSocket.OPEN) return;
				for (const fragment of 发送片段列表) {
					const 转发响应 = 数据转Uint8Array(fragment);
					if (!转发响应.byteLength) continue;
					if (魏烈思Header) {
						const response = new Uint8Array(魏烈思Header.length + 转发响应.byteLength);
						response.set(魏烈思Header, 0);
						response.set(转发响应, 魏烈思Header.length);
						await WebSocket发送并等待(webSocket, response.buffer);
						魏烈思Header = null;
					} else {
						await WebSocket发送并等待(webSocket, 转发响应);
					}
				}
			},
		}));
	} catch (error) {
		log(`[انتقال UDP] ارسال DNS ناموفق بود: ${error?.message || error}`);
	}
}

function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (error) { }
}

function formatIdentifier(arr, offset = 0) {
	const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
	return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

async function WebSocket发送并等待(webSocket, payload) {
	const sendResult = webSocket.send(payload);
	if (sendResult && typeof sendResult.then === 'function') await sendResult;
}

function 创建Grain收纳器(容量, 复制合包结果 = false) {
	let 队列 = [];
	let 头 = 0;
	let 字节数 = 0;
	let 合包缓冲 = null;

	const 为空 = () => 头 >= 队列.length;
	const 压缩 = () => {
		if (头 > 32 && 头 * 2 >= 队列.length) {
			队列 = 队列.slice(头);
			头 = 0;
		}
	};
	const 取出 = () => {
		if (为空()) return null;
		const item = 队列[头];
		队列[头++] = undefined;
		字节数 -= item.chunk.byteLength;
		压缩();
		return item;
	};

	return {
		get 字节数() { return 字节数 },
		get 条目数() { return 队列.length - 头 },
		get 为空() { return 为空() },
		清空(处理项目 = null) {
			if (处理项目) {
				for (let i = 头; i < 队列.length; i++) {
					if (队列[i]) 处理项目(队列[i]);
				}
			}
			队列 = [];
			头 = 0;
			字节数 = 0;
		},
		收纳(item) {
			if (!item?.chunk?.byteLength) return false;
			队列.push(item);
			字节数 += item.chunk.byteLength;
			return true;
		},
		合包() {
			const first = 取出();
			if (!first) return null;
			const items = [first];
			if (为空() || first.chunk.byteLength >= 容量) return { chunk: first.chunk, items };

			let totalBytes = first.chunk.byteLength;
			let end = 头;
			while (end < 队列.length) {
				const nextBytes = totalBytes + 队列[end].chunk.byteLength;
				if (nextBytes > 容量) break;
				totalBytes = nextBytes;
				end++;
			}
			if (end === 头) return { chunk: first.chunk, items };

			const output = (合包缓冲 ||= new Uint8Array(容量));
			output.set(first.chunk, 0);
			let offset = first.chunk.byteLength;
			while (头 < end) {
				const next = 队列[头];
				队列[头++] = undefined;
				字节数 -= next.chunk.byteLength;
				items.push(next);
				output.set(next.chunk, offset);
				offset += next.chunk.byteLength;
			}
			压缩();
			const bundled = output.subarray(0, totalBytes);
			return { chunk: 复制合包结果 ? bundled.slice() : bundled, items };
		}
	};
}

function 创建上行Grain合包流(目标字节 = 上行合包目标字节) {
	const identity = typeof IdentityTransformStream !== 'undefined'
		? new IdentityTransformStream()
		: new TransformStream();
	const writer = identity.writable.getWriter();
	const 缓冲 = new Uint8Array(目标字节);
	let 缓冲长度 = 0;
	let 定时器 = null;
	let 在途写 = null;
	let 冲刷链 = Promise.resolve();

	const 清理定时器 = () => {
		if (定时器) {
			clearTimeout(定时器);
			定时器 = null;
		}
	};

	const 串行写 = async (chunk) => {
		if (在途写) await 在途写;
		在途写 = writer.write(chunk);
		try { await 在途写 } finally { 在途写 = null; }
	};

	const 冲刷 = async () => {
		if (缓冲长度) {
			const chunk = 缓冲.slice(0, 缓冲长度);
			缓冲长度 = 0;
			await 串行写(chunk);
		}
	};

	const 排队冲刷 = () => {
		冲刷链 = 冲刷链.then(() => 冲刷()).catch(() => { });
	};

	const 启动定时器 = () => {
		if (定时器) return;
		定时器 = setTimeout(() => {
			定时器 = null;
			排队冲刷();
		}, 1);
	};

	return {
		readable: identity.readable,
		写入: async (chunk) => {
			const data = 数据转Uint8Array(chunk);
			if (!data.byteLength) return;
			if (data.byteLength >= 目标字节) {
				清理定时器();
				if (缓冲长度) await 冲刷();
				await 串行写(data);
				return;
			}
			if (缓冲长度 + data.byteLength >= 目标字节) {
				const output = new Uint8Array(缓冲长度 + data.byteLength);
				output.set(缓冲.subarray(0, 缓冲长度), 0);
				output.set(data, 缓冲长度);
				缓冲长度 = 0;
				清理定时器();
				await 串行写(output);
			} else {
				缓冲.set(data, 缓冲长度);
				缓冲长度 += data.byteLength;
				启动定时器();
			}
		},
		结束: async () => {
			清理定时器();
			try {
				await 冲刷链;
				await 冲刷();
				await writer.close();
			} finally {
				try { writer.releaseLock() } catch (e) { }
			}
		}
	};
}

function 创建上行写入队列({ 获取写入器, 获取连接任务 = null, 释放写入器, 重试连接, 关闭连接, 名称 = 'صف ارسال' }) {
	const grain = 创建Grain收纳器(上行合包目标字节);
	let draining = false;
	let closed = false;
	let idleResolvers = [];
	let activeCompletions = null;

	const settleCompletions = (completions, err = null) => {
		if (!completions) return;
		for (const completion of completions) {
			if (err) completion.reject(err);
			else completion.resolve();
		}
	};

	const resolveIdle = () => {
		if (grain.字节数 || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers;
		idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};

	const clear = (err = null) => {
		const closeErr = err || (closed ? new Error(`${名称}: queue closed`) : null);
		if (closeErr) {
			grain.清空(item => settleCompletions(item.completions, closeErr));
			settleCompletions(activeCompletions, closeErr);
			activeCompletions = null;
		} else grain.清空();
		resolveIdle();
	};

	const bundle = () => {
		const packed = grain.合包();
		if (!packed) return null;
		let allowRetry = true;
		let completions = null;
		for (const item of packed.items) {
			allowRetry = allowRetry && item.allowRetry;
			if (item.completions) completions = completions ? completions.concat(item.completions) : item.completions;
		}
		return { chunk: packed.chunk, allowRetry, completions };
	};

	const 等待可用写入器 = async () => {
		let writer = 获取写入器();
		if (writer) return writer;
		const connectionTask = 获取连接任务?.();
		if (connectionTask) await connectionTask;
		return 获取写入器();
	};

	const drain = async () => {
		if (draining || closed) return;
		draining = true;
		try {
			for (; ;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					let writer = await 等待可用写入器();
					if (closed) break;
					if (!writer) throw new Error(`${名称}: remote writer unavailable`);
					try {
						await writer.write(item.chunk);
					} catch (err) {
						释放写入器?.();
						if (closed) break;
						if (!item.allowRetry || typeof 重试连接 !== 'function') throw err;
						await 重试连接();
						if (closed) break;
						writer = 获取写入器();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err);
					throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			log(`[${名称}] نوشتن ناموفق بود: ${err?.message || err}`);
			try { 关闭连接?.(err) } catch (_) { }
		} finally {
			draining = false;
			if (!closed && !grain.为空) drain();
			else resolveIdle();
		}
	};

	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		// 首包解析阶段既没有 writer 也没有连接任务；返回 false 交给上层继续协议解析。
		// 已建立会话的重拨阶段则先收纳，drain 会等待新 writer，避免数据被误当成首包。
		if (!获取写入器() && !获取连接任务?.()) return false;
		const chunk = 数据转Uint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = grain.字节数 + chunk.byteLength;
		const nextItems = grain.条目数 + 1;
		if (nextBytes > 上行队列最大字节 || nextItems > 上行队列最大条目) {
			closed = true;
			const err = Object.assign(new Error(`${名称}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
			clear(err);
			log(`[${名称}] صف از حد مجاز گذشت؛ اتصال بسته شد`);
			try { 关闭连接?.(err) } catch (_) { }
			throw err;
		}
		let completionPromise = null;
		let completions = null;
		if (waitForFlush) {
			completions = [];
			completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
		}
		grain.收纳({ chunk, allowRetry, completions });
		if (!draining) drain();
		return waitForFlush ? completionPromise.then(() => true) : true;
	};

	return {
		写入(data, allowRetry = true) {
			return enqueue(data, allowRetry, false);
		},
		写入并等待(data, allowRetry = true) {
			return enqueue(data, allowRetry, true);
		},
		async 等待空() {
			if (!grain.字节数 && !draining) return;
			await new Promise(resolve => idleResolvers.push(resolve));
		},
		清空() {
			closed = true;
			clear();
		}
	};
}

function 创建下行Grain发送器(webSocket, headerData = null, isActive = null) {
	const packetCap = 下行Grain包字节;
	const tailBytes = 下行Grain尾部阈值;
	const grain = 创建Grain收纳器(packetCap, true);
	let header = typeof headerData === 'function' ? null : headerData;
	const 获取响应头 = typeof headerData === 'function' ? headerData : () => {
		const value = header;
		header = null;
		return value;
	};
	let flushTimer = null;
	let generation = 0;
	let scheduledGeneration = 0;
	let waitRounds = 0;
	let flushPromise = null;
	let directSendPromise = null;
	let 强制排空 = false;
	let 停止已开始 = false;
	let 活动发送数 = 0;
	let 活动直发数 = 0;
	let 活动发送错误 = null;
	let 活动发送等待者 = [];
	const 等待活动发送完成 = () => {
		if (!活动发送数 && !活动直发数) return Promise.resolve();
		return new Promise(resolve => 活动发送等待者.push(resolve));
	};
	const 标记发送完成 = () => {
		if (活动发送数 || 活动直发数 || !活动发送等待者.length) return;
		const resolvers = 活动发送等待者;
		活动发送等待者 = [];
		for (const resolve of resolvers) resolve();
	};
	const 检查活动发送错误 = () => {
		if (!活动发送错误) return;
		const err = 活动发送错误;
		grain.清空();
		throw err;
	};
	const 当前发送器有效 = () => 强制排空 || !isActive || isActive();
	const 关闭活动连接 = () => {
		if (当前发送器有效()) closeSocketQuietly(webSocket);
	};

	const 发送原始块 = async (chunk) => {
		if (!当前发送器有效()) return;
		if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
		chunk = 附加响应头(chunk);
		await WebSocket发送并等待(webSocket, chunk);
	};

	const 串行发送原始块 = async (chunk) => {
		while (directSendPromise) await directSendPromise;
		const sendTask = 发送原始块(chunk);
		directSendPromise = sendTask;
		try { await sendTask }
		finally {
			if (directSendPromise === sendTask) directSendPromise = null;
		}
	};

	const 附加响应头 = (chunk) => {
		const responseHeader = 获取响应头();
		if (!responseHeader) return chunk;
		const merged = new Uint8Array(responseHeader.length + chunk.byteLength);
		merged.set(responseHeader, 0);
		merged.set(chunk, responseHeader.length);
		return merged;
	};

	const flush = async () => {
		while (flushPromise) await flushPromise;
		if (flushTimer) clearTimeout(flushTimer);
		flushTimer = null;
		waitRounds = 0;
		if (!当前发送器有效()) {
			grain.清空();
			return;
		}
		const 发送任务 = (async () => {
			for (; ;) {
				if (!当前发送器有效()) {
					grain.清空();
					break;
				}
				const packed = grain.合包();
				if (!packed) break;
				await 串行发送原始块(packed.chunk);
			}
		})();
		flushPromise = 发送任务.catch(err => {
			活动发送错误 ||= err;
			throw err;
		}).finally(() => { flushPromise = null });
		return flushPromise;
	};

	const scheduleFlush = () => {
		if (!当前发送器有效()) {
			grain.清空();
			return;
		}
		if (grain.为空 || flushTimer) return;
		if (grain.字节数 >= packetCap || packetCap - grain.字节数 < tailBytes) {
			flush().catch(关闭活动连接);
			return;
		}
		flushTimer = setTimeout(() => {
			flushTimer = null;
			if (!当前发送器有效()) {
				grain.清空();
				return;
			}
			if (grain.为空) return;
			if (grain.字节数 >= packetCap || packetCap - grain.字节数 < tailBytes) {
				flush().catch(关闭活动连接);
				return;
			}
			if (waitRounds < 下行Grain最大等待轮次 && (generation !== scheduledGeneration || grain.字节数 < 下行Grain低水位字节)) {
				waitRounds++;
				scheduledGeneration = generation;
				scheduleFlush();
				return;
			}
			flush().catch(关闭活动连接);
		}, 1);
	};

	return {
		async 直接发送(data) {
			if (停止已开始 || !当前发送器有效()) return;
			活动直发数++;
			try {
				const chunk = 数据转Uint8Array(data);
				if (!chunk.byteLength) return;
				await 串行发送原始块(chunk);
			} catch (err) {
				活动发送错误 ||= err;
				throw err;
			} finally {
				活动直发数--;
				标记发送完成();
			}
		},
		async 发送(data) {
			if (停止已开始 || !当前发送器有效()) return;
			活动发送数++;
			try {
				const chunk = 数据转Uint8Array(data);
				if (!chunk.byteLength) return;
				let offset = 0;
				const totalBytes = chunk.byteLength;
				while (offset < totalBytes) {
					const remainingBytes = totalBytes - offset;
					if (grain.为空 && remainingBytes >= packetCap) {
						const sendBytes = Math.min(packetCap, remainingBytes);
						const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
						await 串行发送原始块(view);
						offset += sendBytes;
						continue;
					}
					const copyBytes = Math.min(packetCap - grain.字节数, totalBytes - offset);
					if (!copyBytes) {
						await flush();
						continue;
					}
					grain.收纳({ chunk: offset || copyBytes !== totalBytes ? chunk.subarray(offset, offset + copyBytes) : chunk });
					offset += copyBytes;
					generation++;
					if (grain.字节数 >= packetCap || packetCap - grain.字节数 < tailBytes) await flush();
					else scheduleFlush();
				}
			} catch (err) {
				活动发送错误 ||= err;
				throw err;
			} finally {
				活动发送数--;
				标记发送完成();
			}
		},
		flush,
		async 停止并刷新() {
			if (停止已开始) {
				await 等待活动发送完成();
				while (directSendPromise) await directSendPromise;
				检查活动发送错误();
				await flush();
				return;
			}
			停止已开始 = true;
			强制排空 = true;
			if (flushTimer) clearTimeout(flushTimer);
			flushTimer = null;
			await 等待活动发送完成();
			while (directSendPromise) await directSendPromise;
			检查活动发送错误();
			await flush();
		}
	};
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, isCurrentSocket = null, remoteConnWrapper = null) {
	let header = headerData, hasData = false, reader, useBYOB = false, readError = null;
	const BYOB单次读取上限 = 64 * 1024;
	const 当前连接仍有效 = () => !isCurrentSocket || isCurrentSocket();
	const 下行发送器 = 创建下行Grain发送器(webSocket, header, 当前连接仍有效);
	header = null;
	const 下行控制器 = { 停止并刷新: () => 下行发送器.停止并刷新() };
	if (remoteConnWrapper) remoteConnWrapper.downlinkController = 下行控制器;
	try { remoteSocket.closed?.catch?.(() => { }) } catch (e) { }

	try { reader = remoteSocket.readable.getReader({ mode: 'byob' }); useBYOB = true }
	catch (e) { reader = remoteSocket.readable.getReader() }

	try {
		if (!useBYOB) {
			while (true) {
				const { done, value } = await reader.read();
				if (!当前连接仍有效()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= 下行Grain包字节) {
					await 下行发送器.flush();
					await 下行发送器.直接发送(value);
				} else {
					await 下行发送器.发送(value);
				}
			}
		} else {
			let readBuffer = new ArrayBuffer(BYOB单次读取上限);
			while (true) {
				const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOB单次读取上限));
				if (!当前连接仍有效()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= 下行Grain包字节) {
					await 下行发送器.flush();
					await 下行发送器.直接发送(value);
					readBuffer = new ArrayBuffer(BYOB单次读取上限);
				} else {
					await 下行发送器.发送(value.slice());
					readBuffer = value.buffer.byteLength >= BYOB单次读取上限 ? value.buffer : new ArrayBuffer(BYOB单次读取上限);
				}
			}
		}
		if (当前连接仍有效()) await 下行发送器.flush();
	} catch (err) { readError = err }
	finally {
		if (当前连接仍有效() && webSocket.readyState === WebSocket.OPEN) {
			try { await 下行发送器.停止并刷新() } catch (err) { readError ||= err }
		}
		if (remoteConnWrapper?.downlinkController === 下行控制器) remoteConnWrapper.downlinkController = null;
		try { await reader.cancel() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { remoteSocket.close() } catch (e) { }
	}
	if (!hasData && retryFunc && webSocket.readyState === WebSocket.OPEN && 当前连接仍有效()) {
		try {
			await retryFunc();
			return;
		} catch (err) {
			readError ||= err;
		}
	}
	if (!当前连接仍有效()) return;
	if (readError) log(`[دریافت TCP] خواندن ناموفق بود: ${readError?.message || readError}`);
	closeSocketQuietly(webSocket);
}

function isSpeedTestSite(hostname) {
	const speedTestDomains = ['speed.cloudflare.com', 'cp.cloudflare.com'];
	hostname = hostname.toLowerCase();
	return speedTestDomains.some(domain => hostname === domain || hostname.endsWith('.' + domain));
}

function 构造本地204响应(respHeader = null) {
	const 本地204响应 = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
		'Content-Length: 0\r\n' +
		'Connection: close\r\n' +
		'\r\n'
	);
	if (有效数据长度(respHeader) === 0) return 本地204响应;
	const 协议响应头 = 数据转Uint8Array(respHeader);
	const response = new Uint8Array(协议响应头.byteLength + 本地204响应.byteLength);
	response.set(协议响应头, 0);
	response.set(本地204响应, 协议响应头.byteLength);
	log(`[انتقال TCP] پاسخ محلی 204 ساخته شد: ${response.byteLength}B`);
	return response;
}

function 构造WS本地204响应(respHeader = null) {
	const WS本地204响应 = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
		'Content-Length: 0\r\n' +
		'Connection: keep-alive\r\n' +
		'\r\n'
	);
	if (有效数据长度(respHeader) === 0) return WS本地204响应;
	const 协议响应头 = 数据转Uint8Array(respHeader);
	const response = new Uint8Array(协议响应头.byteLength + WS本地204响应.byteLength);
	response.set(协议响应头, 0);
	response.set(WS本地204响应, 协议响应头.byteLength);
	return response;
}

///////////////////////////////////////////////////////SOCKS5/HTTP函数///////////////////////////////////////////////
async function socks5Connect(targetHost, targetPort, initialData, TCP连接, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const socket = TCP连接({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	try {
		const authMethods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
		await writer.write(authMethods);
		let response = await reader.read();
		if (response.done || response.value.byteLength < 2) throw new Error('S5 method selection failed');

		const selectedMethod = new Uint8Array(response.value)[1];
		if (selectedMethod === 0x02) {
			if (!username || !password) throw new Error('S5 requires authentication');
			const userBytes = new TextEncoder().encode(username), passBytes = new TextEncoder().encode(password);
			const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
			await writer.write(authPacket);
			response = await reader.read();
			if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 authentication failed');
		} else if (selectedMethod !== 0x00) throw new Error(`S5 unsupported auth method: ${selectedMethod}`);

		const hostBytes = new TextEncoder().encode(targetHost);
		const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]);
		await writer.write(connectPacket);
		response = await reader.read();
		if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 connection failed');

		if (有效数据长度(initialData) > 0) await writer.write(initialData);
		writer.releaseLock(); reader.releaseLock();
		return socket;
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}

async function httpConnect(targetHost, targetPort, initialData, HTTPS代理 = false, TCP连接, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const socket = HTTPS代理
		? TCP连接({ hostname, port }, { secureTransport: 'on', allowHalfOpen: false })
		: TCP连接({ hostname, port });
	const writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	try {
		if (HTTPS代理) await socket.opened;

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await writer.write(encoder.encode(request));
		writer.releaseLock();

		let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const { done, value } = await reader.read();
			if (done || !value) throw new Error(`پراکسی ${HTTPS代理 ? 'HTTPS' : 'HTTP'} پیش از پاسخ به CONNECT اتصال را بست`);
			responseBuffer = new Uint8Array([...responseBuffer, ...value]);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('سرآیند پاسخ CONNECT پراکسی بیش از حد طولانی یا نامعتبر است');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		reader.releaseLock();

		if (有效数据长度(initialData) > 0) {
			const 远端写入器 = socket.writable.getWriter();
			await 远端写入器.write(initialData);
			远端写入器.releaseLock();
		}

		// CONNECT 响应头后可能夹带隧道数据，先回灌到可读流，避免首包被吞。
		if (bytesRead > headerEndIndex) {
			const { readable, writable } = new TransformStream();
			const transformWriter = writable.getWriter();
			await transformWriter.write(responseBuffer.subarray(headerEndIndex, bytesRead));
			transformWriter.releaseLock();
			socket.readable.pipeTo(writable).catch(() => { });
			return { readable, writable: socket.writable, closed: socket.closed, close: () => socket.close() };
		}

		return socket;
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}

async function httpsConnect(targetHost, targetPort, initialData, TCP连接, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	let tlsSocket = null;
	const tlsServerName = isIPHostname(hostname) ? '' : stripIPv6Brackets(hostname);
	const 打开HTTPS代理TLS = async (allowChacha = false) => {
		const proxySocket = TCP连接({ hostname, port });
		try {
			await proxySocket.opened;
			const socket = new TlsClient(proxySocket, { serverName: tlsServerName, insecure: true, allowChacha });
			await socket.handshake();
			log(`[پراکسی HTTPS] نسخهٔ TLS: ${socket.isTls13 ? '1.3' : '1.2'} | Cipher: 0x${socket.cipherSuite.toString(16)}${socket.cipherConfig?.chacha ? ' (ChaCha20)' : ' (AES-GCM)'}`);
			return socket;
		} catch (error) {
			try { proxySocket.close() } catch (e) { }
			throw error;
		}
	};
	try {
		try {
			tlsSocket = await 打开HTTPS代理TLS(false);
		} catch (error) {
			if (!/cipher|handshake|TLS Alert|ServerHello|Finished|Unsupported|Missing TLS/i.test(error?.message || `${error || ''}`)) throw error;
			log(`[پراکسی HTTPS] دست‌دهی TLS با AES-GCM ناموفق بود؛ بازگشت به حالت سازگار ChaCha20: ${error?.message || error}`);
			tlsSocket = await 打开HTTPS代理TLS(true);
		}

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await tlsSocket.write(encoder.encode(request));

		let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const value = await tlsSocket.read();
			if (!value) throw new Error('پراکسی HTTPS پیش از پاسخ به CONNECT اتصال را بست');
			responseBuffer = 拼接字节数据(responseBuffer, value);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('سرآیند پاسخ CONNECT پراکسی HTTPS بیش از حد طولانی یا نامعتبر است');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		if (有效数据长度(initialData) > 0) await tlsSocket.write(数据转Uint8Array(initialData));
		const bufferedData = bytesRead > headerEndIndex ? responseBuffer.subarray(headerEndIndex, bytesRead) : null;
		let closedSettled = false, resolveClosed, rejectClosed;
		const settleClosed = (settle, value) => {
			if (!closedSettled) {
				closedSettled = true;
				settle(value);
			}
		};
		const closed = new Promise((resolve, reject) => {
			resolveClosed = resolve;
			rejectClosed = reject;
		});
		const close = () => {
			try { tlsSocket.close() } catch (e) { }
			settleClosed(resolveClosed);
		};
		const readable = new ReadableStream({
			async start(controller) {
				try {
					if (有效数据长度(bufferedData) > 0) controller.enqueue(bufferedData);
					while (true) {
						const data = await tlsSocket.read();
						if (!data) break;
						if (data.byteLength > 0) controller.enqueue(data);
					}
					try { controller.close() } catch (e) { }
					settleClosed(resolveClosed);
				} catch (error) {
					try { controller.error(error) } catch (e) { }
					settleClosed(rejectClosed, error);
				}
			},
			cancel() {
				close();
			}
		});
		const writable = new WritableStream({
			async write(chunk) {
				await tlsSocket.write(数据转Uint8Array(chunk));
			},
			close,
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			}
		});
		return { readable, writable, closed, close };
	} catch (error) {
		try { tlsSocket?.close() } catch (e) { }
		throw error;
	}
}

function 创建请求TCP连接器(request) {
	const 请求对象 = /** @type {any} */ (request);
	const fetcher = 请求对象?.fetcher;
	if (!fetcher || typeof fetcher.connect !== 'function') throw new Error('request.fetcher.connect unavailable');
	return (options, init) => init === undefined ? fetcher.connect(options) : fetcher.connect(options, init);
}
////////////////////////////////////////////TLSClient by: @Alexandre_Kojeve////////////////////////////////////////////////
const TLS_VERSION_10 = 769, TLS_VERSION_12 = 771, TLS_VERSION_13 = 772;
const CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20, CONTENT_TYPE_ALERT = 21, CONTENT_TYPE_HANDSHAKE = 22, CONTENT_TYPE_APPLICATION_DATA = 23;
const HANDSHAKE_TYPE_CLIENT_HELLO = 1, HANDSHAKE_TYPE_SERVER_HELLO = 2, HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8, HANDSHAKE_TYPE_CERTIFICATE = 11, HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12, HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13, HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14, HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16, HANDSHAKE_TYPE_FINISHED = 20, HANDSHAKE_TYPE_KEY_UPDATE = 24;
const EXT_SERVER_NAME = 0, EXT_SUPPORTED_GROUPS = 10, EXT_EC_POINT_FORMATS = 11, EXT_SIGNATURE_ALGORITHMS = 13, EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16, EXT_SUPPORTED_VERSIONS = 43, EXT_PSK_KEY_EXCHANGE_MODES = 45, EXT_KEY_SHARE = 51;

const ALERT_CLOSE_NOTIFY = 0, ALERT_LEVEL_WARNING = 1, ALERT_UNRECOGNIZED_NAME = 112;
const shouldIgnoreTlsAlert = fragment => fragment?.[0] === ALERT_LEVEL_WARNING && fragment?.[1] === ALERT_UNRECOGNIZED_NAME;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const EMPTY_BYTES = new Uint8Array(0);

const CIPHER_SUITES_BY_ID = new Map([
	[4865, { id: 4865, keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: !0 }],
	[4866, { id: 4866, keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: !0 }],
	[4867, { id: 4867, keyLen: 32, ivLen: 12, hash: "SHA-256", tls13: !0, chacha: !0 }],
	[49199, { id: 49199, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49200, { id: 49200, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52392, { id: 52392, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }],
	[49195, { id: 49195, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49196, { id: 49196, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52393, { id: 52393, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }]
]);
const GROUPS_BY_ID = new Map([[29, "X25519"], [23, "P-256"]]);
const SUPPORTED_SIGNATURE_ALGORITHMS = [2052, 2053, 2054, 1025, 1281, 1537, 1027, 1283, 1539];

const tlsBytes = (...parts) => {
	const flattenBytes = values => values.flatMap(value => value instanceof Uint8Array ? [...value] : Array.isArray(value) ? flattenBytes(value) : "number" == typeof value ? [value] : []);
	return new Uint8Array(flattenBytes(parts))
};
const uint16be = value => [value >> 8 & 255, 255 & value];
const readUint16 = (buffer, offset) => buffer[offset] << 8 | buffer[offset + 1];
const readUint24 = (buffer, offset) => buffer[offset] << 16 | buffer[offset + 1] << 8 | buffer[offset + 2];
const concatBytes = (...chunks) => {
	const nonEmptyChunks = chunks.filter((chunk => chunk && chunk.length > 0)),
		length = nonEmptyChunks.reduce(((total, chunk) => total + chunk.length), 0),
		result = new Uint8Array(length);
	let offset = 0;
	for (const chunk of nonEmptyChunks) result.set(chunk, offset), offset += chunk.length;
	return result
};
const randomBytes = length => crypto.getRandomValues(new Uint8Array(length));
const constantTimeEqual = (left, right) => {
	if (!left || !right || left.length !== right.length) return !1;
	let diff = 0; for (let index = 0; index < left.length; index++) diff |= left[index] ^ right[index];
	return 0 === diff
};
const hashByteLength = hash => "SHA-512" === hash ? 64 : "SHA-384" === hash ? 48 : 32;
async function hmac(hash, key, data) {
	const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash }, !1, ["sign"]);
	return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data))
}
async function digestBytes(hash, data) { return new Uint8Array(await crypto.subtle.digest(hash, data)) }
async function tls12Prf(secret, label, seed, length, hash = "SHA-256") {
	const labelSeed = concatBytes(textEncoder.encode(label), seed);
	let output = new Uint8Array(0),
		currentA = labelSeed;
	for (; output.length < length;) {
		currentA = await hmac(hash, secret, currentA);
		const block = await hmac(hash, secret, concatBytes(currentA, labelSeed));
		output = concatBytes(output, block)
	}
	return output.slice(0, length)
}
async function hkdfExtract(hash, salt, inputKeyMaterial) {
	return salt && salt.length || (salt = new Uint8Array(hashByteLength(hash))), hmac(hash, salt, inputKeyMaterial)
}
async function hkdfExpandLabel(hash, secret, label, context, length) {
	const fullLabel = textEncoder.encode("tls13 " + label);
	return async function (hash, secret, info, length) {
		const hashLen = hashByteLength(hash),
			roundCount = Math.ceil(length / hashLen);
		let output = new Uint8Array(0),
			previousBlock = new Uint8Array(0);
		for (let round = 1; round <= roundCount; round++) previousBlock = await hmac(hash, secret, concatBytes(previousBlock, info, [round])), output = concatBytes(output, previousBlock);
		return output.slice(0, length)
	}(hash, secret, tlsBytes(uint16be(length), fullLabel.length, fullLabel, context.length, context), length)
}
async function generateKeyShare(group = "P-256") {
	const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group };
	const keyPair = /** @type {CryptoKeyPair} */ (await crypto.subtle.generateKey(algorithm, !0, ["deriveBits"]));
	const publicKeyRaw = /** @type {ArrayBuffer} */ (await crypto.subtle.exportKey("raw", keyPair.publicKey));
	return { keyPair, publicKeyRaw: new Uint8Array(publicKeyRaw) }
}
async function deriveSharedSecret(privateKey, peerPublicKey, group = "P-256") {
	const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group },
		peerKey = await crypto.subtle.importKey("raw", peerPublicKey, algorithm, !1, []),
		bits = "P-384" === group ? 384 : "P-521" === group ? 528 : 256;
	return new Uint8Array(await crypto.subtle.deriveBits(/** @type {any} */({ name: algorithm.name, public: peerKey }), privateKey, bits))
}
async function importAesGcmKey(key, usages) { return crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, !1, usages) }
async function aesGcmEncryptWithKey(cryptoKey, initializationVector, plaintext, additionalData) {
	return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, plaintext))
}
async function aesGcmDecryptWithKey(cryptoKey, initializationVector, ciphertext, additionalData) {
	return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, ciphertext))
}

function rotateLeft32(value, bits) { return (value << bits | value >>> 32 - bits) >>> 0 }

function chachaQuarterRound(state, indexA, indexB, indexC, indexD) {
	state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 16), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 12), state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 8), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 7)
}

function chacha20Block(key, counter, nonce) {
	const state = new Uint32Array(16);
	state[0] = 1634760805, state[1] = 857760878, state[2] = 2036477234, state[3] = 1797285236;
	const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
	for (let wordIndex = 0; wordIndex < 8; wordIndex++) state[4 + wordIndex] = keyView.getUint32(4 * wordIndex, !0);
	state[12] = counter;
	const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
	state[13] = nonceView.getUint32(0, !0), state[14] = nonceView.getUint32(4, !0), state[15] = nonceView.getUint32(8, !0);
	const workingState = new Uint32Array(state);
	for (let round = 0; round < 10; round++) chachaQuarterRound(workingState, 0, 4, 8, 12), chachaQuarterRound(workingState, 1, 5, 9, 13), chachaQuarterRound(workingState, 2, 6, 10, 14), chachaQuarterRound(workingState, 3, 7, 11, 15), chachaQuarterRound(workingState, 0, 5, 10, 15), chachaQuarterRound(workingState, 1, 6, 11, 12), chachaQuarterRound(workingState, 2, 7, 8, 13), chachaQuarterRound(workingState, 3, 4, 9, 14);
	for (let wordIndex = 0; wordIndex < 16; wordIndex++) workingState[wordIndex] = workingState[wordIndex] + state[wordIndex] >>> 0;
	return new Uint8Array(workingState.buffer.slice(0))
}

function chacha20Xor(key, nonce, data) {
	const output = new Uint8Array(data.length);
	let counter = 1;
	for (let offset = 0; offset < data.length; offset += 64) {
		const block = chacha20Block(key, counter++, nonce),
			blockLength = Math.min(64, data.length - offset);
		for (let index = 0; index < blockLength; index++) output[offset + index] = data[offset + index] ^ block[index]
	}
	return output
}

function poly1305Mac(key, message) {
	const rKey = function (rBytes) {
		const clamped = new Uint8Array(rBytes);
		return clamped[3] &= 15, clamped[7] &= 15, clamped[11] &= 15, clamped[15] &= 15, clamped[4] &= 252, clamped[8] &= 252, clamped[12] &= 252, clamped
	}(key.slice(0, 16)),
		sKey = key.slice(16, 32);
	let accumulator = [0n, 0n, 0n, 0n, 0n];
	const rLimbs = [0x3ffffffn & BigInt(rKey[0] | rKey[1] << 8 | rKey[2] << 16 | rKey[3] << 24), 0x3ffffffn & BigInt(rKey[3] >> 2 | rKey[4] << 6 | rKey[5] << 14 | rKey[6] << 22), 0x3ffffffn & BigInt(rKey[6] >> 4 | rKey[7] << 4 | rKey[8] << 12 | rKey[9] << 20), 0x3ffffffn & BigInt(rKey[9] >> 6 | rKey[10] << 2 | rKey[11] << 10 | rKey[12] << 18), 0x3ffffffn & BigInt(rKey[13] | rKey[14] << 8 | rKey[15] << 16)];
	for (let offset = 0; offset < message.length; offset += 16) {
		const chunk = message.slice(offset, offset + 16),
			paddedChunk = new Uint8Array(17);
		paddedChunk.set(chunk), paddedChunk[chunk.length] = 1, accumulator[0] += BigInt(paddedChunk[0] | paddedChunk[1] << 8 | paddedChunk[2] << 16 | (3 & paddedChunk[3]) << 24), accumulator[1] += BigInt(paddedChunk[3] >> 2 | paddedChunk[4] << 6 | paddedChunk[5] << 14 | (15 & paddedChunk[6]) << 22), accumulator[2] += BigInt(paddedChunk[6] >> 4 | paddedChunk[7] << 4 | paddedChunk[8] << 12 | (63 & paddedChunk[9]) << 20), accumulator[3] += BigInt(paddedChunk[9] >> 6 | paddedChunk[10] << 2 | paddedChunk[11] << 10 | paddedChunk[12] << 18), accumulator[4] += BigInt(paddedChunk[13] | paddedChunk[14] << 8 | paddedChunk[15] << 16 | paddedChunk[16] << 24);
		const product = [0n, 0n, 0n, 0n, 0n];
		for (let accIndex = 0; accIndex < 5; accIndex++)
			for (let rIndex = 0; rIndex < 5; rIndex++) {
				const limbIndex = accIndex + rIndex;
				limbIndex < 5 ? product[limbIndex] += accumulator[accIndex] * rLimbs[rIndex] : product[limbIndex - 5] += accumulator[accIndex] * rLimbs[rIndex] * 5n
			}
		let carry = 0n;
		for (let index = 0; index < 5; index++) product[index] += carry, accumulator[index] = 0x3ffffffn & product[index], carry = product[index] >> 26n;
		accumulator[0] += 5n * carry, carry = accumulator[0] >> 26n, accumulator[0] &= 0x3ffffffn, accumulator[1] += carry
	}
	let tagValue = accumulator[0] | accumulator[1] << 26n | accumulator[2] << 52n | accumulator[3] << 78n | accumulator[4] << 104n;
	tagValue = tagValue + sKey.reduce(((total, byte, index) => total + (BigInt(byte) << BigInt(8 * index))), 0n) & (1n << 128n) - 1n;
	const tag = new Uint8Array(16);
	for (let index = 0; index < 16; index++) tag[index] = Number(tagValue >> BigInt(8 * index) & 0xffn);
	return tag
}

function chacha20Poly1305Encrypt(key, nonce, plaintext, additionalData) {
	const polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		ciphertext = chacha20Xor(key, nonce, plaintext),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - ciphertext.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + ciphertext.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(ciphertext, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + ciphertext.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), !0), lengthView.setBigUint64(8, BigInt(ciphertext.length), !0);
	const tag = poly1305Mac(polyKey, macData);
	return concatBytes(ciphertext, tag)
}

function chacha20Poly1305Decrypt(key, nonce, ciphertext, additionalData) {
	if (ciphertext.length < 16) throw new Error("Ciphertext too short");
	const tag = ciphertext.slice(-16),
		encryptedData = ciphertext.slice(0, -16),
		polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - encryptedData.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + encryptedData.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(encryptedData, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + encryptedData.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), !0), lengthView.setBigUint64(8, BigInt(encryptedData.length), !0);
	const expectedTag = poly1305Mac(polyKey, macData);
	let diff = 0;
	for (let index = 0; index < 16; index++) diff |= tag[index] ^ expectedTag[index];
	if (0 !== diff) throw new Error("ChaCha20-Poly1305 authentication failed");
	return chacha20Xor(key, nonce, encryptedData)
}

const TLS_MAX_PLAINTEXT_FRAGMENT = 16 * 1024;
function buildTlsRecord(contentType, fragment, version = TLS_VERSION_12) {
	const data = 数据转Uint8Array(fragment);
	const record = new Uint8Array(5 + data.byteLength);
	record[0] = contentType;
	record[1] = version >> 8 & 255;
	record[2] = version & 255;
	record[3] = data.byteLength >> 8 & 255;
	record[4] = data.byteLength & 255;
	record.set(data, 5);
	return record;
}
function buildHandshakeMessage(handshakeType, body) { return tlsBytes(handshakeType, (length => [length >> 16 & 255, length >> 8 & 255, 255 & length])(body.length), body) }
class TlsRecordParser {
	constructor() { this.buffer = new Uint8Array(0) }
	feed(chunk) {
		const bytes = 数据转Uint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next() {
		if (this.buffer.length < 5) return null;
		const contentType = this.buffer[0],
			version = readUint16(this.buffer, 1),
			length = readUint16(this.buffer, 3);
		if (this.buffer.length < 5 + length) return null;
		const fragment = this.buffer.subarray(5, 5 + length);
		return this.buffer = this.buffer.subarray(5 + length), { type: contentType, version, length, fragment }
	}
}
class TlsHandshakeParser {
	constructor() { this.buffer = new Uint8Array(0) }
	feed(chunk) {
		const bytes = 数据转Uint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next() {
		if (this.buffer.length < 4) return null;
		const handshakeType = this.buffer[0],
			length = readUint24(this.buffer, 1);
		if (this.buffer.length < 4 + length) return null;
		const body = this.buffer.subarray(4, 4 + length),
			raw = this.buffer.subarray(0, 4 + length);
		return this.buffer = this.buffer.subarray(4 + length), { type: handshakeType, length, body, raw }
	}
}

function parseServerHello(body) {
	let offset = 0;
	const legacyVersion = readUint16(body, offset);
	offset += 2;
	const serverRandom = body.slice(offset, offset + 32);
	offset += 32;
	const sessionIdLength = body[offset++],
		sessionId = body.slice(offset, offset + sessionIdLength);
	offset += sessionIdLength;
	const cipherSuite = readUint16(body, offset);
	offset += 2;
	const compression = body[offset++];
	let selectedVersion = legacyVersion,
		keyShare = null,
		alpn = null;
	if (offset < body.length) {
		const extensionsLength = readUint16(body, offset);
		offset += 2;
		const extensionsEnd = offset + extensionsLength;
		for (; offset + 4 <= extensionsEnd;) {
			const extensionType = readUint16(body, offset);
			offset += 2;
			const extensionLength = readUint16(body, offset);
			offset += 2;
			const extensionData = body.slice(offset, offset + extensionLength);
			if (offset += extensionLength, extensionType === EXT_SUPPORTED_VERSIONS && extensionLength >= 2) selectedVersion = readUint16(extensionData, 0);
			else if (extensionType === EXT_KEY_SHARE && extensionLength >= 4) {
				const group = readUint16(extensionData, 0),
					keyLength = readUint16(extensionData, 2);
				keyShare = { group, key: extensionData.slice(4, 4 + keyLength) }
			} else extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3 && (alpn = textDecoder.decode(extensionData.slice(3, 3 + extensionData[2])))
		}
	}
	const helloRetryRequestRandom = new Uint8Array([207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156]);
	return { version: legacyVersion, serverRandom, sessionId, cipherSuite, compression, selectedVersion, keyShare, alpn, isHRR: constantTimeEqual(serverRandom, helloRetryRequestRandom), isTls13: selectedVersion === TLS_VERSION_13 }
}

function parseServerKeyExchange(body) {
	let offset = 1;
	const namedCurve = readUint16(body, offset);
	offset += 2;
	const keyLength = body[offset++];
	return { namedCurve, serverPublicKey: body.slice(offset, offset + keyLength) }
}

function extractLeafCertificate(body, hasContext = 0) {
	let offset = 0;
	if (hasContext) {
		const contextLength = body[offset++];
		offset += contextLength
	}
	if (offset + 3 > body.length) return null;
	const certificateListLength = readUint24(body, offset);
	if (offset += 3, !certificateListLength || offset + 3 > body.length) return null;
	const certificateLength = readUint24(body, offset);
	return offset += 3, certificateLength ? body.slice(offset, offset + certificateLength) : null
}

function parseEncryptedExtensions(body) {
	const parsed = { alpn: null };
	let offset = 2;
	const extensionsEnd = 2 + readUint16(body, 0);
	for (; offset + 4 <= extensionsEnd;) {
		const extensionType = readUint16(body, offset);
		offset += 2;
		const extensionLength = readUint16(body, offset);
		if (offset += 2, extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3) {
			const protocolLength = body[offset + 2];
			protocolLength > 0 && offset + 3 + protocolLength <= offset + extensionLength && (parsed.alpn = textDecoder.decode(body.slice(offset + 3, offset + 3 + protocolLength)))
		}
		offset += extensionLength
	}
	return parsed
}

function buildClientHello(clientRandom, serverName, keyShares, { tls13: enableTls13 = !0, tls12: enableTls12 = !0, alpn = null, chacha = !0 } = {}) {
	const cipherIds = [];
	enableTls13 && cipherIds.push(4865, 4866, ...(chacha ? [4867] : [])), enableTls12 && cipherIds.push(49199, 49200, 49195, 49196, ...(chacha ? [52392, 52393] : []));
	const cipherBytes = tlsBytes(...cipherIds.flatMap(uint16be)),
		extensions = [tlsBytes(255, 1, 0, 1, 0)];
	if (serverName) {
		const serverNameBytes = textEncoder.encode(serverName),
			serverNameList = tlsBytes(0, uint16be(serverNameBytes.length), serverNameBytes);
		extensions.push(tlsBytes(uint16be(EXT_SERVER_NAME), uint16be(serverNameList.length + 2), uint16be(serverNameList.length), serverNameList))
	}
	extensions.push(tlsBytes(uint16be(EXT_EC_POINT_FORMATS), 0, 2, 1, 0)), extensions.push(tlsBytes(uint16be(EXT_SUPPORTED_GROUPS), 0, 6, 0, 4, 0, 29, 0, 23));
	const signatureBytes = tlsBytes(...SUPPORTED_SIGNATURE_ALGORITHMS.flatMap(uint16be));
	extensions.push(tlsBytes(uint16be(EXT_SIGNATURE_ALGORITHMS), uint16be(signatureBytes.length + 2), uint16be(signatureBytes.length), signatureBytes));
	const protocols = Array.isArray(alpn) ? alpn.filter(Boolean) : alpn ? [alpn] : [];
	if (protocols.length) {
		const alpnBytes = concatBytes(...protocols.map((protocol => { const protocolBytes = textEncoder.encode(protocol); return tlsBytes(protocolBytes.length, protocolBytes) })));
		extensions.push(tlsBytes(uint16be(EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION), uint16be(alpnBytes.length + 2), uint16be(alpnBytes.length), alpnBytes))
	}
	if (enableTls13 && keyShares) {
		let keyShareBytes;
		if (extensions.push(enableTls12 ? tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 5, 4, 3, 4, 3, 3) : tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 3, 2, 3, 4)), extensions.push(tlsBytes(uint16be(EXT_PSK_KEY_EXCHANGE_MODES), 0, 2, 1, 1)), keyShares?.x25519 && keyShares?.p256) keyShareBytes = concatBytes(tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519), tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256));
		else if (keyShares?.x25519) keyShareBytes = tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519);
		else if (keyShares?.p256) keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256);
		else {
			if (!(keyShares instanceof Uint8Array)) throw new Error("Invalid keyShares");
			keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.length), keyShares)
		}
		extensions.push(tlsBytes(uint16be(EXT_KEY_SHARE), uint16be(keyShareBytes.length + 2), uint16be(keyShareBytes.length), keyShareBytes))
	}
	const extensionsBytes = concatBytes(...extensions);
	return buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_HELLO, tlsBytes(uint16be(TLS_VERSION_12), clientRandom, 0, uint16be(cipherBytes.length), cipherBytes, 1, 0, uint16be(extensionsBytes.length), extensionsBytes))
}
const uint64be = sequenceNumber => { const bytes = new Uint8Array(8); return new DataView(bytes.buffer).setBigUint64(0, sequenceNumber, !1), bytes },
	xorSequenceIntoIv = (initializationVector, sequenceNumber) => {
		const nonce = initializationVector.slice(),
			sequenceBytes = uint64be(sequenceNumber);
		for (let index = 0; index < 8; index++) nonce[nonce.length - 8 + index] ^= sequenceBytes[index];
		return nonce
	},
	deriveTrafficKeys = (hash, secret, keyLen, ivLen) => Promise.all([hkdfExpandLabel(hash, secret, "key", EMPTY_BYTES, keyLen), hkdfExpandLabel(hash, secret, "iv", EMPTY_BYTES, ivLen)]);
class TlsClient {
	constructor(socket, options = {}) {
		if (this.socket = socket, this.serverName = options.serverName || "", this.supportTls13 = !1 !== options.tls13, this.supportTls12 = !1 !== options.tls12, !this.supportTls13 && !this.supportTls12) throw new Error("At least one TLS version must be enabled");
		this.alpnProtocols = Array.isArray(options.alpn) ? options.alpn : options.alpn ? [options.alpn] : null, this.allowChacha = options.allowChacha !== false, this.timeout = options.timeout ?? 3e4, this.clientRandom = randomBytes(32), this.serverRandom = null, this.handshakeChunks = [], this.handshakeComplete = !1, this.negotiatedAlpn = null, this.cipherSuite = null, this.cipherConfig = null, this.isTls13 = !1, this.masterSecret = null, this.handshakeSecret = null, this.clientWriteKey = null, this.serverWriteKey = null, this.clientWriteIv = null, this.serverWriteIv = null, this.clientHandshakeKey = null, this.serverHandshakeKey = null, this.clientHandshakeIv = null, this.serverHandshakeIv = null, this.clientAppKey = null, this.serverAppKey = null, this.clientAppIv = null, this.serverAppIv = null, this.clientWriteCryptoKey = null, this.serverWriteCryptoKey = null, this.clientHandshakeCryptoKey = null, this.serverHandshakeCryptoKey = null, this.clientAppCryptoKey = null, this.serverAppCryptoKey = null, this.clientSeqNum = 0n, this.serverSeqNum = 0n, this.recordParser = new TlsRecordParser, this.handshakeParser = new TlsHandshakeParser, this.keyPairs = new Map, this.ecdhKeyPair = null, this.sawCert = !1
	}
	recordHandshake(chunk) { this.handshakeChunks.push(chunk) }
	transcript() { return 1 === this.handshakeChunks.length ? this.handshakeChunks[0] : concatBytes(...this.handshakeChunks) }
	getCipherConfig(cipherSuite) { return CIPHER_SUITES_BY_ID.get(cipherSuite) || null }
	async readChunk(reader) { return this.timeout ? Promise.race([reader.read(), new Promise(((resolve, reject) => setTimeout((() => reject(new Error("TLS read timeout"))), this.timeout)))]) : reader.read() }
	async readRecordsUntil(reader, predicate, closedError) {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();)
				if (await predicate(record)) return;
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error(closedError);
			this.recordParser.feed(value)
		}
	}
	async readHandshakeUntil(reader, predicate, closedError) {
		for (let message; message = this.handshakeParser.next();)
			if (await predicate(message)) return;
		return this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(record.fragment);
				for (let message; message = this.handshakeParser.next();)
					if (await predicate(message)) return 1
			}
		}), closedError)
	}
	async acceptCertificate(certificate) { if (!certificate?.length) throw new Error("Empty certificate"); this.sawCert = !0 }
	async handshake() {
		const [p256Share, x25519Share] = await Promise.all([generateKeyShare("P-256"), generateKeyShare("X25519")]);
		this.keyPairs = new Map([[23, p256Share], [29, x25519Share]]), this.ecdhKeyPair = p256Share.keyPair;
		const reader = this.socket.readable.getReader(),
			writer = this.socket.writable.getWriter();
		try {
			const clientHello = buildClientHello(this.clientRandom, this.serverName, { x25519: x25519Share.publicKeyRaw, p256: p256Share.publicKeyRaw }, { tls13: this.supportTls13, tls12: this.supportTls12, alpn: this.alpnProtocols, chacha: this.allowChacha });
			this.recordHandshake(clientHello), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientHello, TLS_VERSION_10));
			const serverHello = await this.receiveServerHello(reader);
			if (serverHello.isHRR) throw new Error("HelloRetryRequest is not supported by TLSClientMini");
			if (serverHello.keyShare?.group && this.keyPairs.has(serverHello.keyShare.group)) {
				const selectedKeyPair = this.keyPairs.get(serverHello.keyShare.group);
				this.ecdhKeyPair = selectedKeyPair.keyPair
			}
			serverHello.isTls13 ? await this.handshakeTls13(reader, writer, serverHello) : await this.handshakeTls12(reader, writer), this.handshakeComplete = !0
		} finally {
			reader.releaseLock(), writer.releaseLock()
		}
	}
	async receiveServerHello(reader) {
		for (; ;) {
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error("Connection closed waiting for ServerHello");
			let record;
			for (this.recordParser.feed(value); record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (shouldIgnoreTlsAlert(record.fragment)) continue;
					throw new Error(`TLS Alert: level=${record.fragment[0]}, desc=${record.fragment[1]}`);
				}
				if (record.type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(record.fragment); message = this.handshakeParser.next();) {
					if (message.type !== HANDSHAKE_TYPE_SERVER_HELLO) continue;
					this.recordHandshake(message.raw);
					const serverHello = parseServerHello(message.body);
					if (this.serverRandom = serverHello.serverRandom, this.cipherSuite = serverHello.cipherSuite, this.cipherConfig = this.getCipherConfig(serverHello.cipherSuite), this.isTls13 = serverHello.isTls13, this.negotiatedAlpn = serverHello.alpn || null, !this.cipherConfig) throw new Error(`Unsupported cipher suite: 0x${serverHello.cipherSuite.toString(16)}`);
					return serverHello
				}
			}
		}
	}
	async handshakeTls12(reader, writer) {
		/** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */
		let serverKeyExchange = null;
		let sawServerHelloDone = !1;
		let clientCertRequested = !1;
		if (await this.readHandshakeUntil(reader, (async message => {
			switch (message.type) {
				case HANDSHAKE_TYPE_CERTIFICATE: {
					this.recordHandshake(message.raw);
					const certificate = extractLeafCertificate(message.body, 1);
					if (!certificate) throw new Error("Missing TLS 1.2 certificate");
					await this.acceptCertificate(certificate);
					break
				}
				case HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
					this.recordHandshake(message.raw), serverKeyExchange = parseServerKeyExchange(message.body);
					break;
				case HANDSHAKE_TYPE_SERVER_HELLO_DONE:
					return this.recordHandshake(message.raw), sawServerHelloDone = !0, 1;
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					this.recordHandshake(message.raw), clientCertRequested = !0;
					break;
				default:
					this.recordHandshake(message.raw)
			}
		}), "Connection closed during TLS 1.2 handshake"), !this.sawCert) throw new Error("Missing TLS 1.2 leaf certificate");
		const serverKeyExchangeData = /** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */ (serverKeyExchange);
		if (!serverKeyExchangeData) throw new Error("Missing TLS 1.2 ServerKeyExchange");
		const curveName = GROUPS_BY_ID.get(serverKeyExchangeData.namedCurve);
		if (!curveName) throw new Error(`Unsupported named curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const keyShare = this.keyPairs.get(serverKeyExchangeData.namedCurve);
		if (!keyShare) throw new Error(`Missing key pair for curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const preMasterSecret = await deriveSharedSecret(keyShare.keyPair.privateKey, serverKeyExchangeData.serverPublicKey, curveName),
			clientKeyExchange = buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, tlsBytes(keyShare.publicKeyRaw.length, keyShare.publicKeyRaw));
		if (clientCertRequested) {
			const emptyCertificate = buildHandshakeMessage(HANDSHAKE_TYPE_CERTIFICATE, tlsBytes(0, 0, 0));
			this.recordHandshake(emptyCertificate), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, emptyCertificate))
		}
		this.recordHandshake(clientKeyExchange);
		const hashName = this.cipherConfig.hash;
		this.masterSecret = await tls12Prf(preMasterSecret, "master secret", concatBytes(this.clientRandom, this.serverRandom), 48, hashName);
		const keyLen = this.cipherConfig.keyLen,
			ivLen = this.cipherConfig.ivLen,
			keyBlock = await tls12Prf(this.masterSecret, "key expansion", concatBytes(this.serverRandom, this.clientRandom), 2 * keyLen + 2 * ivLen, hashName);
		this.clientWriteKey = keyBlock.slice(0, keyLen), this.serverWriteKey = keyBlock.slice(keyLen, 2 * keyLen), this.clientWriteIv = keyBlock.slice(2 * keyLen, 2 * keyLen + ivLen), this.serverWriteIv = keyBlock.slice(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen);
		if (!this.cipherConfig.chacha) [this.clientWriteCryptoKey, this.serverWriteCryptoKey] = await Promise.all([importAesGcmKey(this.clientWriteKey, ["encrypt"]), importAesGcmKey(this.serverWriteKey, ["decrypt"])]);
		await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientKeyExchange)), await writer.write(buildTlsRecord(CONTENT_TYPE_CHANGE_CIPHER_SPEC, tlsBytes(1)));
		const clientVerifyData = await tls12Prf(this.masterSecret, "client finished", await digestBytes(hashName, this.transcript()), 12, hashName),
			finishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientVerifyData);
		this.recordHandshake(finishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, await this.encryptTls12(finishedMessage, CONTENT_TYPE_HANDSHAKE)));
		let sawChangeCipherSpec = !1;
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC) return void (sawChangeCipherSpec = !0);
			if (record.type !== CONTENT_TYPE_HANDSHAKE || !sawChangeCipherSpec) return;
			const decrypted = await this.decryptTls12(record.fragment, CONTENT_TYPE_HANDSHAKE);
			if (decrypted[0] !== HANDSHAKE_TYPE_FINISHED) return;
			const verifyLength = readUint24(decrypted, 1),
				verifyData = decrypted.slice(4, 4 + verifyLength),
				expectedVerifyData = await tls12Prf(this.masterSecret, "server finished", await digestBytes(hashName, this.transcript()), 12, hashName);
			if (!constantTimeEqual(verifyData, expectedVerifyData)) throw new Error("TLS 1.2 server Finished verify failed");
			return 1
		}), "Connection closed waiting for TLS 1.2 Finished")
	}
	async handshakeTls13(reader, writer, serverHello) {
		const groupName = GROUPS_BY_ID.get(serverHello.keyShare?.group);
		if (!groupName || !serverHello.keyShare?.key?.length) throw new Error("Missing TLS 1.3 key_share");
		const hashName = this.cipherConfig.hash,
			hashLen = hashByteLength(hashName),
			keyLen = this.cipherConfig.keyLen,
			ivLen = this.cipherConfig.ivLen,
			sharedSecret = await deriveSharedSecret(this.ecdhKeyPair.privateKey, serverHello.keyShare.key, groupName),
			earlySecret = await hkdfExtract(hashName, null, new Uint8Array(hashLen)),
			derivedSecret = await hkdfExpandLabel(hashName, earlySecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen);
		this.handshakeSecret = await hkdfExtract(hashName, derivedSecret, sharedSecret);
		const transcriptHash = await digestBytes(hashName, this.transcript()),
			clientHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "c hs traffic", transcriptHash, hashLen),
			serverHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "s hs traffic", transcriptHash, hashLen);
		[this.clientHandshakeKey, this.clientHandshakeIv] = await deriveTrafficKeys(hashName, clientHandshakeTrafficSecret, keyLen, ivLen), [this.serverHandshakeKey, this.serverHandshakeIv] = await deriveTrafficKeys(hashName, serverHandshakeTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig.chacha) [this.clientHandshakeCryptoKey, this.serverHandshakeCryptoKey] = await Promise.all([importAesGcmKey(this.clientHandshakeKey, ["encrypt"]), importAesGcmKey(this.serverHandshakeKey, ["decrypt"])]);
		const serverFinishedKey = await hkdfExpandLabel(hashName, serverHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen);
		let serverFinishedReceived = !1;
		let clientCertRequested = !1;
		const handleHandshakeMessage = async message => {
			switch (message.type) {
				case HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: {
					const encryptedExtensions = parseEncryptedExtensions(message.body);
					encryptedExtensions.alpn && (this.negotiatedAlpn = encryptedExtensions.alpn), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE: {
					const certificate = extractLeafCertificate(message.body);
					if (!certificate) throw new Error("Missing TLS 1.3 certificate");
					await this.acceptCertificate(certificate), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					this.recordHandshake(message.raw), clientCertRequested = !0;
					break;
				case HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
					this.recordHandshake(message.raw);
					break;
				case HANDSHAKE_TYPE_FINISHED: {
					const expectedVerifyData = await hmac(hashName, serverFinishedKey, await digestBytes(hashName, this.transcript()));
					if (!constantTimeEqual(expectedVerifyData, message.body)) throw new Error("TLS 1.3 server Finished verify failed");
					this.recordHandshake(message.raw), serverFinishedReceived = !0;
					break
				}
				default:
					this.recordHandshake(message.raw)
			}
		};
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC || record.type === CONTENT_TYPE_HANDSHAKE) return;
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type !== CONTENT_TYPE_APPLICATION_DATA) return;
			const decrypted = await this.decryptTls13Handshake(record.fragment),
				innerType = decrypted[decrypted.length - 1],
				plaintext = decrypted.slice(0, -1);
			if (innerType === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(plaintext);
				for (let message; message = this.handshakeParser.next();)
					if (await handleHandshakeMessage(message), serverFinishedReceived) return 1
			}
		}), "Connection closed during TLS 1.3 handshake");
		const applicationTranscriptHash = await digestBytes(hashName, this.transcript()),
			masterDerivedSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen),
			masterSecret = await hkdfExtract(hashName, masterDerivedSecret, new Uint8Array(hashLen)),
			clientAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "c ap traffic", applicationTranscriptHash, hashLen),
			serverAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "s ap traffic", applicationTranscriptHash, hashLen);
		[this.clientAppKey, this.clientAppIv] = await deriveTrafficKeys(hashName, clientAppTrafficSecret, keyLen, ivLen), [this.serverAppKey, this.serverAppIv] = await deriveTrafficKeys(hashName, serverAppTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig.chacha) [this.clientAppCryptoKey, this.serverAppCryptoKey] = await Promise.all([importAesGcmKey(this.clientAppKey, ["encrypt"]), importAesGcmKey(this.serverAppKey, ["decrypt"])]);
		let clientFlightHandshake = EMPTY_BYTES;
		if (clientCertRequested) clientFlightHandshake = buildHandshakeMessage(HANDSHAKE_TYPE_CERTIFICATE, tlsBytes(0, 0, 0, 0)), this.recordHandshake(clientFlightHandshake);
		const clientFinishedKey = await hkdfExpandLabel(hashName, clientHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen),
			clientFinishedVerifyData = await hmac(hashName, clientFinishedKey, await digestBytes(hashName, this.transcript())),
			clientFinishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientFinishedVerifyData);
		this.recordHandshake(clientFinishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, await this.encryptTls13Handshake(concatBytes(clientFlightHandshake, clientFinishedMessage, [CONTENT_TYPE_HANDSHAKE])))), this.clientSeqNum = 0n, this.serverSeqNum = 0n
	}
	async encryptTls12(plaintext, contentType) {
		const sequenceNumber = this.clientSeqNum++,
			sequenceBytes = uint64be(sequenceNumber),
			additionalData = concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(plaintext.length));
		if (this.cipherConfig.chacha) {
			const nonce = xorSequenceIntoIv(this.clientWriteIv, sequenceNumber);
			return chacha20Poly1305Encrypt(this.clientWriteKey, nonce, plaintext, additionalData)
		}
		const explicitNonce = randomBytes(8);
		if (!this.clientWriteCryptoKey) this.clientWriteCryptoKey = await importAesGcmKey(this.clientWriteKey, ["encrypt"]);
		return concatBytes(explicitNonce, await aesGcmEncryptWithKey(this.clientWriteCryptoKey, concatBytes(this.clientWriteIv, explicitNonce), plaintext, additionalData))
	}
	async decryptTls12(ciphertext, contentType) {
		const sequenceNumber = this.serverSeqNum++,
			sequenceBytes = uint64be(sequenceNumber);
		if (this.cipherConfig.chacha) {
			const nonce = xorSequenceIntoIv(this.serverWriteIv, sequenceNumber);
			return chacha20Poly1305Decrypt(this.serverWriteKey, nonce, ciphertext, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(ciphertext.length - 16)))
		}
		const explicitNonce = ciphertext.subarray(0, 8),
			encryptedData = ciphertext.subarray(8);
		if (!this.serverWriteCryptoKey) this.serverWriteCryptoKey = await importAesGcmKey(this.serverWriteKey, ["decrypt"]);
		return aesGcmDecryptWithKey(this.serverWriteCryptoKey, concatBytes(this.serverWriteIv, explicitNonce), encryptedData, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(encryptedData.length - 16)))
	}
	async encryptTls13Handshake(plaintext) {
		const nonce = xorSequenceIntoIv(this.clientHandshakeIv, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientHandshakeKey, nonce, plaintext, additionalData);
		if (!this.clientHandshakeCryptoKey) this.clientHandshakeCryptoKey = await importAesGcmKey(this.clientHandshakeKey, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientHandshakeCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13Handshake(ciphertext) {
		const nonce = xorSequenceIntoIv(this.serverHandshakeIv, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length));
		const decrypted = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverHandshakeKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverHandshakeCryptoKey || (this.serverHandshakeCryptoKey = await importAesGcmKey(this.serverHandshakeKey, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = decrypted.length - 1;
		for (; innerTypeIndex >= 0 && !decrypted[innerTypeIndex];) innerTypeIndex--;
		return innerTypeIndex < 0 ? EMPTY_BYTES : decrypted.slice(0, innerTypeIndex + 1)
	}
	async encryptTls13(data) {
		const plaintext = concatBytes(data, [CONTENT_TYPE_APPLICATION_DATA]),
			nonce = xorSequenceIntoIv(this.clientAppIv, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientAppKey, nonce, plaintext, additionalData);
		if (!this.clientAppCryptoKey) this.clientAppCryptoKey = await importAesGcmKey(this.clientAppKey, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientAppCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13(ciphertext) {
		const nonce = xorSequenceIntoIv(this.serverAppIv, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length)),
			plaintext = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverAppKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverAppCryptoKey || (this.serverAppCryptoKey = await importAesGcmKey(this.serverAppKey, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = plaintext.length - 1;
		for (; innerTypeIndex >= 0 && !plaintext[innerTypeIndex];) innerTypeIndex--;
		if (innerTypeIndex < 0) return {
			data: EMPTY_BYTES,
			type: 0
		};
		return {
			data: plaintext.slice(0, innerTypeIndex),
			type: plaintext[innerTypeIndex]
		}
	}
	async write(data) {
		if (!this.handshakeComplete) throw new Error("Handshake not complete");
		const plaintext = 数据转Uint8Array(data);
		if (!plaintext.byteLength) return;
		const writer = this.socket.writable.getWriter();
		try {
			const records = [];
			for (let offset = 0; offset < plaintext.byteLength; offset += TLS_MAX_PLAINTEXT_FRAGMENT) {
				const chunk = plaintext.subarray(offset, Math.min(offset + TLS_MAX_PLAINTEXT_FRAGMENT, plaintext.byteLength));
				const encrypted = this.isTls13 ? await this.encryptTls13(chunk) : await this.encryptTls12(chunk, CONTENT_TYPE_APPLICATION_DATA);
				records.push(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, encrypted));
			}
			await writer.write(records.length === 1 ? records[0] : concatBytes(...records))
		} finally {
			writer.releaseLock()
		}
	}
	async read() {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (record.fragment[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${record.fragment[1]}`)
				}
				if (record.type !== CONTENT_TYPE_APPLICATION_DATA) continue;
				if (!this.isTls13) return this.decryptTls12(record.fragment, CONTENT_TYPE_APPLICATION_DATA);
				const { data, type } = await this.decryptTls13(record.fragment);
				if (type === CONTENT_TYPE_APPLICATION_DATA) return data;
				if (type === CONTENT_TYPE_ALERT) {
					if (data[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${data[1]}`)
				}
				if (type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(data); message = this.handshakeParser.next();)
					if (message.type !== HANDSHAKE_TYPE_NEW_SESSION_TICKET && message.type === HANDSHAKE_TYPE_KEY_UPDATE) throw new Error("TLS 1.3 KeyUpdate is not supported by TLSClientMini")
			}
			const reader = this.socket.readable.getReader();
			try {
				const { value, done } = await this.readChunk(reader);
				if (done) return null;
				this.recordParser.feed(value)
			} finally {
				reader.releaseLock()
			}
		}
	}
	close() { this.socket.close() }
}

function stripIPv6Brackets(hostname = '') {
	const host = String(hostname || '').trim();
	return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function isIPHostname(hostname = '') {
	const host = stripIPv6Brackets(hostname);
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
	if (ipv4Regex.test(host)) return true;
	if (!host.includes(':')) return false;
	try {
		new URL(`http://[${host}]/`);
		return true;
	} catch (e) {
		return false;
	}
}

//////////////////////////////////////////////////turnConnect///////////////////////////////////////////////
const CONNECT_TIMEOUT_MS = 9999;
const TURN_STUN_MAGIC_COOKIE = new Uint8Array([0x21, 0x12, 0xa4, 0x42]);
const TURN_STUN_TYPE = {
	ALLOCATE_REQUEST: 0x0003, ALLOCATE_SUCCESS: 0x0103, ALLOCATE_ERROR: 0x0113,
	CREATE_PERMISSION_REQUEST: 0x0008, CREATE_PERMISSION_SUCCESS: 0x0108,
	CONNECT_REQUEST: 0x000a, CONNECT_SUCCESS: 0x010a,
	CONNECTION_BIND_REQUEST: 0x000b, CONNECTION_BIND_SUCCESS: 0x010b
};
const TURN_STUN_ATTR = {
	USERNAME: 0x0006, MESSAGE_INTEGRITY: 0x0008, ERROR_CODE: 0x0009,
	XOR_PEER_ADDRESS: 0x0012, REALM: 0x0014, NONCE: 0x0015,
	REQUESTED_TRANSPORT: 0x0019, CONNECTION_ID: 0x002a
};

async function withTimeout(promise, timeoutMs, message) {
	let timer;
	try {
		return await Promise.race([
			promise,
			new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), timeoutMs) })
		]);
	} finally {
		clearTimeout(timer);
	}
}

function isIPv4(value) {
	const parts = String(value || '').split('.');
	return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function turnStunPadding(length) {
	return -length & 3;
}

function createTurnStunAttribute(type, value) {
	const body = 数据转Uint8Array(value);
	const attribute = new Uint8Array(4 + body.byteLength + turnStunPadding(body.byteLength));
	const view = new DataView(attribute.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	attribute.set(body, 4);
	return attribute;
}

function createTurnStunMessage(type, transactionId, attributes) {
	const body = 拼接字节数据(...attributes);
	const header = new Uint8Array(20);
	const view = new DataView(header.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	header.set(TURN_STUN_MAGIC_COOKIE, 4);
	header.set(transactionId, 8);
	return 拼接字节数据(header, body);
}

function parseTurnErrorCode(data) {
	return data?.byteLength >= 4 ? (data[2] & 7) * 100 + data[3] : 0;
}

function randomTurnTransactionId() {
	return crypto.getRandomValues(new Uint8Array(12));
}

async function addTurnMessageIntegrity(message, key) {
	const signedMessage = new Uint8Array(message);
	const view = new DataView(signedMessage.buffer);
	view.setUint16(2, view.getUint16(2) + 24);
	const hmacKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
	const signature = await crypto.subtle.sign('HMAC', hmacKey, signedMessage);
	return 拼接字节数据(signedMessage, createTurnStunAttribute(TURN_STUN_ATTR.MESSAGE_INTEGRITY, new Uint8Array(signature)));
}

async function readTurnStunMessage(reader, bufferedData = null, timeoutMessage = 'TURN response timed out') {
	let buffer = 有效数据长度(bufferedData) ? 数据转Uint8Array(bufferedData) : new Uint8Array(0);
	const pull = async () => {
		const { done, value } = await withTimeout(reader.read(), CONNECT_TIMEOUT_MS, timeoutMessage);
		if (done) throw new Error('TURN server closed connection');
		if (value?.byteLength) buffer = 拼接字节数据(buffer, value);
	};
	while (buffer.byteLength < 20) await pull();

	const messageLength = 20 + ((buffer[2] << 8) | buffer[3]);
	if (messageLength > 65555) throw new Error('TURN response is too large');
	while (buffer.byteLength < messageLength) await pull();
	const messageBuffer = buffer.subarray(0, messageLength);
	if (TURN_STUN_MAGIC_COOKIE.some((value, index) => messageBuffer[4 + index] !== value)) throw new Error('Invalid TURN/STUN response');

	const view = new DataView(messageBuffer.buffer, messageBuffer.byteOffset, messageBuffer.byteLength);
	const attributes = {};
	for (let offset = 20; offset + 4 <= messageLength;) {
		const type = view.getUint16(offset);
		const length = view.getUint16(offset + 2);
		if (offset + 4 + length > messageBuffer.byteLength) break;
		attributes[type] = messageBuffer.slice(offset + 4, offset + 4 + length);
		offset += 4 + length + turnStunPadding(length);
	}
	return {
		message: { type: view.getUint16(0), attributes },
		extraData: buffer.byteLength > messageLength ? buffer.subarray(messageLength) : null
	};
}

async function writeTurnBytes(writer, bytes, timeoutMessage) {
	await withTimeout(writer.write(bytes), CONNECT_TIMEOUT_MS, timeoutMessage);
}

async function turnConnect(proxy, targetHost, targetPort, TCP连接) {
	proxy = { ...proxy, username: proxy.username ?? null, password: proxy.password ?? null };
	const resolvedTargetHost = stripIPv6Brackets(targetHost);
	/** @type {string | null} */
	let targetIp = isIPv4(resolvedTargetHost) ? resolvedTargetHost : null;
	if (!targetIp) {
		const records = await DoH查询(resolvedTargetHost, 'A');
		const recordData = records.find(item => item.type === 1 && isIPv4(item.data))?.data;
		targetIp = typeof recordData === 'string' ? recordData : null;
	}
	if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for TURN CONNECT`);

	const turnHost = stripIPv6Brackets(proxy.hostname);
	let controlSocket = null, dataSocket = null, controlWriter = null, controlReader = null, dataWriter = null, dataReader = null, dataReaderReleased = false;
	const close = () => {
		try { controlSocket?.close?.() } catch (e) { }
		try { dataSocket?.close?.() } catch (e) { }
	};
	const releaseDataReader = () => {
		if (dataReaderReleased) return;
		dataReaderReleased = true;
		try { dataReader?.releaseLock?.() } catch (e) { }
	};

	try {
		controlSocket = TCP连接({ hostname: turnHost, port: proxy.port });
		await withTimeout(controlSocket.opened, CONNECT_TIMEOUT_MS, 'TURN server connection timed out');
		controlWriter = controlSocket.writable.getWriter();
		controlReader = controlSocket.readable.getReader();

		const xorPeerAddress = new Uint8Array(8);
		xorPeerAddress[1] = 1;
		new DataView(xorPeerAddress.buffer).setUint16(2, targetPort ^ 0x2112);
		targetIp.split('.').forEach((value, index) => {
			xorPeerAddress[4 + index] = Number(value) ^ TURN_STUN_MAGIC_COOKIE[index];
		});
		const peerAddress = createTurnStunAttribute(TURN_STUN_ATTR.XOR_PEER_ADDRESS, xorPeerAddress);
		const requestedTransport = new Uint8Array([6, 0, 0, 0]);

		await writeTurnBytes(controlWriter, createTurnStunMessage(
			TURN_STUN_TYPE.ALLOCATE_REQUEST,
			randomTurnTransactionId(),
			[createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport)]
		), 'TURN Allocate request timed out');

		let turnResponse = await readTurnStunMessage(controlReader, null, 'TURN Allocate response timed out');
		let message = turnResponse.message;
		let bufferedData = turnResponse.extraData;
		let integrityKey = null;
		let authAttributes = [];
		const sign = messageToSign => integrityKey ? addTurnMessageIntegrity(messageToSign, integrityKey) : Promise.resolve(messageToSign);

		if (
			message.type === TURN_STUN_TYPE.ALLOCATE_ERROR
			&& proxy.username !== null
			&& proxy.password !== null
			&& parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]) === 401
		) {
			const realmBytes = message.attributes[TURN_STUN_ATTR.REALM];
			const nonce = message.attributes[TURN_STUN_ATTR.NONCE];
			if (!realmBytes || !nonce?.byteLength) throw new Error('TURN authentication challenge is missing realm or nonce');

			const realm = textDecoder.decode(realmBytes);
			integrityKey = new Uint8Array(await crypto.subtle.digest('MD5', textEncoder.encode(`${proxy.username}:${realm}:${proxy.password}`)));
			authAttributes = [
				createTurnStunAttribute(TURN_STUN_ATTR.USERNAME, textEncoder.encode(proxy.username)),
				createTurnStunAttribute(TURN_STUN_ATTR.REALM, textEncoder.encode(realm)),
				createTurnStunAttribute(TURN_STUN_ATTR.NONCE, nonce)
			];

			const allocateRequest = await addTurnMessageIntegrity(createTurnStunMessage(
				TURN_STUN_TYPE.ALLOCATE_REQUEST,
				randomTurnTransactionId(),
				[
					createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport),
					...authAttributes
				]
			), integrityKey);
			const pipelinedMessages = await Promise.all([
				sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
				sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes]))
			]);
			await writeTurnBytes(controlWriter, 拼接字节数据(allocateRequest, ...pipelinedMessages), 'TURN authenticated Allocate request timed out');
			turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN authenticated Allocate response timed out');
			message = turnResponse.message;
			bufferedData = turnResponse.extraData;
		} else if (message.type === TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
			const pipelinedMessages = await Promise.all([
				sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
				sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes]))
			]);
			if (pipelinedMessages.length) await writeTurnBytes(controlWriter, 拼接字节数据(...pipelinedMessages), 'TURN pipelined request timed out');
		}

		if (message.type !== TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
			const errorCode = parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]);
			throw new Error(errorCode ? `TURN Allocate failed with ${errorCode}` : 'TURN Allocate failed');
		}

		dataSocket = TCP连接({ hostname: turnHost, port: proxy.port });
		turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CreatePermission response timed out');
		message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CREATE_PERMISSION_SUCCESS) throw new Error('TURN CreatePermission failed');

		turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CONNECT response timed out');
		message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECT_SUCCESS || !message.attributes[TURN_STUN_ATTR.CONNECTION_ID]) throw new Error('TURN CONNECT failed');

		await withTimeout(dataSocket.opened, CONNECT_TIMEOUT_MS, 'TURN data connection timed out');
		dataWriter = dataSocket.writable.getWriter();
		dataReader = dataSocket.readable.getReader();
		await writeTurnBytes(dataWriter, await sign(createTurnStunMessage(
			TURN_STUN_TYPE.CONNECTION_BIND_REQUEST,
			randomTurnTransactionId(),
			[
				createTurnStunAttribute(TURN_STUN_ATTR.CONNECTION_ID, message.attributes[TURN_STUN_ATTR.CONNECTION_ID]),
				...authAttributes
			]
		)), 'TURN ConnectionBind request timed out');

		turnResponse = await readTurnStunMessage(dataReader, null, 'TURN ConnectionBind response timed out');
		message = turnResponse.message;
		const extraPayload = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECTION_BIND_SUCCESS) throw new Error('TURN ConnectionBind failed');

		controlWriter.releaseLock();
		controlWriter = null;
		controlReader.releaseLock();
		controlReader = null;
		dataWriter.releaseLock();
		dataWriter = null;

		const readable = new ReadableStream({
			start(controller) {
				if (extraPayload?.byteLength) controller.enqueue(extraPayload);
			},
			pull(controller) {
				return dataReader.read().then(({ done, value }) => {
					if (done) {
						releaseDataReader();
						controller.close();
					} else if (value?.byteLength) controller.enqueue(new Uint8Array(value));
				});
			},
			cancel() {
				try { dataReader?.cancel?.() } catch (e) { }
				releaseDataReader();
				close();
			}
		});

		return { readable, writable: dataSocket.writable, closed: dataSocket.closed, close };
	} catch (error) {
		try { controlWriter?.releaseLock?.() } catch (e) { }
		try { controlReader?.releaseLock?.() } catch (e) { }
		try { dataWriter?.releaseLock?.() } catch (e) { }
		releaseDataReader();
		close();
		throw error;
	}
}
//////////////////////////////////////////////////sstpConnect///////////////////////////////////////////////
const SSTP_TCP_MSS = 1400;
const SSTP_EMPTY_BYTES = new Uint8Array(0);

function readSstpUint16(bytes, offset = 0) {
	return (bytes[offset] << 8) | bytes[offset + 1];
}

function readSstpUint32(bytes, offset = 0) {
	return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function randomSstpUint16() {
	return readSstpUint16(crypto.getRandomValues(new Uint8Array(2)));
}

function internetChecksum(bytes, offset, length) {
	let sum = 0;
	for (let index = offset; index < offset + length - 1; index += 2) sum += readSstpUint16(bytes, index);
	if (length & 1) sum += bytes[offset + length - 1] << 8;
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return (~sum) & 0xffff;
}

async function sstpConnect(proxy, targetHost, targetPort, TCP连接) {
	proxy = { ...proxy, username: proxy.username ?? null, password: proxy.password ?? null };
	let bufferedBytes = SSTP_EMPTY_BYTES, pppIdentifier = 1, socket = null, reader = null, writer = null;
	let closedSettled = false, resolveClosed, rejectClosed;
	const closed = new Promise((resolve, reject) => {
		resolveClosed = resolve;
		rejectClosed = reject;
	});
	const settleClosed = (settle, value) => {
		if (closedSettled) return;
		closedSettled = true;
		settle(value);
	};
	const close = () => {
		try { reader?.cancel?.().catch?.(() => { }) } catch (e) { }
		try { reader?.releaseLock?.() } catch (e) { }
		try { writer?.close?.().catch?.(() => { }) } catch (e) { }
		try { writer?.releaseLock?.() } catch (e) { }
		try { socket?.close?.() } catch (e) { }
		settleClosed(resolveClosed);
	};

	const readSocketChunk = async () => {
		const { value, done } = await reader.read();
		if (done || !value) throw new Error('SSTP socket closed');
		return 数据转Uint8Array(value);
	};
	const readBytes = async length => {
		while (bufferedBytes.byteLength < length) {
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? 拼接字节数据(bufferedBytes, chunk) : chunk;
		}
		const result = bufferedBytes.subarray(0, length);
		bufferedBytes = bufferedBytes.subarray(length);
		return result;
	};
	const readHttpLine = async () => {
		for (; ;) {
			const lineEnd = bufferedBytes.indexOf(10);
			if (lineEnd >= 0) {
				const line = textDecoder.decode(bufferedBytes.subarray(0, lineEnd));
				bufferedBytes = bufferedBytes.subarray(lineEnd + 1);
				return line.replace(/\r$/, '');
			}
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? 拼接字节数据(bufferedBytes, chunk) : chunk;
		}
	};
	const readPacket = async (timeoutMs = CONNECT_TIMEOUT_MS) => {
		const header = await withTimeout(readBytes(4), timeoutMs, 'SSTP read timeout');
		const length = readSstpUint16(header, 2) & 0x0fff;
		if (length < 4) throw new Error('Invalid SSTP packet length');
		return {
			isControl: (header[1] & 1) !== 0,
			body: length > 4 ? await withTimeout(readBytes(length - 4), timeoutMs, 'SSTP packet body read timeout') : SSTP_EMPTY_BYTES
		};
	};
	const buildSstpDataPacket = pppFrame => {
		const packetLength = 6 + pppFrame.byteLength;
		const packet = new Uint8Array(packetLength);
		packet.set([0x10, 0x00, ((packetLength >> 8) & 0x0f) | 0x80, packetLength & 0xff, 0xff, 0x03]);
		packet.set(pppFrame, 6);
		return packet;
	};
	const buildPppConfigurePacket = (protocol, code, id, options = []) => {
		const optionsLength = options.reduce((size, option) => size + 2 + option.data.byteLength, 0);
		const frame = new Uint8Array(6 + optionsLength);
		const view = new DataView(frame.buffer);
		view.setUint16(0, protocol);
		frame[2] = code;
		frame[3] = id;
		view.setUint16(4, 4 + optionsLength);
		options.reduce((offset, option) => {
			frame[offset] = option.type;
			frame[offset + 1] = 2 + option.data.byteLength;
			frame.set(option.data, offset + 2);
			return offset + 2 + option.data.byteLength;
		}, 6);
		return frame;
	};
	const parsePPPFrame = data => {
		const offset = data.byteLength >= 2 && data[0] === 0xff && data[1] === 0x03 ? 2 : 0;
		if (data.byteLength - offset < 4) return null;
		const protocol = readSstpUint16(data, offset);
		if (protocol === 0x0021) return { protocol, ipPacket: data.subarray(offset + 2) };
		if (data.byteLength - offset < 6) return null;
		return { protocol, code: data[offset + 2], id: data[offset + 3], payload: data.subarray(offset + 6), rawPacket: data.subarray(offset) };
	};
	const parsePppOptions = data => {
		const options = [];
		for (let offset = 0; offset + 2 <= data.byteLength;) {
			const type = data[offset];
			const length = data[offset + 1];
			if (length < 2 || offset + length > data.byteLength) break;
			options.push({ type, data: data.subarray(offset + 2, offset + length) });
			offset += length;
		}
		return options;
	};

	try {
		const serverHost = stripIPv6Brackets(proxy.hostname);
		const serverPort = proxy.port;
		socket = TCP连接({ hostname: serverHost, port: serverPort }, { secureTransport: 'on', allowHalfOpen: false });
		await withTimeout(socket.opened, CONNECT_TIMEOUT_MS, 'SSTP server connection timed out');
		reader = socket.readable.getReader();
		writer = socket.writable.getWriter();

		const displayHost = serverHost.includes(':') ? `[${serverHost}]` : serverHost;
		const httpRequest = textEncoder.encode(
			`SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n`
			+ `Host: ${Number(serverPort) === 443 ? displayHost : `${displayHost}:${serverPort}`}\r\n`
			+ 'Content-Length: 18446744073709551615\r\n'
			+ `SSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`
		);
		const encapsulatedProtocol = new Uint8Array(2);
		new DataView(encapsulatedProtocol.buffer).setUint16(0, 1);
		const maximumReceiveUnit = new Uint8Array(2);
		new DataView(maximumReceiveUnit.buffer).setUint16(0, 1500);
		const sstpConnectRequest = new Uint8Array(12 + encapsulatedProtocol.byteLength);
		const sstpConnectView = new DataView(sstpConnectRequest.buffer);
		sstpConnectRequest[0] = 0x10;
		sstpConnectRequest[1] = 0x01;
		sstpConnectView.setUint16(2, sstpConnectRequest.byteLength | 0x8000);
		sstpConnectView.setUint16(4, 0x0001);
		sstpConnectView.setUint16(6, 1);
		sstpConnectRequest[9] = 1;
		sstpConnectView.setUint16(10, 4 + encapsulatedProtocol.byteLength);
		sstpConnectRequest.set(encapsulatedProtocol, 12);

		await withTimeout(writer.write(拼接字节数据(
			httpRequest,
			sstpConnectRequest,
			buildSstpDataPacket(buildPppConfigurePacket(0xc021, 1, pppIdentifier++, [
				{ type: 1, data: maximumReceiveUnit }
			]))
		)), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake request timed out');

		const statusLine = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake timed out');
		for (; ;) {
			const line = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP header read timed out');
			if (line === '') break;
		}
		if (!/HTTP\/\d(?:\.\d)?\s+2\d\d/i.test(statusLine)) throw new Error(`SSTP HTTP handshake failed: ${statusLine || 'invalid status'}`);

		let localLcpAcked = false, peerLcpAcked = false, papRequired = false, papSent = false, papDone = false, ipcpStarted = false, ipcpFinished = false, sourceIp = null;
		const sendPapIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || !papRequired || papSent) return;
			if (proxy.username === null || proxy.password === null) throw new Error('SSTP server requires PAP authentication');
			const username = textEncoder.encode(proxy.username);
			const password = textEncoder.encode(proxy.password);
			if (username.byteLength > 255 || password.byteLength > 255) throw new Error('SSTP username/password is too long');
			const papLength = 6 + username.byteLength + password.byteLength;
			const frame = new Uint8Array(2 + papLength);
			const view = new DataView(frame.buffer);
			view.setUint16(0, 0xc023);
			frame[2] = 1;
			frame[3] = pppIdentifier++;
			view.setUint16(4, papLength);
			frame[6] = username.byteLength;
			frame.set(username, 7);
			frame[7 + username.byteLength] = password.byteLength;
			frame.set(password, 8 + username.byteLength);
			await withTimeout(writer.write(buildSstpDataPacket(frame)), CONNECT_TIMEOUT_MS, 'SSTP PAP authentication request timed out');
			papSent = true;
		};
		const startIpcpIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || ipcpStarted || (papRequired && !papDone)) return;
			await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
				{ type: 3, data: new Uint8Array(4) }
			]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP request timed out');
			ipcpStarted = true;
		};

		for (let round = 0; round < 50 && !ipcpFinished; round++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp) continue;

			if (ppp.protocol === 0xc021) {
				if (ppp.code === 1) {
					const authOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (authOption?.data?.byteLength >= 2) {
						const authProtocol = readSstpUint16(authOption.data);
						if (authProtocol !== 0xc023) throw new Error(`SSTP unsupported PPP authentication protocol: 0x${authProtocol.toString(16)}`);
						papRequired = true;
					}
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP LCP Configure-Ack timed out');
					peerLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				} else if (ppp.code === 2) {
					localLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				}
				continue;
			}

			if (ppp.protocol === 0xc023) {
				if (ppp.code === 2) {
					papDone = true;
					await startIpcpIfReady();
				} else if (ppp.code === 3) throw new Error('SSTP PAP authentication failed');
				continue;
			}

			if (ppp.protocol === 0x8021) {
				if (ppp.code === 1) {
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP IPCP Configure-Ack timed out');
					await startIpcpIfReady();
				} else if (ppp.code === 3) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) {
						sourceIp = [...addressOption.data].join('.');
						await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
							{ type: 3, data: addressOption.data }
						]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP address request timed out');
						ipcpStarted = true;
					}
				} else if (ppp.code === 2) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) sourceIp = [...addressOption.data].join('.');
					ipcpFinished = true;
				}
			}
		}
		if (!sourceIp) throw new Error('SSTP did not assign an IPv4 address');

		const target = stripIPv6Brackets(targetHost);
		/** @type {string | null} */
		let targetIp = isIPv4(target) ? target : null;
		if (!targetIp) {
			const records = await DoH查询(target, 'A');
			const recordData = records.find(item => item.type === 1 && isIPv4(item.data))?.data;
			targetIp = typeof recordData === 'string' ? recordData : null;
		}
		if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for SSTP`);

		const sourcePort = 10000 + (randomSstpUint16() % 50000);
		const sourceAddress = new Uint8Array(String(sourceIp || '').split('.').map(Number));
		const destinationAddress = new Uint8Array(String(targetIp || '').split('.').map(Number));
		let sequenceNumber = readSstpUint32(crypto.getRandomValues(new Uint8Array(4)));
		let acknowledgementNumber = 0;
		const ipHeaderTemplate = new Uint8Array(20);
		ipHeaderTemplate.set([0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 64, 6]);
		ipHeaderTemplate.set(sourceAddress, 12);
		ipHeaderTemplate.set(destinationAddress, 16);
		const tcpPseudoHeader = new Uint8Array(1432);
		tcpPseudoHeader.set(sourceAddress);
		tcpPseudoHeader.set(destinationAddress, 4);
		tcpPseudoHeader[9] = 6;
		const buildTcpFrame = (flags, payload = SSTP_EMPTY_BYTES) => {
			const bytes = 数据转Uint8Array(payload);
			const payloadLength = bytes.byteLength;
			const tcpLength = 20 + payloadLength;
			const ipLength = 20 + tcpLength;
			const sstpLength = 8 + ipLength;
			const frame = new Uint8Array(sstpLength);
			const view = new DataView(frame.buffer);
			frame.set([0x10, 0x00, ((sstpLength >> 8) & 0x0f) | 0x80, sstpLength & 0xff, 0xff, 0x03, 0x00, 0x21]);
			frame.set(ipHeaderTemplate, 8);
			view.setUint16(10, ipLength);
			view.setUint16(12, randomSstpUint16());
			view.setUint16(18, internetChecksum(frame, 8, 20));
			view.setUint16(28, sourcePort);
			view.setUint16(30, targetPort);
			view.setUint32(32, sequenceNumber);
			view.setUint32(36, acknowledgementNumber);
			frame[40] = 0x50;
			frame[41] = flags;
			view.setUint16(42, 65535);
			if (payloadLength) frame.set(bytes, 48);
			tcpPseudoHeader[10] = tcpLength >> 8;
			tcpPseudoHeader[11] = tcpLength & 0xff;
			tcpPseudoHeader.set(frame.subarray(28, 28 + tcpLength), 12);
			view.setUint16(44, internetChecksum(tcpPseudoHeader, 0, 12 + tcpLength));
			return frame;
		};
		const matchIncomingIpPacket = ipPacket => {
			if (ipPacket.byteLength < 40 || ipPacket[9] !== 6) return null;
			const ipHeaderLength = (ipPacket[0] & 0x0f) * 4;
			if (ipPacket.byteLength < ipHeaderLength + 20) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength) !== targetPort) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength + 2) !== sourcePort) return null;
			return {
				flags: ipPacket[ipHeaderLength + 13],
				sequence: readSstpUint32(ipPacket, ipHeaderLength + 4),
				payloadOffset: ipHeaderLength + ((ipPacket[ipHeaderLength + 12] >> 4) & 0x0f) * 4
			};
		};

		await withTimeout(writer.write(buildTcpFrame(0x02)), CONNECT_TIMEOUT_MS, 'SSTP TCP SYN write timed out');
		sequenceNumber = (sequenceNumber + 1) >>> 0;
		let tcpReady = false;
		for (let attempt = 0; attempt < 30; attempt++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp || ppp.protocol !== 0x0021) continue;
			const tcp = matchIncomingIpPacket(ppp.ipPacket);
			if (!tcp || (tcp.flags & 0x12) !== 0x12) continue;
			acknowledgementNumber = (tcp.sequence + 1) >>> 0;
			await withTimeout(writer.write(buildTcpFrame(0x10)), CONNECT_TIMEOUT_MS, 'SSTP TCP ACK write timed out');
			tcpReady = true;
			break;
		}
		if (!tcpReady) throw new Error('TCP handshake through SSTP timed out');

		/** @type {ReadableStreamDefaultController<Uint8Array> | null} */
		let streamController = null;
		const readable = new ReadableStream({
			start(controller) {
				streamController = controller;
			},
			cancel() {
				close();
			}
		});

		(async () => {
			try {
				let pendingChunks = [], pendingLength = 0;
				const flush = () => {
					if (!pendingLength) return;
					if (!streamController) throw new Error('SSTP readable stream is not ready');
					streamController.enqueue(pendingChunks.length === 1 ? pendingChunks[0] : 拼接字节数据(...pendingChunks));
					pendingChunks = [];
					pendingLength = 0;
					writer.write(buildTcpFrame(0x10)).catch(() => { });
				};

				for (; ;) {
					const packet = await readPacket(60000);
					if (packet.isControl) continue;
					const ppp = parsePPPFrame(packet.body);
					if (!ppp || ppp.protocol !== 0x0021) continue;
					const incoming = matchIncomingIpPacket(ppp.ipPacket);
					if (!incoming) continue;

					if (incoming.payloadOffset < ppp.ipPacket.byteLength) {
						const payload = ppp.ipPacket.subarray(incoming.payloadOffset);
						if (payload.byteLength) {
							acknowledgementNumber = (incoming.sequence + payload.byteLength) >>> 0;
							pendingChunks.push(new Uint8Array(payload));
							pendingLength += payload.byteLength;
						}
					}

					if (incoming.flags & 0x01) {
						flush();
						acknowledgementNumber = (acknowledgementNumber + 1) >>> 0;
						writer.write(buildTcpFrame(0x11)).catch(() => { });
						const controller = streamController;
						if (controller) {
							try { controller.close() } catch (e) { }
						}
						close();
						return;
					}

					if (bufferedBytes.byteLength < 4 || pendingLength >= 32768) flush();
				}
			} catch (error) {
				const controller = streamController;
				if (controller) {
					try { controller.error(error) } catch (e) { }
				}
				settleClosed(rejectClosed, error);
				try { socket?.close?.() } catch (e) { }
			}
		})();

		const writable = new WritableStream({
			async write(chunk) {
				const bytes = 数据转Uint8Array(chunk);
				if (!bytes.byteLength) return;
				if (bytes.byteLength <= SSTP_TCP_MSS) {
					await writer.write(buildTcpFrame(0x18, bytes));
					sequenceNumber = (sequenceNumber + bytes.byteLength) >>> 0;
					return;
				}
				const frames = [];
				for (let offset = 0; offset < bytes.byteLength; offset += SSTP_TCP_MSS) {
					const segment = bytes.subarray(offset, Math.min(offset + SSTP_TCP_MSS, bytes.byteLength));
					frames.push(buildTcpFrame(0x18, segment));
					sequenceNumber = (sequenceNumber + segment.byteLength) >>> 0;
				}
				await writer.write(拼接字节数据(...frames));
			},
			close() {
				return writer.write(buildTcpFrame(0x11)).catch(() => { });
			},
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			}
		});

		return { readable, writable, closed, close };
	} catch (error) {
		close();
		throw error;
	}
}
//////////////////////////////////////////////////功能性函数///////////////////////////////////////////////
/**
 * 带秘钥的 Base64 编码
 * @param {string} plaintext - 原始明文字符串
 * @param {string} secret - 秘钥字符串（如 "KEY123"）
 * @returns {string} 经过秘钥处理的 Base64 字符串
 */
function base64SecretEncode(plaintext, secret) {
	const encoder = new TextEncoder();
	const data = encoder.encode(plaintext);
	const key = encoder.encode(secret);
	const mixed = new Uint8Array(data.length);

	for (let i = 0; i < data.length; i++) {
		mixed[i] = data[i] ^ key[i % key.length];
	}

	// 将 Uint8Array 转换为可被 btoa 处理的字符串
	let binary = '';
	for (let i = 0; i < mixed.length; i++) {
		binary += String.fromCharCode(mixed[i]);
	}
	return btoa(binary);
}

/**
 * 带秘钥的 Base64 解码
 * @param {string} encoded - 经秘钥处理过的 Base64 字符串
 * @param {string} secret - 秘钥字符串（必须与编码时相同）
 * @returns {string} 解码后的原始明文字符串
 */
function base64SecretDecode(encoded, secret) {
	const binary = atob(encoded);
	const mixed = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		mixed[i] = binary.charCodeAt(i);
	}

	const encoder = new TextEncoder();
	const key = encoder.encode(secret);
	const data = new Uint8Array(mixed.length);

	for (let i = 0; i < mixed.length; i++) {
		data[i] = mixed[i] ^ key[i % key.length];
	}

	const decoder = new TextDecoder();
	return decoder.decode(data);
}

function 获取传输协议配置(配置 = {}) {
	const 是gRPC = 配置.传输协议 === 'grpc';
	const { 头: 本机Padding头, 键: 本机Padding键 } = 获取叉HTTPPadding标识(配置.UUID);
	const 叉混淆JSON = {
		"xPaddingObfsMode": true,
		"xPaddingMethod": "tokenish",
		"xPaddingPlacement": "queryInHeader",
		"xPaddingHeader": 本机Padding头,
		"xPaddingKey": 本机Padding键
	};
	return {
		type: 是gRPC ? (配置.gRPC模式 === 'multi' ? 'grpc&mode=multi' : 'grpc&mode=gun') : (配置.传输协议 === 'xhttp' ? `xhttp&mode=stream-one&extra=${encodeURIComponent(JSON.stringify(叉混淆JSON))}` : 'ws'),
		路径字段名: 是gRPC ? 'serviceName' : 'path',
		域名字段名: 是gRPC ? 'authority' : 'host'
	};
}

function 获取传输路径参数值(配置 = {}, 节点路径 = '/', 作为优选订阅生成器 = false) {
	const 路径值 = 作为优选订阅生成器 ? '/' : (配置.随机路径 ? 随机路径(节点路径) : 节点路径);
	if (配置.传输协议 !== 'grpc') return 路径值;
	return 路径值.split('?')[0] || '/';
}

function log(...args) {
	if (调试日志打印) console.log(...args);
}

function Clash订阅配置文件热补丁(Clash_原始订阅内容, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const ECH启用 = Boolean(config_JSON?.ECH);
	const HOSTS = Array.isArray(config_JSON?.HOSTS) ? [...config_JSON.HOSTS] : [];
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || null;
	const ECH_DNS = config_JSON?.ECHConfig?.DNS;
	const 需要处理ECH = Boolean(uuid && ECH启用);
	const gRPCUserAgent = (typeof config_JSON?.gRPCUserAgent === 'string' && config_JSON.gRPCUserAgent.trim()) ? config_JSON.gRPCUserAgent.trim() : null;
	const 需要处理gRPC = config_JSON?.传输协议 === "grpc" && Boolean(gRPCUserAgent);
	const gRPCUserAgentYAML = gRPCUserAgent ? JSON.stringify(gRPCUserAgent) : null;
	let clash_yaml = Clash_原始订阅内容.replace(/mode:\s*Rule\b/g, 'mode: rule');

	const baseDnsBlock = `dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - 114.114.114.114
  use-hosts: true
  nameserver:
    - https://sm2.doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  fallback:
    - 8.8.4.4
    - 208.67.220.220
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
      - 127.0.0.1/32
      - 0.0.0.0/32
    domain:
      - '+.google.com'
      - '+.facebook.com'
      - '+.youtube.com'
`;

	const 添加InlineGrpcUserAgent = (text) => text.replace(/grpc-opts:\s*\{([\s\S]*?)\}/i, (all, inner) => {
		if (/grpc-user-agent\s*:/i.test(inner)) return all;
		let content = inner.trim();
		if (content.endsWith(',')) content = content.slice(0, -1).trim();
		const patchedContent = content ? `${content}, grpc-user-agent: ${gRPCUserAgentYAML}` : `grpc-user-agent: ${gRPCUserAgentYAML}`;
		return `grpc-opts: {${patchedContent}}`;
	});
	const 匹配到gRPC网络 = (text) => /(?:^|[,{])\s*network:\s*(?:"grpc"|'grpc'|grpc)(?=\s*(?:[,}\n#]|$))/mi.test(text);
	const 获取代理类型 = (nodeText) => nodeText.match(/type:\s*(\w+)/)?.[1] || 'vl' + 'ess';
	const 获取凭据值 = (nodeText, isFlowStyle) => {
		const credentialField = 获取代理类型(nodeText) === 'trojan' ? 'password' : 'uuid';
		const pattern = new RegExp(`${credentialField}:\\s*${isFlowStyle ? '([^,}\\n]+)' : '([^\\n]+)'}`);
		return nodeText.match(pattern)?.[1]?.trim() || null;
	};
	const 插入NameserverPolicy = (yaml, hostsEntries) => {
		if (/^\s{2}nameserver-policy:\s*(?:\n|$)/m.test(yaml)) {
			return yaml.replace(/^(\s{2}nameserver-policy:\s*\n)/m, `$1${hostsEntries}\n`);
		}
		const lines = yaml.split('\n');
		let dnsBlockEndIndex = -1;
		let inDnsBlock = false;
		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			if (/^dns:\s*$/.test(line)) {
				inDnsBlock = true;
				continue;
			}
			if (inDnsBlock && /^[a-zA-Z]/.test(line)) {
				dnsBlockEndIndex = i;
				break;
			}
		}
		const nameserverPolicyBlock = `  nameserver-policy:\n${hostsEntries}`;
		if (dnsBlockEndIndex !== -1) lines.splice(dnsBlockEndIndex, 0, nameserverPolicyBlock);
		else lines.push(nameserverPolicyBlock);
		return lines.join('\n');
	};
	const 添加Flow格式gRPCUserAgent = (nodeText) => {
		if (!匹配到gRPC网络(nodeText) || /grpc-user-agent\s*:/i.test(nodeText)) return nodeText;
		if (/grpc-opts:\s*\{/i.test(nodeText)) return 添加InlineGrpcUserAgent(nodeText);
		return nodeText.replace(/\}(\s*)$/, `, grpc-opts: {grpc-user-agent: ${gRPCUserAgentYAML}}}$1`);
	};
	const 添加Block格式gRPCUserAgent = (nodeLines, topLevelIndent) => {
		const 顶级缩进 = ' '.repeat(topLevelIndent);
		let grpcOptsIndex = -1;
		for (let idx = 0; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx];
			if (!line.trim()) continue;
			const indent = line.search(/\S/);
			if (indent !== topLevelIndent) continue;
			if (/^\s*grpc-opts:\s*(?:#.*)?$/.test(line) || /^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(line)) {
				grpcOptsIndex = idx;
				break;
			}
		}
		if (grpcOptsIndex === -1) {
			let insertIndex = -1;
			for (let j = nodeLines.length - 1; j >= 0; j--) {
				if (nodeLines[j].trim()) {
					insertIndex = j;
					break;
				}
			}
			if (insertIndex >= 0) nodeLines.splice(insertIndex + 1, 0, `${顶级缩进}grpc-opts:`, `${顶级缩进}  grpc-user-agent: ${gRPCUserAgentYAML}`);
			return nodeLines;
		}
		const grpcLine = nodeLines[grpcOptsIndex];
		if (/^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(grpcLine)) {
			if (!/grpc-user-agent\s*:/i.test(grpcLine)) nodeLines[grpcOptsIndex] = 添加InlineGrpcUserAgent(grpcLine);
			return nodeLines;
		}
		let blockEndIndex = nodeLines.length;
		let 子级缩进 = topLevelIndent + 2;
		let 已有gRPCUserAgent = false;
		for (let idx = grpcOptsIndex + 1; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx];
			const trimmed = line.trim();
			if (!trimmed) continue;
			const indent = line.search(/\S/);
			if (indent <= topLevelIndent) {
				blockEndIndex = idx;
				break;
			}
			if (indent > topLevelIndent && 子级缩进 === topLevelIndent + 2) 子级缩进 = indent;
			if (/^grpc-user-agent\s*:/.test(trimmed)) {
				已有gRPCUserAgent = true;
				break;
			}
		}
		if (!已有gRPCUserAgent) nodeLines.splice(blockEndIndex, 0, `${' '.repeat(子级缩进)}grpc-user-agent: ${gRPCUserAgentYAML}`);
		return nodeLines;
	};
	const 添加Block格式ECHOpts = (nodeLines, topLevelIndent) => {
		let insertIndex = -1;
		for (let j = nodeLines.length - 1; j >= 0; j--) {
			if (nodeLines[j].trim()) {
				insertIndex = j;
				break;
			}
		}
		if (insertIndex < 0) return nodeLines;
		const indent = ' '.repeat(topLevelIndent);
		const echOptsLines = [`${indent}ech-opts:`, `${indent}  enable: true`];
		if (ECH_SNI) echOptsLines.push(`${indent}  query-server-name: ${ECH_SNI}`);
		nodeLines.splice(insertIndex + 1, 0, ...echOptsLines);
		return nodeLines;
	};

	if (!/^dns:\s*(?:\n|$)/m.test(clash_yaml)) clash_yaml = baseDnsBlock + clash_yaml;
	if (ECH_SNI && !HOSTS.includes(ECH_SNI)) HOSTS.push(ECH_SNI);

	if (ECH启用 && HOSTS.length > 0) {
		const hostsEntries = HOSTS.map(host => `    "${host}": ${ECH_DNS ? ECH_DNS : ''}`).join('\n');
		clash_yaml = 插入NameserverPolicy(clash_yaml, hostsEntries);
	}

	if (!需要处理ECH && !需要处理gRPC) return clash_yaml;

	const lines = clash_yaml.split('\n');
	const processedLines = [];
	let i = 0;

	while (i < lines.length) {
		const line = lines[i];
		const trimmedLine = line.trim();

		if (trimmedLine.startsWith('- {')) {
			let fullNode = line;
			let braceCount = (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
			while (braceCount > 0 && i + 1 < lines.length) {
				i++;
				fullNode += '\n' + lines[i];
				braceCount += (lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length;
			}
			if (需要处理gRPC) fullNode = 添加Flow格式gRPCUserAgent(fullNode);
			if (需要处理ECH && 获取凭据值(fullNode, true) === uuid.trim()) {
				fullNode = fullNode.replace(/\}(\s*)$/, `, ech-opts: {enable: true${ECH_SNI ? `, query-server-name: ${ECH_SNI}` : ''}}}$1`);
			}
			processedLines.push(fullNode);
			i++;
		} else if (trimmedLine.startsWith('- name:')) {
			let nodeLines = [line];
			let baseIndent = line.search(/\S/);
			let topLevelIndent = baseIndent + 2;
			i++;
			while (i < lines.length) {
				const nextLine = lines[i];
				const nextTrimmed = nextLine.trim();
				if (!nextTrimmed) {
					nodeLines.push(nextLine);
					i++;
					break;
				}
				const nextIndent = nextLine.search(/\S/);
				if (nextIndent <= baseIndent && nextTrimmed.startsWith('- ')) {
					break;
				}
				if (nextIndent < baseIndent && nextTrimmed) {
					break;
				}
				nodeLines.push(nextLine);
				i++;
			}
			let nodeText = nodeLines.join('\n');
			if (需要处理gRPC && 匹配到gRPC网络(nodeText)) {
				nodeLines = 添加Block格式gRPCUserAgent(nodeLines, topLevelIndent);
				nodeText = nodeLines.join('\n');
			}
			if (需要处理ECH && 获取凭据值(nodeText, false) === uuid.trim()) nodeLines = 添加Block格式ECHOpts(nodeLines, topLevelIndent);
			processedLines.push(...nodeLines);
		} else {
			processedLines.push(line);
			i++;
		}
	}

	return processedLines.join('\n');
}

async function Singbox订阅配置文件热补丁(SingBox_原始订阅内容, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const fingerprint = config_JSON?.Fingerprint || "chrome";
	const ECH启用 = Boolean(config_JSON?.ECH);
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || "cloudflare-ech.com";
	const sb_json_text = SingBox_原始订阅内容.replace('1.1.1.1', '8.8.8.8').replace('1.0.0.1', '8.8.4.4');
	try {
		const config = JSON.parse(sb_json_text);
		const 数组化 = value => value === undefined || value === null ? [] : (Array.isArray(value) ? value : [value]);
		const 确保Route = () => config.route = config.route && typeof config.route === 'object' ? config.route : {};
		const 获取DNS规则服务器 = rule => rule && typeof rule === 'object' && !Array.isArray(rule) && typeof rule.server === 'string' ? rule.server : null;
		const 添加规则集 = (type, code) => {
			if (!code || typeof code !== 'string') return null;
			const route = 确保Route(), tag = `${type}-${code}`, ruleSet = Array.isArray(route.rule_set) ? route.rule_set : 数组化(route.rule_set);
			if (!ruleSet.some(item => item?.tag === tag)) {
				const legacyOptions = type === 'geoip' ? route.geoip : route.geosite;
				ruleSet.push({ tag, type: 'remote', format: 'binary', url: `https://raw.githubusercontent.com/SagerNet/sing-${type}/rule-set/${tag}.srs`, ...(legacyOptions?.download_detour ? { download_detour: legacyOptions.download_detour } : {}) });
				config.experimental = config.experimental && typeof config.experimental === 'object' ? config.experimental : {};
				config.experimental.cache_file = config.experimental.cache_file && typeof config.experimental.cache_file === 'object' ? config.experimental.cache_file : {};
				config.experimental.cache_file.enabled ??= true;
			}
			route.rule_set = ruleSet;
			return tag;
		};

		const 迁移规则集字段 = rule => {
			if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return rule;
			if (rule.type === 'logical' && Array.isArray(rule.rules)) {
				rule.rules = rule.rules.map(迁移规则集字段);
				return rule;
			}
			const tags = [];
			for (const geoip of 数组化(rule.geoip)) {
				if (typeof geoip !== 'string') continue;
				if (geoip.toLowerCase() === 'private') rule.ip_is_private = true;
				else tags.push(添加规则集('geoip', geoip));
			}
			for (const sourceGeoip of 数组化(rule.source_geoip)) {
				if (typeof sourceGeoip !== 'string') continue;
				tags.push(添加规则集('geoip', sourceGeoip));
				rule.rule_set_ip_cidr_match_source = true;
			}
			for (const geosite of 数组化(rule.geosite)) if (typeof geosite === 'string') tags.push(添加规则集('geosite', geosite));
			if (tags.length) rule.rule_set = [...new Set([...数组化(rule.rule_set), ...tags].filter(Boolean))];
			delete rule.geoip;
			delete rule.source_geoip;
			delete rule.geosite;
			return rule;
		};

		const 迁移DNS规则 = (rule, rcodeServerMap) => {
			rule = 迁移规则集字段(rule);
			if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return rule;
			if (rule.type === 'logical' && Array.isArray(rule.rules)) {
				rule.rules = rule.rules.map(childRule => 迁移DNS规则(childRule, rcodeServerMap));
				return rule;
			}
			const serverTag = 获取DNS规则服务器(rule);
			if (serverTag && rcodeServerMap.has(serverTag)) {
				for (const key of ['server', 'strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']) delete rule[key];
				rule.action = 'predefined';
				rule.rcode = rcodeServerMap.get(serverTag);
			} else if (serverTag && !rule.action) rule.action = 'route';
			return rule;
		};

		if (Array.isArray(config.inbounds)) {
			for (const inbound of config.inbounds) {
				if (!inbound || typeof inbound !== 'object' || inbound.type !== 'tun') continue;
				for (const migration of [
					{ targetKey: 'address', sourceKeys: ['inet4_address', 'inet6_address'] },
					{ targetKey: 'route_address', sourceKeys: ['inet4_route_address', 'inet6_route_address'] },
					{ targetKey: 'route_exclude_address', sourceKeys: ['inet4_route_exclude_address', 'inet6_route_exclude_address'] }
				]) {
					const values = 数组化(inbound[migration.targetKey]);
					for (const sourceKey of migration.sourceKeys) values.push(...数组化(inbound[sourceKey]));
					if (values.length) inbound[migration.targetKey] = [...new Set(values)];
					for (const sourceKey of migration.sourceKeys) delete inbound[sourceKey];
				}
				if (inbound.tag) {
					const addedRules = [];
					if (inbound.domain_strategy) addedRules.push({ inbound: inbound.tag, action: 'resolve', strategy: inbound.domain_strategy });
					if (inbound.sniff) {
						const sniffRule = { inbound: inbound.tag, action: 'sniff' };
						if (inbound.sniff_timeout) sniffRule.timeout = inbound.sniff_timeout;
						addedRules.push(sniffRule);
					}
					if (addedRules.length) {
						const route = 确保Route();
						route.rules = [...addedRules, ...数组化(route.rules)];
					}
				}
				delete inbound.sniff;
				delete inbound.sniff_timeout;
				delete inbound.domain_strategy;
			}
		}

		if (config?.route && typeof config.route === 'object' && Array.isArray(config.route.rules)) {
			const 修补路由规则 = rule => {
				rule = 迁移规则集字段(rule);
				if (rule?.type === 'logical' && Array.isArray(rule.rules)) rule.rules = rule.rules.map(修补路由规则);
				else if (rule && typeof rule === 'object' && !Array.isArray(rule) && rule.outbound && !rule.action) rule.action = 'route';
				return rule;
			};
			config.route.rules = config.route.rules.map(修补路由规则);
		}

		const dns = config?.dns;
		if (dns && typeof dns === 'object') {
			const legacyFakeIP = dns.fakeip && typeof dns.fakeip === 'object' ? dns.fakeip : null;
			const rcodeServerMap = new Map();
			const DNS地址协议类型 = { 'tcp:': 'tcp', 'udp:': 'udp', 'tls:': 'tls', 'quic:': 'quic', 'https:': 'https', 'h3:': 'h3' };
			const RCode映射 = { success: 'NOERROR', format_error: 'FORMERR', server_failure: 'SERVFAIL', name_error: 'NXDOMAIN', not_implemented: 'NOTIMP', refused: 'REFUSED' };
			let hasFakeIPServer = false;

			if (Array.isArray(dns.servers)) {
				const migratedServers = [];
				for (const originalServer of dns.servers) {
					if (!originalServer || typeof originalServer !== 'object' || Array.isArray(originalServer)) {
						migratedServers.push(originalServer);
						continue;
					}

					const server = { ...originalServer };
					let parsedAddress = null, parsedRCode = '', rawAddress = typeof server.address === 'string' ? server.address.trim() : '';
					if (rawAddress) {
						const lowerAddress = rawAddress.toLowerCase();
						if (lowerAddress === 'fakeip') parsedAddress = { type: 'fakeip' };
						else if (lowerAddress === 'local') parsedAddress = { type: 'local' };
						else if (lowerAddress.startsWith('rcode://')) {
							parsedAddress = { type: 'rcode' };
							parsedRCode = rawAddress.slice('rcode://'.length).toLowerCase();
						}
						else if (lowerAddress.startsWith('dhcp://')) {
							const dhcpInterface = rawAddress.slice('dhcp://'.length);
							parsedAddress = dhcpInterface && dhcpInterface.toLowerCase() !== 'auto' ? { type: 'dhcp', interface: dhcpInterface } : { type: 'dhcp' };
						} else {
							try {
								const addressURL = new URL(rawAddress);
								const type = DNS地址协议类型[addressURL.protocol.toLowerCase()];
								if (type) {
									const parsedServer = addressURL.hostname?.startsWith('[') && addressURL.hostname.endsWith(']') ? addressURL.hostname.slice(1, -1) : addressURL.hostname;
									parsedAddress = {
										type,
										server: parsedServer || addressURL.host || rawAddress,
										...(addressURL.port ? { server_port: Number(addressURL.port) } : {}),
										...((type === 'https' || type === 'h3') && addressURL.pathname && addressURL.pathname !== '/dns-query' ? { path: addressURL.pathname } : {})
									};
								}
							} catch (_) { }
							if (!parsedAddress) parsedAddress = { type: 'udp', server: rawAddress };
						}
					}

					if (parsedAddress?.type === 'rcode') {
						const rcode = RCode映射[parsedRCode] || 'NOERROR';
						if (typeof server.tag === 'string' && server.tag) {
							rcodeServerMap.set(server.tag, rcode);
							rcodeServerMap.set(server.tag.startsWith('dns_') ? server.tag.slice(4) : `dns_${server.tag}`, rcode);
						}
						continue;
					}

					if (parsedAddress) {
						delete server.address;
						Object.assign(server, parsedAddress);
					}
					if (server.address_resolver !== undefined && server.domain_resolver === undefined) server.domain_resolver = server.address_resolver;
					if (server.address_strategy !== undefined && server.domain_strategy === undefined) server.domain_strategy = server.address_strategy;
					delete server.address_resolver;
					delete server.address_strategy;
					if (server.detour === 'DIRECT') delete server.detour;

					if (server.type === 'fakeip') {
						hasFakeIPServer = true;
						if (legacyFakeIP) {
							for (const key of ['inet4_range', 'inet6_range']) {
								if (legacyFakeIP[key] !== undefined && server[key] === undefined) server[key] = legacyFakeIP[key];
							}
						}
					}
					migratedServers.push(server);
				}
				dns.servers = migratedServers;
			}

			if (legacyFakeIP && !hasFakeIPServer && legacyFakeIP.enabled !== false) {
				const fakeIPServer = { type: 'fakeip', tag: 'fakeip' };
				for (const rule of Array.isArray(dns.rules) ? dns.rules : []) {
					const serverTag = 获取DNS规则服务器(rule);
					if (serverTag && serverTag.toLowerCase().includes('fakeip')) {
						fakeIPServer.tag = serverTag;
						break;
					}
				}
				for (const key of ['inet4_range', 'inet6_range']) {
					if (legacyFakeIP[key] !== undefined) fakeIPServer[key] = legacyFakeIP[key];
				}
				if (Array.isArray(dns.servers)) dns.servers.push(fakeIPServer);
				else dns.servers = [fakeIPServer];
			}

			if (Array.isArray(dns.rules)) {
				const migratedRules = [];
				for (const rule of dns.rules) {
					const serverTag = 获取DNS规则服务器(rule);
					const outbound = 数组化(rule?.outbound);
					const DNS路由选项字段 = new Set(['outbound', 'server', 'action', 'strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']);
					const isOutboundAnyDNSRule = rule && typeof rule === 'object' && !Array.isArray(rule) && rule.type !== 'logical'
						&& serverTag && outbound.includes('any') && Object.keys(rule).every(key => DNS路由选项字段.has(key));
					if (isOutboundAnyDNSRule) {
						const route = 确保Route();
						if (route.default_domain_resolver === undefined) {
							const resolver = { server: serverTag };
							for (const key of ['strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']) {
								if (rule[key] !== undefined) resolver[key] = rule[key];
							}
							route.default_domain_resolver = Object.keys(resolver).length === 1 ? resolver.server : resolver;
						}
						continue;
					}
					migratedRules.push(迁移DNS规则(rule, rcodeServerMap));
				}
				dns.rules = migratedRules;
			}

			delete dns.fakeip;
			delete dns.independent_cache;
		}

		if (config?.route && typeof config.route === 'object') {
			delete config.route.geoip;
			delete config.route.geosite;
		}
		if (config?.ntp?.detour === 'DIRECT') delete config.ntp.detour;

		if (Array.isArray(config.outbounds)) {
			const outboundTags = new Set(config.outbounds.map(outbound => outbound?.tag).filter(Boolean));
			const 引用REJECT = value => value === 'REJECT' || (value && typeof value === 'object' && (Array.isArray(value) ? value.some(引用REJECT) : Object.values(value).some(引用REJECT)));
			if (!outboundTags.has('REJECT') && 引用REJECT({ outbounds: config.outbounds, route: config.route })) config.outbounds.push({ type: 'block', tag: 'REJECT' });
		}

		// --- UUID 匹配节点的 TLS 热补丁 (utls & ech) ---
		if (uuid) {
			config.outbounds?.forEach(outbound => {
				// 仅处理包含 uuid 或 password 且匹配的节点
				if ((outbound.uuid && outbound.uuid === uuid) || (outbound.password && outbound.password === uuid)) {
					// 确保 tls 对象存在
					if (!outbound.tls) {
						outbound.tls = { enabled: true };
					}

					// 添加/更新 utls 配置
					if (fingerprint) {
						outbound.tls.utls = {
							enabled: true,
							fingerprint: fingerprint
						};
					}

					// 如果提供了 ech_config，添加/更新 ech 配置
					if (ECH启用) {
						outbound.tls.ech = {
							enabled: true,
							query_server_name: ECH_SNI,// 等待 1.13.0+ 版本上线
							//config: `-----BEGIN ECH CONFIGS-----\n${ech_config}\n-----END ECH CONFIGS-----`
						};
					}
				}
			});
		}

		return JSON.stringify(config, null, 2);
	} catch (e) {
		console.error("اصلاح خودکار پیکربندی Sing-box ناموفق بود:", e);
		return JSON.stringify(JSON.parse(sb_json_text), null, 2);
	}
}

function Surge订阅配置文件热补丁(content, url, config_JSON) {
	const 每行内容 = content.includes('\r\n') ? content.split('\r\n') : content.split('\n');
	const 完整节点路径 = config_JSON.随机路径 ? 随机路径(config_JSON.完整节点路径) : config_JSON.完整节点路径;
	let 输出内容 = "";
	for (let x of 每行内容) {
		if (x.includes('= tro' + 'jan,') && !x.includes('ws=true') && !x.includes('ws-path=')) {
			const host = x.split("sni=")[1].split(",")[0];
			const 备改内容 = `sni=${host}, skip-cert-verify=${config_JSON.跳过证书验证}`;
			const 正确内容 = `sni=${host}, skip-cert-verify=${config_JSON.跳过证书验证}, ws=true, ws-path=${完整节点路径.replace(/,/g, '%2C')}, ws-headers=Host:"${host}"`;
			输出内容 += x.replace(new RegExp(备改内容, 'g'), 正确内容).replace("[", "").replace("]", "") + '\n';
		} else {
			输出内容 += x + '\n';
		}
	}

	输出内容 = `#!MANAGED-CONFIG ${url} interval=${config_JSON.优选订阅生成.SUBUpdateTime * 60 * 60} strict=false` + 输出内容.substring(输出内容.indexOf('\n'));
	return 输出内容;
}

async function 请求日志记录(env, request, 访问IP, 请求类型 = "Get_SUB", config_JSON, 是否写入KV日志 = true) {
	try {
		const 当前时间 = new Date();
		const 日志内容 = { TYPE: 请求类型, IP: 访问IP, ASN: `AS${request.cf.asn || '0'} ${request.cf.asOrganization || 'Unknown'}`, CC: `${request.cf.country || 'N/A'} ${request.cf.city || 'N/A'}`, URL: request.url, UA: request.headers.get('User-Agent') || 'Unknown', TIME: 当前时间.getTime() };
		if (config_JSON.TG.启用) {
			try {
				const TG_TXT = await env.KV.get('tg.json');
				const TG_JSON = JSON.parse(TG_TXT);
				if (TG_JSON?.BotToken && TG_JSON?.ChatID) {
					const 请求时间 = new Date(日志内容.TIME).toLocaleString('fa-IR-u-ca-persian', { timeZone: 'Asia/Tehran' });
					const 请求URL = new URL(日志内容.URL);
					const msg = `<b>#${HTML转义(config_JSON.优选订阅生成.SUBNAME)} · گزارش رویداد</b>\n\n` +
						`📌 <b>نوع:</b> #${({ Get_SUB: 'دریافت_اشتراک', Get_Best_SUB: 'دریافت_فهرست_بهینه', Admin_Login: 'ورود_به_پنل', Save_Config: 'ذخیره_تنظیمات', Save_Custom_IPs: 'ذخیره_فهرست_سفارشی', Init_Config: 'بازنشانی_تنظیمات' })[日志内容.TYPE] || 日志内容.TYPE}\n` +
						`🌐 <b>آی‌پی:</b> <code>${HTML转义(日志内容.IP)}</code>\n` +
						`📍 <b>موقعیت:</b> ${HTML转义(日志内容.CC)}\n` +
						`🏢 <b>شبکه:</b> ${HTML转义(日志内容.ASN)}\n` +
						`🔗 <b>دامنه:</b> <code>${HTML转义(请求URL.host)}</code>\n` +
						`🔍 <b>مسیر:</b> <code>${HTML转义((请求URL.pathname + 请求URL.search).replace(/token=[^&]+/, 'token=…'))}</code>\n` +
						`🤖 <b>UA:</b> <code>${HTML转义(日志内容.UA)}</code>\n` +
						`📅 <b>زمان:</b> ${请求时间}\n` +
						`${config_JSON.CF.Usage.success ? `📊 <b>مصرف درخواست‌ها:</b> ${config_JSON.CF.Usage.total}/${config_JSON.CF.Usage.max} <b>${((config_JSON.CF.Usage.total / config_JSON.CF.Usage.max) * 100).toFixed(2)}%</b>\n` : ''}`;
					await fetch(`https://api.telegram.org/bot${TG_JSON.BotToken}/sendMessage?chat_id=${encodeURIComponent(TG_JSON.ChatID)}&parse_mode=HTML&text=${encodeURIComponent(msg)}`, {
						method: 'GET',
						headers: {
							'Accept': 'text/html,application/xhtml+xml,application/xml;',
							'Accept-Encoding': 'gzip, deflate, br',
							'User-Agent': 日志内容.UA || 'Unknown',
						}
					});
				}
			} catch (error) { console.error(`خطا در خواندن tg.json: ${error.message}`) }
		}
		是否写入KV日志 = ['1', 'true'].includes(env.OFF_LOG) ? false : 是否写入KV日志;
		if (!是否写入KV日志) return;
		let 日志数组 = [];
		const 现有日志 = await env.KV.get('log.json'), KV容量限制 = 4;//MB
		if (现有日志) {
			try {
				日志数组 = JSON.parse(现有日志);
				if (!Array.isArray(日志数组)) { 日志数组 = [日志内容] }
				else if (请求类型 !== "Get_SUB") {
					const 三十分钟前时间戳 = 当前时间.getTime() - 30 * 60 * 1000;
					if (日志数组.some(log => log.TYPE !== "Get_SUB" && log.IP === 访问IP && log.URL === request.url && log.UA === (request.headers.get('User-Agent') || 'Unknown') && log.TIME >= 三十分钟前时间戳)) return;
					日志数组.push(日志内容);
					while (JSON.stringify(日志数组, null, 2).length > KV容量限制 * 1024 * 1024 && 日志数组.length > 0) 日志数组.shift();
				} else {
					日志数组.push(日志内容);
					while (JSON.stringify(日志数组, null, 2).length > KV容量限制 * 1024 * 1024 && 日志数组.length > 0) 日志数组.shift();
				}
			} catch (e) { 日志数组 = [日志内容] }
		} else { 日志数组 = [日志内容] }
		await env.KV.put('log.json', JSON.stringify(日志数组, null, 2));
	} catch (error) { console.error(`ثبت گزارش ناموفق بود: ${error.message}`) }
}

function 掩码敏感信息(文本, 前缀长度 = 3, 后缀长度 = 2) {
	if (!文本 || typeof 文本 !== 'string') return 文本;
	if (文本.length <= 前缀长度 + 后缀长度) return 文本; // 如果长度太短，直接返回

	const 前缀 = 文本.slice(0, 前缀长度);
	const 后缀 = 文本.slice(-后缀长度);
	const 星号数量 = 文本.length - 前缀长度 - 后缀长度;

	return `${前缀}${'*'.repeat(星号数量)}${后缀}`;
}

async function MD5MD5(文本) {
	const 编码器 = new TextEncoder();

	const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
	const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希));
	const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

	const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
	const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希));
	const 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

	return 第二次十六进制.toLowerCase();
}

function 随机路径(完整节点路径 = "/") {
	const 常用路径目录 = ["about", "account", "acg", "act", "activity", "ad", "ads", "ajax", "album", "albums", "anime", "api", "app", "apps", "archive", "archives", "article", "articles", "ask", "auth", "avatar", "bbs", "bd", "blog", "blogs", "book", "books", "bt", "buy", "cart", "category", "categories", "cb", "channel", "channels", "chat", "china", "city", "class", "classify", "clip", "clips", "club", "cn", "code", "collect", "collection", "comic", "comics", "community", "company", "config", "contact", "content", "course", "courses", "cp", "data", "detail", "details", "dh", "directory", "discount", "discuss", "dl", "dload", "doc", "docs", "document", "documents", "doujin", "download", "downloads", "drama", "edu", "en", "ep", "episode", "episodes", "event", "events", "f", "faq", "favorite", "favourites", "favs", "feedback", "file", "files", "film", "films", "forum", "forums", "friend", "friends", "game", "games", "gif", "go", "go.html", "go.php", "group", "groups", "help", "home", "hot", "htm", "html", "image", "images", "img", "index", "info", "intro", "item", "items", "ja", "jp", "jump", "jump.html", "jump.php", "jumping", "knowledge", "lang", "lesson", "lessons", "lib", "library", "link", "links", "list", "live", "lives", "m", "mag", "magnet", "mall", "manhua", "map", "member", "members", "message", "messages", "mobile", "movie", "movies", "music", "my", "new", "news", "note", "novel", "novels", "online", "order", "out", "out.html", "out.php", "outbound", "p", "page", "pages", "pay", "payment", "pdf", "photo", "photos", "pic", "pics", "picture", "pictures", "play", "player", "playlist", "post", "posts", "product", "products", "program", "programs", "project", "qa", "question", "rank", "ranking", "read", "readme", "redirect", "redirect.html", "redirect.php", "reg", "register", "res", "resource", "retrieve", "sale", "search", "season", "seasons", "section", "seller", "series", "service", "services", "setting", "settings", "share", "shop", "show", "shows", "site", "soft", "sort", "source", "special", "star", "stars", "static", "stock", "store", "stream", "streaming", "streams", "student", "study", "tag", "tags", "task", "teacher", "team", "tech", "temp", "test", "thread", "tool", "tools", "topic", "topics", "torrent", "trade", "travel", "tv", "txt", "type", "u", "upload", "uploads", "url", "urls", "user", "users", "v", "version", "videos", "view", "vip", "vod", "watch", "web", "wenku", "wiki", "work", "www", "zh", "zh-cn", "zh-tw", "zip"];
	const 随机数 = Math.floor(Math.random() * 3 + 1);
	const 随机路径 = 常用路径目录.sort(() => 0.5 - Math.random()).slice(0, 随机数).join('/');
	if (完整节点路径 === "/") return `/${随机路径}`;
	else return `/${随机路径 + 完整节点路径.replace('/?', '?')}`;
}

function 替换星号为随机字符(内容) {
	if (typeof 内容 !== 'string' || !内容.includes('*')) return 内容;
	const 字符集 = 'abcdefghijklmnopqrstuvwxyz0123456789';
	return 内容.replace(/\*/g, () => {
		let s = '';
		for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++) s += 字符集[Math.floor(Math.random() * 字符集.length)];
		return s;
	});
}

const DoH缓存 = {};
const DoH缓存最大条目 = 256;
const DoH记录类型映射 = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, SRV: 33, HTTPS: 65 };
async function DoH查询(域名, 记录类型, DoH解析服务 = "https://cloudflare-dns.com/dns-query") {
	const 规范化域名 = String(域名 || '').trim().toLowerCase().replace(/\.$/, '');
	const 规范化记录类型 = String(记录类型 || '').trim().toUpperCase();
	const 缓存键 = `${规范化域名}:${规范化记录类型}`;
	const qtype = DoH记录类型映射[规范化记录类型] || 1;
	const 当前时间戳 = Date.now();
	const 现缓存项 = DoH缓存[缓存键];
	if (现缓存项 && 当前时间戳 < 现缓存项.过期时间) {
		log(`[پرس‌وجوی DoH] از حافظهٔ موقت: ${域名} ${记录类型} via ${DoH解析服务}`);
		return 现缓存项.data.map(data => ({ type: qtype, data }));
	}
	const 开始时间 = performance.now();
	log(`[پرس‌وجوی DoH] آغاز پرس‌وجو: ${域名} ${记录类型} via ${DoH解析服务}`);
	try {
		// 记录类型字符串转数值
		// 编码域名为 DNS wire format labels
		const 编码域名 = (name) => {
			const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
			const bufs = [];
			for (const label of parts) {
				const enc = new TextEncoder().encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			const total = bufs.reduce((s, b) => s + b.length, 0);
			const result = new Uint8Array(total);
			let off = 0;
			for (const b of bufs) { result.set(b, off); off += b.length }
			return result;
		};

		// 构建 DNS 查询报文
		const qname = 编码域名(规范化域名);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]); // ID (random per RFC 1035)
		qview.setUint16(2, 0x0100);  // Flags: RD=1 (递归查询)
		qview.setUint16(4, 1);       // QDCOUNT
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1); // QCLASS = IN

		// 通过 POST 发送 dns-message 请求
		log(`[پرس‌وجوی DoH] ارسال بستهٔ پرس‌وجو ${域名} via ${DoH解析服务} (type=${qtype}, ${query.length} بایت)`);
		const response = await fetch(DoH解析服务, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/dns-message',
				'Accept': 'application/dns-message',
			},
			body: query,
		});
		if (!response.ok) {
			console.warn(`[پرس‌وجوی DoH] درخواست ناموفق بود ${域名} ${记录类型} via ${DoH解析服务} کد پاسخ: ${response.status}`);
			return [];
		}

		// 解析 DNS 响应报文
		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);
		log(`[پرس‌وجوی DoH] پاسخ دریافت شد ${域名} ${记录类型} via ${DoH解析服务} (${buf.length} بایت، ${ancount} پاسخ)`);

		// 解析域名（处理指针压缩）
		const 解析域名 = (pos) => {
			const labels = [];
			let p = pos, jumped = false, endPos = -1, safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) { if (!jumped) endPos = p + 1; break }
				if ((len & 0xC0) === 0xC0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3F) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join('.'), endPos];
		};

		// 跳过 Question Section
		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = 解析域名(offset);
			offset = /** @type {number} */ (end) + 4; // +4 跳过 QTYPE + QCLASS
		}

		// 解析 Answer Section
		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = 解析域名(offset);
			offset = /** @type {number} */ (nameEnd);
			const type = dv.getUint16(offset); offset += 2;
			offset += 2; // CLASS
			const ttl = dv.getUint32(offset); offset += 4;
			const rdlen = dv.getUint16(offset); offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;

			let data;
			if (type === 1 && rdlen === 4) {
				// A 记录
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				// AAAA 记录
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(':');
			} else if (type === 16) {
				// TXT 记录 (长度前缀字符串)
				let tOff = 0;
				const parts = [];
				while (tOff < rdlen) {
					const tLen = rdata[tOff++];
					parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
					tOff += tLen;
				}
				data = parts.join('');
			} else if (type === 5) {
				// CNAME 记录
				const [cname] = 解析域名(offset - rdlen);
				data = cname;
			} else {
				data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
			}
			answers.push({ name, type, TTL: ttl, data, rdata });
		}
		const 耗时 = (performance.now() - 开始时间).toFixed(2);
		log(`[پرس‌وجوی DoH] پایان پرس‌وجو ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms · ${answers.length} نتیجه${answers.length > 0 ? '\n' + answers.map((a, i) => `  ${i + 1}. ${a.name} type=${a.type} TTL=${a.TTL} data=${a.data}`).join('\n') : ''}`);
		// DoH 缓存至少保留 5 分钟，响应 TTL 更长时尊重响应 TTL；空响应使用 5 分钟负缓存
		const 相关记录 = answers.filter(answer => answer.type === qtype);
		const 最小TTL = 相关记录.length > 0 ? Math.min(...相关记录.map(a => a.TTL)) : 0;
		const 缓存TTL = Math.max(最小TTL, 5 * 60);
		const 缓存过期时间 = Date.now() + 缓存TTL * 1000;
		const 缓存数据 = 相关记录.map(answer => answer.data);
		if (缓存数据.length > 0 || answers.length === 0) {
			if (Object.keys(DoH缓存).length >= DoH缓存最大条目) {
				const 清理时间戳 = Date.now();
				for (const [缓存条目键, 缓存条目] of Object.entries(DoH缓存)) {
					if (清理时间戳 >= 缓存条目.过期时间) delete DoH缓存[缓存条目键];
				}
				if (Object.keys(DoH缓存).length >= DoH缓存最大条目) {
					delete DoH缓存[Object.keys(DoH缓存)[0]];
				}
			}
			DoH缓存[缓存键] = { data: 缓存数据, 过期时间: 缓存过期时间 };
			log(`[پرس‌وجوی DoH] ذخیره در حافظهٔ موقت ${域名} ${记录类型} TTL=${缓存TTL}s${缓存数据.length === 0 ? ' (بدون نتیجه)' : ''}`);
		}
		return answers;
	} catch (error) {
		const 耗时 = (performance.now() - 开始时间).toFixed(2);
		console.error(`[پرس‌وجوی DoH] پرس‌وجو ناموفق بود ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms:`, error);
		return [];
	}
}

async function 读取config_JSON(env, hostname, userID, UA = "Mozilla/5.0", 重置配置 = false) {
	const _p = 特征码字典[0];
	const host = hostname, Ali_DoH = "https://dns.alidns.com/dns-query", ECH_SNI = "cloudflare-ech.com", 占位符 = '{{IP:PORT}}', 初始化开始时间 = performance.now(), 默认配置JSON = {
		TIME: new Date().toISOString(),
		HOST: host,
		HOSTS: [hostname],
		UUID: userID,
		PATH: "/",
		ALPN: "",
		协议类型: "v" + "le" + "ss",
		传输协议: "ws",
		gRPC模式: "gun",
		gRPCUserAgent: UA,
		跳过证书验证: false,
		启用0RTT: false,
		TLS分片: null,
		随机路径: false,
		ECH: false,
		ECHConfig: {
			DNS: Ali_DoH,
			SNI: ECH_SNI,
		},
		SS: {
			加密方式: "aes-128-gcm",
			TLS: true,
		},
		Fingerprint: "chrome",
		优选订阅生成: {
			local: true, // true: 基于本地的优选地址  false: 优选订阅生成器
			本地IP库: {
				随机IP: true, // 当 随机IP 为true时生效，启用随机IP的数量，否则使用KV内的ADD.txt
				随机数量: 16,
				指定端口: -1,
			},
			SUB: null,
			SUBNAME: "Avatar",
			SUBUpdateTime: 3, // 订阅更新时间（小时）
			TOKEN: await MD5MD5(hostname + userID),
		},
		订阅转换配置: {
			SUBAPI: "", // خالی: سرویس پیش‌فرض
			SUBCONFIG: "", // خالی: قوانین پیش‌فرض
			SUBEMOJI: false,
			SUBLIST: false, //仅输出节点信息
			UDP: false, // 启用 UDP
			XUDP: false, // 启用 XUDP
			TLS13: false, // 启用 TLS 1.3
			APPEND_TYPE: false, // 插入节点类型
			SORT: false, // 基础节点排序
			EXPAND: true, // 展开规则全文
		},
		反代: {
			[_p]: "auto",
			SOCKS5: {
				启用: null,
				全局: false,
				账号: '',
				白名单: SOCKS5白名单,
			},
			路径模板: {
				[_p]: "proxyip=" + 占位符,
				SOCKS5: {
					全局: "socks5://" + 占位符,
					标准: "socks5=" + 占位符
				},
				HTTP: {
					全局: "http://" + 占位符,
					标准: "http=" + 占位符
				},
				HTTPS: {
					全局: "https://" + 占位符,
					标准: "https=" + 占位符
				},
				TURN: {
					全局: "turn://" + 占位符,
					标准: "turn=" + 占位符
				},
				SSTP: {
					全局: "sstp://" + 占位符,
					标准: "sstp=" + 占位符
				},
			},
		},
		TG: {
			启用: false,
			BotToken: null,
			ChatID: null,
		},
		CF: {
			Email: null,
			GlobalAPIKey: null,
			AccountID: null,
			APIToken: null,
			UsageAPI: null,
			Usage: {
				success: false,
				pages: 0,
				workers: 0,
				total: 0,
				max: 100000,
			},
		}
	};

	try {
		let configJSON = await env.KV.get('config.json');
		if (!configJSON || 重置配置 == true) {
			await env.KV.put('config.json', JSON.stringify(默认配置JSON, null, 2));
			config_JSON = 默认配置JSON;
		} else {
			config_JSON = JSON.parse(configJSON);
		}
	} catch (error) {
		console.error(`خطا در خواندن پیکربندی: ${error.message}`);
		config_JSON = 默认配置JSON;
	}

	if (!config_JSON.订阅转换配置.SUBAPI || config_JSON.订阅转换配置.SUBAPI === 默认订阅转换后端) config_JSON.订阅转换配置.SUBAPI = "";
	if (!config_JSON.订阅转换配置.SUBCONFIG || config_JSON.订阅转换配置.SUBCONFIG === 默认订阅转换规则) config_JSON.订阅转换配置.SUBCONFIG = "";
	if (!config_JSON.订阅转换配置.SUBLIST) config_JSON.订阅转换配置.SUBLIST = false;
	if (!config_JSON.订阅转换配置.UDP) config_JSON.订阅转换配置.UDP = false;
	if (!config_JSON.订阅转换配置.XUDP) config_JSON.订阅转换配置.XUDP = false;
	if (!config_JSON.订阅转换配置.TLS13) config_JSON.订阅转换配置.TLS13 = false;
	if (!config_JSON.订阅转换配置.APPEND_TYPE) config_JSON.订阅转换配置.APPEND_TYPE = false;
	if (!config_JSON.订阅转换配置.SORT) config_JSON.订阅转换配置.SORT = false;
	if (typeof config_JSON.订阅转换配置.EXPAND !== 'boolean') config_JSON.订阅转换配置.EXPAND = true;
	if (!config_JSON.gRPCUserAgent) config_JSON.gRPCUserAgent = UA;
	config_JSON.HOST = host;
	if (!config_JSON.HOSTS) config_JSON.HOSTS = [hostname];
	if (env.HOST) config_JSON.HOSTS = (await 整理成数组(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]);
	config_JSON.UUID = userID;
	if (!config_JSON.随机路径) config_JSON.随机路径 = false;
	if (!config_JSON.启用0RTT) config_JSON.启用0RTT = false;

	if (env.PATH) config_JSON.PATH = env.PATH.startsWith('/') ? env.PATH : '/' + env.PATH;
	else if (!config_JSON.PATH) config_JSON.PATH = '/';
	if (!config_JSON.ALPN) config_JSON.ALPN = "";

	if (!config_JSON.gRPC模式) config_JSON.gRPC模式 = 'gun';
	if (!config_JSON.SS) config_JSON.SS = { 加密方式: "aes-128-gcm", TLS: false };

	if (!config_JSON.反代.路径模板?.[_p]) {
		config_JSON.反代.路径模板 = {
			[_p]: "proxyip=" + 占位符,
			SOCKS5: {
				全局: "socks5://" + 占位符,
				标准: "socks5=" + 占位符
			},
			HTTP: {
				全局: "http://" + 占位符,
				标准: "http=" + 占位符
			},
			HTTPS: {
				全局: "https://" + 占位符,
				标准: "https=" + 占位符
			},
			TURN: {
				全局: "turn://" + 占位符,
				标准: "turn=" + 占位符
			},
			SSTP: {
				全局: "sstp://" + 占位符,
				标准: "sstp=" + 占位符
			},
		};
	}
	if (!config_JSON.反代.路径模板.HTTPS) config_JSON.反代.路径模板.HTTPS = { 全局: "https://" + 占位符, 标准: "https=" + 占位符 };
	if (!config_JSON.反代.路径模板.TURN) config_JSON.反代.路径模板.TURN = { 全局: "turn://" + 占位符, 标准: "turn=" + 占位符 };
	if (!config_JSON.反代.路径模板.SSTP) config_JSON.反代.路径模板.SSTP = { 全局: "sstp://" + 占位符, 标准: "sstp=" + 占位符 };

	const 代理配置 = config_JSON.反代.路径模板[config_JSON.反代.SOCKS5.启用?.toUpperCase()];

	let 路径反代参数 = '';
	if (代理配置 && config_JSON.反代.SOCKS5.账号) 路径反代参数 = (config_JSON.反代.SOCKS5.全局 ? 代理配置.全局 : 代理配置.标准).replace(占位符, config_JSON.反代.SOCKS5.账号);
	else if (config_JSON.反代[_p] !== 'auto') 路径反代参数 = config_JSON.反代.路径模板[_p].replace(占位符, config_JSON.反代[_p]);

	let 反代查询参数 = '';
	if (路径反代参数.includes('?')) {
		const [反代路径部分, 反代查询部分] = 路径反代参数.split('?');
		路径反代参数 = 反代路径部分;
		反代查询参数 = 反代查询部分;
	}

	config_JSON.PATH = config_JSON.PATH.replace(路径反代参数, '').replace('//', '/');
	const normalizedPath = config_JSON.PATH === '/' ? '' : config_JSON.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
	const [路径部分, ...查询数组] = normalizedPath.split('?');
	const 查询部分 = 查询数组.length ? '?' + 查询数组.join('?') : '';
	const 最终查询部分 = 反代查询参数 ? (查询部分 ? 查询部分 + '&' + 反代查询参数 : '?' + 反代查询参数) : 查询部分;
	config_JSON.完整节点路径 = (路径部分 || '/') + (路径部分 && 路径反代参数 ? '/' : '') + 路径反代参数 + 最终查询部分 + (config_JSON.启用0RTT ? (最终查询部分 ? '&' : '?') + 'ed=2560' : '');

	if (!config_JSON.TLS分片 && config_JSON.TLS分片 !== null) config_JSON.TLS分片 = null;
	const TLS分片参数 = config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
	if (!config_JSON.Fingerprint) config_JSON.Fingerprint = "chrome";
	if (!config_JSON.ECH) config_JSON.ECH = false;
	if (!config_JSON.ECHConfig) config_JSON.ECHConfig = { DNS: Ali_DoH, SNI: ECH_SNI };
	const ECHLINK参数 = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
	const { type: 传输协议, 路径字段名, 域名字段名 } = 获取传输协议配置(config_JSON);
	const 传输路径参数值 = 获取传输路径参数值(config_JSON, config_JSON.完整节点路径);
	config_JSON.LINK = config_JSON.协议类型 === 'ss'
		? `${config_JSON.协议类型}://${btoa(config_JSON.SS.加密方式 + ':' + userID)}@${host}:${config_JSON.SS.TLS ? '443' : '80'}?plugin=v2${encodeURIComponent(`ray-plugin;mode=websocket;host=${host};path=${((config_JSON.完整节点路径.includes('?') ? config_JSON.完整节点路径.replace('?', '?enc=' + config_JSON.SS.加密方式 + '&') : (config_JSON.完整节点路径 + '?enc=' + config_JSON.SS.加密方式)) + (config_JSON.SS.TLS ? ';tls' : ''))};mux=0`) + ECHLINK参数}#${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`
		: `${config_JSON.协议类型}://${userID}@${host}:443?security=tls&type=${传输协议 + ECHLINK参数}&${域名字段名}=${host}&fp=${config_JSON.Fingerprint}&sni=${host}&${路径字段名}=${encodeURIComponent(传输路径参数值) + TLS分片参数}&encryption=none#${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`;
	config_JSON.优选订阅生成.TOKEN = await MD5MD5(hostname + userID);

	const 初始化TG_JSON = { BotToken: null, ChatID: null };
	config_JSON.TG = { 启用: config_JSON.TG.启用 ? config_JSON.TG.启用 : false, ...初始化TG_JSON };
	try {
		const TG_TXT = await env.KV.get('tg.json');
		if (!TG_TXT) {
			await env.KV.put('tg.json', JSON.stringify(初始化TG_JSON, null, 2));
		} else {
			const TG_JSON = JSON.parse(TG_TXT);
			config_JSON.TG.ChatID = TG_JSON.ChatID ? TG_JSON.ChatID : null;
			config_JSON.TG.BotToken = TG_JSON.BotToken ? 掩码敏感信息(TG_JSON.BotToken) : null;
		}
	} catch (error) {
		console.error(`خطا در خواندن tg.json: ${error.message}`);
	}

	const 初始化CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
	config_JSON.CF = { ...初始化CF_JSON, Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 } };
	try {
		const CF_TXT = await env.KV.get('cf.json');
		if (!CF_TXT) {
			await env.KV.put('cf.json', JSON.stringify(初始化CF_JSON, null, 2));
		} else {
			const CF_JSON = JSON.parse(CF_TXT);
			if (CF_JSON.UsageAPI) {
				try {
					const response = await fetch(CF_JSON.UsageAPI, { signal: AbortSignal.timeout(5000) });
					const Usage = await response.json();
					config_JSON.CF.Usage = Usage;
				} catch (err) {
					console.error(`درخواست به API آمار مصرف ناموفق بود: ${err.message}`);
				}
			} else {
				config_JSON.CF.Email = CF_JSON.Email ? CF_JSON.Email : null;
				config_JSON.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey ? 掩码敏感信息(CF_JSON.GlobalAPIKey) : null;
				config_JSON.CF.AccountID = CF_JSON.AccountID ? 掩码敏感信息(CF_JSON.AccountID) : null;
				config_JSON.CF.APIToken = CF_JSON.APIToken ? 掩码敏感信息(CF_JSON.APIToken) : null;
				config_JSON.CF.UsageAPI = null;
				const Usage = await getCloudflareUsage(CF_JSON.Email, CF_JSON.GlobalAPIKey, CF_JSON.AccountID, CF_JSON.APIToken);
				config_JSON.CF.Usage = Usage;
			}
		}
	} catch (error) {
		console.error(`خطا در خواندن cf.json: ${error.message}`);
	}

	config_JSON.加载时间 = (performance.now() - 初始化开始时间).toFixed(2) + 'ms';
	return config_JSON;
}

function 识别运营商(request) {
	const cf = request?.cf;
	const ASN运营商映射 = {
		'4134': 'ct',
		'4809': 'ct',
		'4811': 'ct',
		'4812': 'ct',
		'4815': 'ct',
		'4837': 'cu',
		'4814': 'cu',
		'9929': 'cu',
		'17623': 'cu',
		'17816': 'cu',
		'9808': 'cmcc',
		'24400': 'cmcc',
		'56040': 'cmcc',
		'56041': 'cmcc',
		'56044': 'cmcc',
	};
	const 运营商关键词映射 = [
		{ code: 'ct', pattern: /chinanet|chinatelecom|china telecom|cn2|shtel/ },
		{ code: 'cmcc', pattern: /cmi|cmnet|chinamobile|china mobile|cmcc|mobile communications/ },
		{ code: 'cu', pattern: /china169|china unicom|chinaunicom|cucc|cncgroup|cuii|netcom/ },
	];
	if (String(cf?.country || '').toLowerCase() !== 'cn') return 'cf';
	const 组织名称 = String(cf?.asOrganization || '').toLowerCase();
	const 命中运营商 = 运营商关键词映射.find(({ pattern }) => pattern.test(组织名称))?.code;
	return 命中运营商 || ASN运营商映射[String(cf?.asn || '')] || 'cf';
}

async function 生成随机IP(request, count = 16, 指定端口 = -1) {
	const url = new URL(request.url);
	const 查询参数运营商 = String(url.searchParams.get('cnIspCode') || '').toLowerCase();
	const 运营商文件标识 = ['ct', 'cu', 'cmcc', 'cf'].includes(查询参数运营商) ? 查询参数运营商 : 识别运营商(request);
	const 运营商名称映射 = {
		cmcc: 'Avatar CMCC',
		cu: 'Avatar CU',
		ct: 'Avatar CT',
		cf: 'Avatar CF',
	};
	const cidr_url = 运营商文件标识 === 'cf' ? `https://raw.githubusercontent.com/${特征码字典[1]}/${特征码字典[1]}/main/CF-CIDR.txt` : `https://raw.githubusercontent.com/${特征码字典[1]}/${特征码字典[1]}/main/CF-CIDR/${运营商文件标识}.txt`;
	const cfname = 运营商名称映射[运营商文件标识] || 'Avatar CF';
	const cfport = [443, 2053, 2083, 2087, 2096, 8443];
	let cidrList = [];
	try { const res = await fetch(cidr_url, { signal: AbortSignal.timeout(4000) }); cidrList = res.ok ? await 整理成数组(await res.text()) : ['104.16.0.0/13'] } catch { cidrList = ['104.16.0.0/13'] }

	const generateRandomIPFromCIDR = (cidr) => {
		const [baseIP, prefixLength] = cidr.split('/'), prefix = parseInt(prefixLength), hostBits = 32 - prefix;
		const ipInt = baseIP.split('.').reduce((a, p, i) => a | (parseInt(p) << (24 - i * 8)), 0);
		const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
		const mask = (0xFFFFFFFF << hostBits) >>> 0, randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;
		return [(randomIP >>> 24) & 0xFF, (randomIP >>> 16) & 0xFF, (randomIP >>> 8) & 0xFF, randomIP & 0xFF].join('.');
	};
	const randomIPs = Array.from({ length: count }, (_, index) => {
		const ip = generateRandomIPFromCIDR(cidrList[Math.floor(Math.random() * cidrList.length)]);
		const 目标端口 = 指定端口 === -1
			? cfport[Math.floor(Math.random() * cfport.length)]
			: 指定端口;
		return `${ip}:${目标端口}#${cfname} ${index + 1}`;
	});
	return [randomIPs, randomIPs.join('\n')];
}

async function 整理成数组(内容) {
	var 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
	if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);
	const 地址数组 = 替换后的内容.split(',');
	return 地址数组;
}

async function 获取优选订阅生成器数据(优选订阅生成器HOST) {
	let 优选IP = [], 其他节点LINK = '', 格式化HOST = 优选订阅生成器HOST.replace(/^sub:\/\//i, 'https://').split('#')[0].split('?')[0];
	if (!/^https?:\/\//i.test(格式化HOST)) 格式化HOST = `https://${格式化HOST}`;

	try {
		const url = new URL(格式化HOST);
		格式化HOST = url.origin;
	} catch (error) {
		优选IP.push(`127.0.0.1:1234#${优选订阅生成器HOST} نشانی تولیدکنندهٔ اشتراک نامعتبر است: ${error.message}`);
		return [优选IP, 其他节点LINK];
	}

	const 优选订阅生成器URL = `${格式化HOST}/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000`;

	try {
		const response = await fetch(优选订阅生成器URL, {
			headers: { 'User-Agent': 汇聚订阅_UA }
		});

		if (!response.ok) {
			优选IP.push(`127.0.0.1:1234#${优选订阅生成器HOST} خطای تولیدکنندهٔ اشتراک: ${response.statusText}`);
			return [优选IP, 其他节点LINK];
		}

		const 优选订阅生成器返回订阅内容 = atob(await response.text());
		const 订阅行列表 = 优选订阅生成器返回订阅内容.includes('\r\n')
			? 优选订阅生成器返回订阅内容.split('\r\n')
			: 优选订阅生成器返回订阅内容.split('\n');

		for (const 行内容 of 订阅行列表) {
			if (!行内容.trim()) continue; // 跳过空行
			if (行内容.includes('00000000-0000-4000-8000-000000000000') && 行内容.includes('example.com')) {
				// 这是优选IP行，提取 域名:端口#备注
				const 地址匹配 = 行内容.match(/:\/\/[^@]+@([^?]+)/);
				if (地址匹配) {
					let 地址端口 = 地址匹配[1], 备注 = ''; // 域名:端口 或 IP:端口
					const 备注匹配 = 行内容.match(/#(.+)$/);
					if (备注匹配) 备注 = '#' + decodeURIComponent(备注匹配[1]);
					优选IP.push(地址端口 + 备注);
				}
			} else {
				其他节点LINK += 行内容 + '\n';
			}
		}
	} catch (error) {
		优选IP.push(`127.0.0.1:1234#${优选订阅生成器HOST} خطای تولیدکنندهٔ اشتراک: ${error.message}`);
	}

	return [优选IP, 其他节点LINK];
}

async function 请求优选API(urls, 默认端口 = '443', 超时时间 = 3000) {
	if (!urls?.length) return [[], [], [], []];
	const results = new Set(), 反代IP池 = new Set();
	let 订阅链接响应的明文LINK内容 = '', 需要订阅转换订阅URLs = [];
	await Promise.allSettled(urls.map(async (url) => {
		// 检查URL是否包含备注名
		const hashIndex = url.indexOf('#');
		const urlWithoutHash = hashIndex > -1 ? url.substring(0, hashIndex) : url;
		const API备注名 = hashIndex > -1 ? decodeURIComponent(url.substring(hashIndex + 1)) : null;
		const 优选IP作为反代IP = url.toLowerCase().includes('proxyip=true');
		if (urlWithoutHash.toLowerCase().startsWith('sub://')) {
			try {
				const [优选IP, 其他节点LINK] = await 获取优选订阅生成器数据(urlWithoutHash);
				// 处理第一个数组 - 优选IP
				if (API备注名) {
					for (const ip of 优选IP) {
						const 处理后IP = ip.includes('#')
							? `${ip} [${API备注名}]`
							: `${ip}#[${API备注名}]`;
						results.add(处理后IP);
						if (优选IP作为反代IP) 反代IP池.add(ip.split('#')[0]);
					}
				} else {
					for (const ip of 优选IP) {
						results.add(ip);
						if (优选IP作为反代IP) 反代IP池.add(ip.split('#')[0]);
					}
				}
				// 处理第二个数组 - 其他节点LINK
				if (其他节点LINK && typeof 其他节点LINK === 'string' && API备注名) {
					const 处理后LINK内容 = 其他节点LINK.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						const 完整链接 = link.includes('#')
							? `${link}${encodeURIComponent(` [${API备注名}]`)}`
							: `${link}${encodeURIComponent(`#[${API备注名}]`)}`;
						return `${完整链接}${lineEnd}`;
					});
					订阅链接响应的明文LINK内容 += 处理后LINK内容;
				} else if (其他节点LINK && typeof 其他节点LINK === 'string') {
					订阅链接响应的明文LINK内容 += 其他节点LINK;
				}
			} catch (e) { }
			return;
		}

		try {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 超时时间);
			const response = await fetch(urlWithoutHash, { signal: controller.signal, headers: { 'User-Agent': 汇聚订阅_UA } });
			clearTimeout(timeoutId);
			let text = '';
			try {
				const buffer = await response.arrayBuffer();
				const contentType = (response.headers.get('content-type') || '').toLowerCase();
				const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';

				// 根据 Content-Type 响应头判断编码优先级
				let decoders = ['utf-8', 'gb2312']; // 默认优先 UTF-8
				if (charset.includes('gb') || charset.includes('gbk') || charset.includes('gb2312')) {
					decoders = ['gb2312', 'utf-8']; // 如果明确指定 GB 系编码，优先尝试 GB2312
				}

				// 尝试多种编码解码
				let decodeSuccess = false;
				for (const decoder of decoders) {
					try {
						const decoded = new TextDecoder(decoder).decode(buffer);
						// 验证解码结果的有效性
						if (decoded && decoded.length > 0 && !decoded.includes('\ufffd')) {
							text = decoded;
							decodeSuccess = true;
							break;
						} else if (decoded && decoded.length > 0) {
							// 如果有替换字符 (U+FFFD)，说明编码不匹配，继续尝试下一个编码
							continue;
						}
					} catch (e) {
						// 该编码解码失败，尝试下一个
						continue;
					}
				}

				// 如果所有编码都失败或无效，尝试 response.text()
				if (!decodeSuccess) {
					text = await response.text();
				}

				// 如果返回的是空或无效数据，返回
				if (!text || text.trim().length === 0) {
					return;
				}
			} catch (e) {
				console.error('Failed to decode response:', e);
				return;
			}

			// 预处理订阅内容
			/*
			if (text.includes('proxies:') || (text.includes('outbounds"') && text.includes('inbounds"'))) {// Clash Singbox 配置
				需要订阅转换订阅URLs.add(url);
				return;
			}
			*/

			let 预处理订阅明文内容 = text;
			const cleanText = typeof text === 'string' ? text.replace(/\s/g, '') : '';
			if (cleanText.length > 0 && cleanText.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(cleanText)) {
				try {
					const bytes = new Uint8Array(atob(cleanText).split('').map(c => c.charCodeAt(0)));
					预处理订阅明文内容 = new TextDecoder('utf-8').decode(bytes);
				} catch { }
			}
			if (预处理订阅明文内容.split('#')[0].includes('://')) {
				// 处理LINK内容
				if (API备注名) {
					const 处理后LINK内容 = 预处理订阅明文内容.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						const 完整链接 = link.includes('#')
							? `${link}${encodeURIComponent(` [${API备注名}]`)}`
							: `${link}${encodeURIComponent(`#[${API备注名}]`)}`;
						return `${完整链接}${lineEnd}`;
					});
					订阅链接响应的明文LINK内容 += 处理后LINK内容 + '\n';
				} else {
					订阅链接响应的明文LINK内容 += 预处理订阅明文内容 + '\n';
				}
				return;
			}

			const lines = text.trim().split('\n').map(l => l.trim()).filter(l => l);
			const isCSV = lines.length > 1 && lines[0].includes(',');
			const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
			const parsedUrl = new URL(urlWithoutHash);
			if (!isCSV) {
				lines.forEach(line => {
					const lineHashIndex = line.indexOf('#');
					const [hostPart, remark] = lineHashIndex > -1 ? [line.substring(0, lineHashIndex), line.substring(lineHashIndex)] : [line, ''];
					let hasPort = false;
					if (hostPart.startsWith('[')) {
						hasPort = /\]:(\d+)$/.test(hostPart);
					} else {
						const colonIndex = hostPart.lastIndexOf(':');
						hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
					}
					const port = parsedUrl.searchParams.get('port') || 默认端口;
					const ipItem = hasPort ? line : `${hostPart}:${port}${remark}`;
					// 处理第一个数组 - 优选IP
					if (API备注名) {
						const 处理后IP = ipItem.includes('#')
							? `${ipItem} [${API备注名}]`
							: `${ipItem}#[${API备注名}]`;
						results.add(处理后IP);
					} else {
						results.add(ipItem);
					}
					if (优选IP作为反代IP) 反代IP池.add(ipItem.split('#')[0]);
				});
			} else {
				const headers = lines[0].split(',').map(h => h.trim());
				const dataLines = lines.slice(1);
				if (headers.includes('IP地址') && headers.includes('端口') && headers.includes('数据中心')) {
					const ipIdx = headers.indexOf('IP地址'), portIdx = headers.indexOf('端口');
					const remarkIdx = headers.indexOf('国家') > -1 ? headers.indexOf('国家') :
						headers.indexOf('城市') > -1 ? headers.indexOf('城市') : headers.indexOf('数据中心');
					const tlsIdx = headers.indexOf('TLS');
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== 'true') return;
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`;
						// 处理第一个数组 - 优选IP
						if (API备注名) {
							const 处理后IP = `${ipItem} [${API备注名}]`;
							results.add(处理后IP);
						} else {
							results.add(ipItem);
						}
						if (优选IP作为反代IP) 反代IP池.add(`${wrappedIP}:${cols[portIdx]}`);
					});
				} else if (headers.some(h => h.includes('IP')) && headers.some(h => h.includes('延迟')) && headers.some(h => h.includes('下载速度'))) {
					const ipIdx = headers.findIndex(h => h.includes('IP'));
					const delayIdx = headers.findIndex(h => h.includes('延迟'));
					const speedIdx = headers.findIndex(h => h.includes('下载速度'));
					const port = parsedUrl.searchParams.get('port') || 默认端口;
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${port}#CF ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`;
						// 处理第一个数组 - 优选IP
						if (API备注名) {
							const 处理后IP = `${ipItem} [${API备注名}]`;
							results.add(处理后IP);
						} else {
							results.add(ipItem);
						}
						if (优选IP作为反代IP) 反代IP池.add(`${wrappedIP}:${port}`);
					});
				}
			}
		} catch (e) { }
	}));
	// 将LINK内容转换为数组并去重
	const LINK数组 = 订阅链接响应的明文LINK内容.trim() ? [...new Set(订阅链接响应的明文LINK内容.split(/\r?\n/).filter(line => line.trim() !== ''))] : [];
	return [Array.from(results), LINK数组, 需要订阅转换订阅URLs, Array.from(反代IP池)];
}

async function 反代参数获取(url, uuid, 默认反代IP = '', 默认反代兜底 = true) {
	const { searchParams } = url;
	const pathname = decodeURIComponent(url.pathname);
	const pathLower = pathname.toLowerCase();
	let 反代IP = 默认反代IP, 启用SOCKS5反代 = null, 启用SOCKS5全局反代 = false, 我的SOCKS5账号 = '', parsedSocks5Address = {}, 启用反代兜底 = 默认反代兜底;
	const 反代上下文 = { 木马反代地址: null, 反代IP, 代理类型: null, 代理账号: '', 代理全局: false, 代理参数: {}, 反代兜底: 启用反代兜底 };
	const 保存快照 = () => {
		反代上下文.反代IP = 反代IP;
		反代上下文.代理类型 = 启用SOCKS5反代;
		反代上下文.代理账号 = 我的SOCKS5账号;
		反代上下文.代理全局 = 启用SOCKS5全局反代;
		反代上下文.代理参数 = { ...parsedSocks5Address };
		反代上下文.反代兜底 = 启用反代兜底;
	};

	const 链式代理路径匹配 = pathname.match(/\/video\/(.+)$/i);
	if (链式代理路径匹配) {
		try {
			const 链式代理明文 = base64SecretDecode(链式代理路径匹配[1].replace(/\/+$/, ''), uuid);
			const { type, ...链式代理地址 } = JSON.parse(链式代理明文);
			if (!type || !反代协议默认端口[String(type).toLowerCase()]) throw new Error('نوع پراکسی زنجیره‌ای نامعتبر است');
			if (!链式代理地址.hostname || !链式代理地址.port) throw new Error('نشانی پراکسی زنجیره‌ای نام میزبان یا درگاه ندارد');
			我的SOCKS5账号 = '';
			反代IP = '链式代理';
			启用反代兜底 = false;
			启用SOCKS5全局反代 = true;
			启用SOCKS5反代 = String(type).toLowerCase();
			parsedSocks5Address = {
				username: 链式代理地址.username,
				password: 链式代理地址.password,
				hostname: 链式代理地址.hostname,
				port: Number(链式代理地址.port)
			};
			if (isNaN(parsedSocks5Address.port)) throw new Error('درگاه پراکسی زنجیره‌ای نامعتبر است');
			保存快照();
			return 反代上下文;
		} catch (err) {
			console.error('تجزیهٔ پارامترهای پراکسی زنجیره‌ای ناموفق بود:', err.message);
		}
	}

	我的SOCKS5账号 = searchParams.get('socks5') || searchParams.get('http') || searchParams.get('https') || searchParams.get('turn') || searchParams.get('sstp') || null;
	启用SOCKS5全局反代 = searchParams.has('globalproxy');
	if (searchParams.get('socks5')) 启用SOCKS5反代 = 'socks5';
	else if (searchParams.get('http')) 启用SOCKS5反代 = 'http';
	else if (searchParams.get('https')) 启用SOCKS5反代 = 'https';
	else if (searchParams.get('turn')) 启用SOCKS5反代 = 'turn';
	else if (searchParams.get('sstp')) 启用SOCKS5反代 = 'sstp';

	const 解析代理URL = (值, 强制全局 = true) => {
		const 匹配 = /^(socks5|http|https|turn|sstp):\/\/(.+)$/i.exec(值 || '');
		if (!匹配) return false;
		启用SOCKS5反代 = 匹配[1].toLowerCase();
		我的SOCKS5账号 = 匹配[2].split('/')[0];
		if (强制全局) 启用SOCKS5全局反代 = true;
		return true;
	};

	const 设置反代IP = (值) => {
		反代IP = 值;
		启用SOCKS5反代 = null;
		启用反代兜底 = false;
	};

	const 提取路径值 = (值) => {
		if (!值.includes('://')) {
			const 斜杠索引 = 值.indexOf('/');
			return 斜杠索引 > 0 ? 值.slice(0, 斜杠索引) : 值;
		}
		const 协议拆分 = 值.split('://');
		if (协议拆分.length !== 2) return 值;
		const 斜杠索引 = 协议拆分[1].indexOf('/');
		return 斜杠索引 > 0 ? `${协议拆分[0]}://${协议拆分[1].slice(0, 斜杠索引)}` : 值;
	};

	const 木马路径匹配 = /\/trojan=([^?#\s]+)/i.exec(pathname);
	if (木马路径匹配) {
		try {
			反代上下文.木马反代地址 = 解析木马反代地址(木马路径匹配[1].replace(/\/+$/, ''));
		} catch (err) {
			console.error('تجزیهٔ نشانی fallback ناموفق بود:', err.message);
			反代上下文.木马反代地址 = null;
		}
	}

	const 查询反代IP = searchParams.get('proxyip');
	if (查询反代IP !== null) {
		if (!解析代理URL(查询反代IP)) {
			设置反代IP(查询反代IP);
			保存快照();
			return 反代上下文;
		}
	} else {
		let 匹配 = /\/(socks5?|http|https|turn|sstp):\/?\/?([^/?#\s]+)/i.exec(pathname);
		if (匹配) {
			const 类型 = 匹配[1].toLowerCase();
			启用SOCKS5反代 = 类型 === 'sock' || 类型 === 'socks' ? 'socks5' : 类型;
			我的SOCKS5账号 = 匹配[2].split('/')[0];
			启用SOCKS5全局反代 = true;
		} else if ((匹配 = /\/(g?s5|socks5|g?http|g?https|g?turn|g?sstp)=([^/?#\s]+)/i.exec(pathname))) {
			const 类型 = 匹配[1].toLowerCase();
			我的SOCKS5账号 = 匹配[2].split('/')[0];
			启用SOCKS5反代 = 类型.includes('sstp') ? 'sstp' : (类型.includes('turn') ? 'turn' : (类型.includes('https') ? 'https' : (类型.includes('http') ? 'http' : 'socks5')));
			if (类型.startsWith('g')) 启用SOCKS5全局反代 = true;
		} else if ((匹配 = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower))) {
			const 路径反代值 = 提取路径值(匹配[2]);
			if (!解析代理URL(路径反代值)) {
				设置反代IP(路径反代值);
				保存快照();
				return 反代上下文;
			}
		}
	}

	if (!我的SOCKS5账号) {
		启用SOCKS5反代 = null;
		保存快照();
		return 反代上下文;
	}

	try {
		parsedSocks5Address = await 获取SOCKS5账号(我的SOCKS5账号, 获取代理默认端口(启用SOCKS5反代));
		if (searchParams.get('socks5')) 启用SOCKS5反代 = 'socks5';
		else if (searchParams.get('http')) 启用SOCKS5反代 = 'http';
		else if (searchParams.get('https')) 启用SOCKS5反代 = 'https';
		else if (searchParams.get('turn')) 启用SOCKS5反代 = 'turn';
		else if (searchParams.get('sstp')) 启用SOCKS5反代 = 'sstp';
		else 启用SOCKS5反代 = 启用SOCKS5反代 || 'socks5';
	} catch (err) {
		console.error('تجزیهٔ نشانی SOCKS5 ناموفق بود:', err.message);
		启用SOCKS5反代 = null;
	}
	保存快照();
	return 反代上下文;
}

const 反代协议默认端口 = { socks5: 1080, http: 80, https: 443, turn: 3478, sstp: 443 };
function 获取代理默认端口(类型) {
	return 反代协议默认端口[String(类型 || '').toLowerCase()] || 80;
}

const SOCKS5账号Base64正则 = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i, IPv6方括号正则 = /^\[.*\]$/;
function 获取SOCKS5账号(address, 默认端口 = 80) {
	address = String(address || '').trim().replace(/^(socks5|http|https|turn|sstp):\/\//i, '').split('#')[0].trim();
	const firstAt = address.lastIndexOf("@");
	if (firstAt !== -1) {
		let auth = address.slice(0, firstAt).replaceAll("%3D", "=");
		if (!auth.includes(":") && SOCKS5账号Base64正则.test(auth)) auth = atob(auth);
		address = `${auth}@${address.slice(firstAt + 1)}`;
	}

	const atIndex = address.lastIndexOf("@");
	const hostPart = (atIndex === -1 ? address : address.slice(atIndex + 1)).split('/')[0];
	const authPart = atIndex === -1 ? "" : address.slice(0, atIndex);
	const [username, password] = authPart ? authPart.split(":") : [];
	if (authPart && !password) throw new Error('قالب نشانی SOCKS نامعتبر است: بخش احراز هویت باید به شکل "username:password" باشد');

	let hostname = hostPart, port = 默认端口;
	if (hostPart.includes("]:")) {
		const [ipv6Host, ipv6Port = ""] = hostPart.split("]:");
		hostname = ipv6Host + "]";
		port = Number(ipv6Port.replace(/[^\d]/g, ""));
	} else if (!hostPart.startsWith("[")) {
		const parts = hostPart.split(":");
		if (parts.length === 2) {
			hostname = parts[0];
			port = Number(parts[1].replace(/[^\d]/g, ""));
		}
	}

	if (isNaN(port)) throw new Error('قالب نشانی SOCKS نامعتبر است: درگاه باید عدد باشد');
	if (hostname.includes(":") && !IPv6方括号正则.test(hostname)) throw new Error('قالب نشانی SOCKS نامعتبر است: نشانی IPv6 باید داخل کروشه باشد، مانند [2001:db8::1]');
	return { username, password, hostname, port };
}

async function getCloudflareUsage(Email, GlobalAPIKey, AccountID, APIToken) {
	const API = "https://api.cloudflare.com/client/v4";
	const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
	const cfg = { "Content-Type": "application/json" };

	try {
		if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };

		if (!AccountID) {
			const r = await fetch(`${API}/accounts`, {
				method: "GET", signal: AbortSignal.timeout(6000),
				headers: { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey }
			});
			if (!r.ok) throw new Error(`دریافت حساب ناموفق بود: ${r.status}`);
			const d = await r.json();
			if (!d?.result?.length) throw new Error("حسابی پیدا نشد");
			const idx = d.result.findIndex(a => a.name?.toLowerCase().startsWith(Email.toLowerCase()));
			AccountID = d.result[idx >= 0 ? idx : 0]?.id;
		}

		const now = new Date();
		now.setUTCHours(0, 0, 0, 0);
		const hdr = APIToken ? { ...cfg, "Authorization": `Bearer ${APIToken}` } : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };

		const res = await fetch(`${API}/graphql`, {
			method: "POST", signal: AbortSignal.timeout(6000),
			headers: hdr,
			body: JSON.stringify({
				query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
					viewer { accounts(filter: {accountTag: $AccountID}) {
						pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
						workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
					} }
				}`,
				variables: { AccountID, filter: { datetime_geq: now.toISOString(), datetime_leq: new Date().toISOString() } }
			})
		});

		if (!res.ok) throw new Error(`پرس‌وجو ناموفق بود: ${res.status}`);
		const result = await res.json();
		if (result.errors?.length) throw new Error(result.errors[0].message);

		const acc = result?.data?.viewer?.accounts?.[0];
		if (!acc) throw new Error("داده‌ای برای این حساب پیدا نشد");

		const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
		const workers = sum(acc.workersInvocationsAdaptive);
		const total = pages + workers;
		const max = 100000;
		log(`آمار مصرف - Pages: ${pages}, Workers: ${workers}, مجموع: ${total}, سقف: 100000`);
		return { success: true, pages, workers, total, max };

	} catch (error) {
		console.error('خطا در دریافت آمار مصرف:', error.message);
		return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };
	}
}

function sha224(s) {
	const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
	const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
	s = unescape(encodeURIComponent(s));
	const l = s.length * 8; s += String.fromCharCode(0x80);
	while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
	const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
	const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
	s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
	const w = []; for (let i = 0; i < s.length; i += 4)w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
	for (let i = 0; i < w.length; i += 16) {
		const x = new Array(64).fill(0);
		for (let j = 0; j < 16; j++)x[j] = w[i + j];
		for (let j = 16; j < 64; j++) {
			const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
			const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
			x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
		}
		let [a, b, c, d, e, f, g, h0] = h;
		for (let j = 0; j < 64; j++) {
			const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
			const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
			h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
		}
		for (let j = 0; j < 8; j++)h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
	}
	let hex = '';
	for (let i = 0; i < 7; i++) {
		for (let j = 24; j >= 0; j -= 8)hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
	}
	return hex;
}

async function 解析地址端口(proxyIP, 目标域名 = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
	proxyIP = proxyIP.toLowerCase();
	function 解析地址端口字符串(str) {
		let 地址 = str, 端口 = 443;
		if (str.includes(']:')) {
			const parts = str.split(']:');
			地址 = parts[0] + ']';
			端口 = parseInt(parts[1], 10) || 端口;
		} else if ((str.match(/:/g) || []).length === 1 && !str.startsWith('[')) {
			const colonIndex = str.lastIndexOf(':');
			地址 = str.slice(0, colonIndex);
			端口 = parseInt(str.slice(colonIndex + 1), 10) || 端口;
		}
		return [地址, 端口];
	}

	function 解析TXT反代记录(txtData) {
		return txtData.flatMap(data => {
			if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
			return data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
		}).map(prefix => 解析地址端口字符串(prefix));
	}

	const 反代IP数组 = await 整理成数组(proxyIP);
	let 所有反代数组 = [];
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
	const ipv6Regex = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;

	// 遍历数组中的每个IP元素进行处理
	for (const singleProxyIP of 反代IP数组) {
		let [地址, 端口] = 解析地址端口字符串(singleProxyIP);

		if (singleProxyIP.includes('.tp')) {
			const tpMatch = singleProxyIP.match(/\.tp(\d+)/);
			if (tpMatch) 端口 = parseInt(tpMatch[1], 10);
		}

		// 判断是否是域名（非IP地址）
		if (ipv4Regex.test(地址) || ipv6Regex.test(地址)) {
			log(`[تفکیک پراکسی] ${地址} نشانی IP است و مستقیم استفاده می‌شود`);
			所有反代数组.push([地址, 端口]);
			continue;
		}

		const [txtRecords, aRecords] = await Promise.all([
			DoH查询(地址, 'TXT'),
			DoH查询(地址, 'A')
		]);

		const txtData = txtRecords.filter(r => r.type === 16).map(r => (r.data));
		const txtAddresses = 解析TXT反代记录(txtData);
		if (txtAddresses.length > 0) {
			log(`[تفکیک پراکسی] ${地址} از رکورد TXT استفاده شد · ${txtAddresses.length} نتیجه`);
			所有反代数组.push(...txtAddresses);
			continue;
		}

		const ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
		if (ipv4List.length > 0) {
			log(`[تفکیک پراکسی] ${地址} رکورد TXT ندارد؛ از رکورد A استفاده شد · ${ipv4List.length} نتیجه`);
			所有反代数组.push(...ipv4List.map(ip => [ip, 端口]));
			continue;
		}

		const aaaaRecords = await DoH查询(地址, 'AAAA');
		const ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
		if (ipv6List.length > 0) {
			log(`[تفکیک پراکسی] ${地址} رکورد TXT و A ندارد؛ از رکورد AAAA استفاده شد · ${ipv6List.length} نتیجه`);
			所有反代数组.push(...ipv6List.map(ip => [ip, 端口]));
		} else {
			log(`[تفکیک پراکسی] ${地址} هیچ رکورد TXT، A یا AAAA ندارد؛ دامنهٔ اصلی حفظ شد`);
			所有反代数组.push([地址, 端口]);
		}
	}
	const 排序后数组 = 所有反代数组.sort((a, b) => a[0].localeCompare(b[0]));
	const 目标根域名 = 目标域名.includes('.') ? 目标域名.split('.').slice(-2).join('.') : 目标域名;
	let 随机种子 = [...(目标根域名 + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
	log(`[تفکیک پراکسی] بذر تصادفی: ${随机种子}\nسایت مقصد: ${目标根域名}`)
	const 洗牌后 = [...排序后数组].sort(() => (随机种子 = (随机种子 * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
	const 解析结果 = 洗牌后.slice(0, 8);
	log(`[تفکیک پراکسی] تفکیک کامل شد · مجموع: ${解析结果.length}\n${解析结果.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
	return 解析结果;
}

//////////////////////////////////////////////////////HTML伪装页面///////////////////////////////////////////////
async function nginx() {
	return `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>

	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>

	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
}

async function html1101(host, 访问IP) {
	host = HTML转义(host); 访问IP = HTML转义(访问IP);
	const now = new Date();
	const 格式化时间戳 = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0') + ' ' + String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0') + ':' + String(now.getSeconds()).padStart(2, '0');
	const 随机字符串 = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');

	return `<!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-js ie8 oldie" lang="en-US"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js" lang="en-US"> <!--<![endif]-->
<head>
<title>Worker threw exception | ${host} | Cloudflare</title>
<meta charset="UTF-8" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
<meta name="robots" content="noindex, nofollow" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<link rel="stylesheet" id="cf_styles-css" href="/cdn-cgi/styles/cf.errors.css" />
<!--[if lt IE 9]><link rel="stylesheet" id='cf_styles-ie-css' href="/cdn-cgi/styles/cf.errors.ie.css" /><![endif]-->
<style>body{margin:0;padding:0}</style>


<!--[if gte IE 10]><!-->
<script>
  if (!navigator.cookieEnabled) {
    window.addEventListener('DOMContentLoaded', function () {
      var cookieEl = document.getElementById('cookie-alert');
      cookieEl.style.display = 'block';
    })
  }
</script>
<!--<![endif]-->

</head>
<body>
    <div id="cf-wrapper">
        <div class="cf-alert cf-alert-error cf-cookie-error" id="cookie-alert" data-translate="enable_cookies">Please enable cookies.</div>
        <div id="cf-error-details" class="cf-error-details-wrapper">
            <div class="cf-wrapper cf-header cf-error-overview">
                <h1>
                    <span class="cf-error-type" data-translate="error">Error</span>
                    <span class="cf-error-code">1101</span>
                    <small class="heading-ray-id">Ray ID: ${随机字符串} &bull; ${格式化时间戳} UTC</small>
                </h1>
                <h2 class="cf-subheadline" data-translate="error_desc">Worker threw exception</h2>
            </div><!-- /.header -->

            <section></section><!-- spacer -->

            <div class="cf-section cf-wrapper">
                <div class="cf-columns two">
                    <div class="cf-column">
                        <h2 data-translate="what_happened">What happened?</h2>
                            <p>You've requested a page on a website (${host}) that is on the <a href="https://www.cloudflare.com/5xx-error-landing?utm_source=error_100x" target="_blank">Cloudflare</a> network. An unknown error occurred while rendering the page.</p>
                    </div>

                    <div class="cf-column">
                        <h2 data-translate="what_can_i_do">What can I do?</h2>
                            <p><strong>If you are the owner of this website:</strong><br />refer to <a href="https://developers.cloudflare.com/workers/observability/errors/" target="_blank">Workers - Errors and Exceptions</a> and check Workers Logs for ${host}.</p>
                    </div>

                </div>
            </div><!-- /.section -->

            <div class="cf-error-footer cf-wrapper w-240 lg:w-full py-10 sm:py-4 sm:px-8 mx-auto text-center sm:text-left border-solid border-0 border-t border-gray-300">
    <p class="text-13">
      <span class="cf-footer-item sm:block sm:mb-1">Cloudflare Ray ID: <strong class="font-semibold"> ${随机字符串}</strong></span>
      <span class="cf-footer-separator sm:hidden">&bull;</span>
      <span id="cf-footer-item-ip" class="cf-footer-item hidden sm:block sm:mb-1">
        Your IP:
        <button type="button" id="cf-footer-ip-reveal" class="cf-footer-ip-reveal-btn">Click to reveal</button>
        <span class="hidden" id="cf-footer-ip">${访问IP}</span>
        <span class="cf-footer-separator sm:hidden">&bull;</span>
      </span>
      <span class="cf-footer-item sm:block sm:mb-1"><span>Performance &amp; security by</span> <a rel="noopener noreferrer" href="https://www.cloudflare.com/5xx-error-landing" id="brand_link" target="_blank">Cloudflare</a></span>

    </p>
    <script>(function(){function d(){var b=a.getElementById("cf-footer-item-ip"),c=a.getElementById("cf-footer-ip-reveal");b&&"classList"in b&&(b.classList.remove("hidden"),c.addEventListener("click",function(){c.classList.add("hidden");a.getElementById("cf-footer-ip").classList.remove("hidden")}))}var a=document;document.addEventListener&&a.addEventListener("DOMContentLoaded",d)})();</script>
  </div><!-- /.error-footer -->

        </div><!-- /#cf-error-details -->
    </div><!-- /#cf-wrapper -->

     <script>
    window._cf_translation = {};


  </script>
</body>
</html>`;
}


///////////////////////////////////////////////////////Avatar · رابط کاربری داخلی///////////////////////////////////////////////
// همهٔ صفحه‌های پنل (ورود، مدیریت و راهنمای راه‌اندازی) درون همین فایل قرار دارند و به میزبان بیرونی وابسته نیستند.
const Avatar_سبک_پایه = `<style>@font-face{font-family:'Vazirmatn';src:url(data:font/woff2;base64,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) format('woff2');font-weight:100 900;font-style:normal;font-display:swap}
/* Avatar · سامانهٔ طراحی مشترک
   الهام: ترمهٔ ایرانی، نیلی تیره + زعفرانی + فیروزه‌ای */
:root{
  --indigo-900:#160f33;--indigo-800:#1f1647;--indigo-700:#2c1f62;--indigo-600:#3b2b7d;--indigo-100:#e9e5f6;--indigo-50:#f4f2fb;
  --saffron:#e84a00;--saffron-600:#c93f00;--saffron-100:#fde6da;--saffron-50:#fff4ee;
  --teal:#006289;--teal-100:#d9eef5;
  --crimson:#bb1d2c;--crimson-100:#f9e0e2;
  --green:#1d7a4f;--green-100:#dcf1e6;
  --bg:#f7f4f2;--card:#fffdfc;--line:#e8e1dd;--line-strong:#d5cbc6;
  --text:#2a1f1c;--muted:#6f5f59;--faint:#9a8a84;
  --radius:14px;--radius-sm:10px;
  --shadow:0 1px 2px rgba(42,31,28,.06),0 8px 24px -12px rgba(42,31,28,.18);
  --font:'Vazirmatn',Tahoma,'Segoe UI',sans-serif;
  --mono:ui-monospace,'SFMono-Regular',Menlo,Consolas,'Liberation Mono',monospace;
  --surface:#fff;--ink:var(--indigo-800);--accent-ink:var(--indigo-700);--ok-ink:#0f4d30;--err-ink:#7c111b;--info-ink:#00435e;--skel:#f3eeeb;
  --ease:cubic-bezier(.2,.8,.2,1);
  color-scheme:light;
}
:root[data-theme=dark]{
  --bg:#0e0a1f;--card:#161130;--surface:#1d1740;--line:#2b2452;--line-strong:#3d3470;
  --text:#ebe7f6;--muted:#aaa3c6;--faint:#8b84ab;
  --indigo-50:#231c48;--indigo-100:#30285e;
  --saffron-50:rgba(255,122,51,.12);--saffron-100:rgba(255,122,51,.3);--saffron-600:#ff8f57;
  --teal:#6fcdf0;--teal-100:rgba(56,170,214,.16);--green:#62d6a0;--green-100:rgba(62,207,142,.14);--crimson:#ff8a93;--crimson-100:rgba(255,107,120,.14);
  --ink:#f4f1ff;--accent-ink:#cbc1ff;--ok-ink:#93e8bd;--err-ink:#ffb3ba;--info-ink:#a3dcf2;--skel:#251e4d;
  --shadow:0 1px 2px rgba(0,0,0,.35),0 10px 28px -14px rgba(0,0,0,.7);
  color-scheme:dark;
}
:root[data-theme=dark] .btn-primary:hover{background:#ff5d10}
:root[data-theme=dark] .sub-hero,:root[data-theme=dark] .band{box-shadow:0 0 0 1px var(--line-strong),0 24px 48px -28px rgba(0,0,0,.9)}
:root[data-theme=dark] .topbar{background:#140e2e}
:root[data-theme=dark] .select{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' fill='none' stroke='%23aaa3c6' stroke-width='1.8' stroke-linecap='round'/%3E%3C/svg%3E")}
.skip{position:fixed;top:10px;inset-inline-start:10px;z-index:2000;padding:10px 16px;border-radius:10px;background:var(--saffron);color:#fff;font-weight:700;transform:translateY(-160%);transition:transform .2s}
.skip:focus{transform:none;text-decoration:none}
*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-text-size-adjust:100%;font-feature-settings:"locl" 0}
body,input,select,textarea,button{font-feature-settings:"locl" 0}
body{font-family:var(--font);font-size:15px;line-height:1.75;color:var(--text);background:var(--bg);transition:background-color .25s,color .25s;min-height:100vh;-webkit-font-smoothing:antialiased}
a{color:var(--teal);text-decoration:none}
a:hover{text-decoration:underline}
button,input,select,textarea{font:inherit;color:inherit}
:focus-visible{outline:3px solid color-mix(in srgb,var(--saffron) 55%,transparent);outline-offset:2px}
.ltr{direction:ltr;unicode-bidi:isolate}
.mono{font-family:var(--mono);font-size:13.5px;direction:ltr;unicode-bidi:isolate}
.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
[dir=rtl] .flip{transform:scaleX(-1)}
/* نشان Avatar: شمسهٔ هشت‌پر */
.mark{display:inline-grid;place-items:center;flex:none}
.mark svg{display:block}
.wordmark{font-weight:800;letter-spacing:.02em;font-size:20px;direction:ltr;unicode-bidi:isolate}
/* دکمه‌ها */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:40px;padding:8px 16px;border-radius:var(--radius-sm);border:1px solid transparent;font-size:14px;font-weight:600;cursor:pointer;transition:background .15s,border-color .15s,color .15s,transform .1s,box-shadow .15s;white-space:nowrap;text-decoration:none!important;user-select:none}
.btn:active{transform:translateY(1px)}
.btn svg{width:18px;height:18px;flex:none}
.btn-primary{background:var(--saffron);color:#fff;box-shadow:0 6px 16px -8px rgba(232,74,0,.8)}
.btn-primary:hover{background:var(--saffron-600)}
.btn-dark{background:var(--indigo-700);color:#fff}
.btn-dark:hover{background:var(--indigo-800)}
.btn-ghost{background:transparent;border-color:var(--line-strong);color:var(--text)}
.btn-ghost:hover{background:var(--indigo-50);border-color:var(--indigo-100)}
.btn-danger{background:transparent;border-color:color-mix(in srgb,var(--crimson) 40%,transparent);color:var(--crimson)}
.btn-danger:hover{background:var(--crimson-100)}
.btn-sm{min-height:32px;padding:4px 12px;font-size:14px;border-radius:8px}
.btn[disabled],.btn.is-busy{opacity:.6;pointer-events:none}
.btn.is-busy::before{content:"";width:14px;height:14px;border-radius:50%;border:2px solid currentColor;border-top-color:transparent;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
/* فرم‌ها */
.field{display:flex;flex-direction:column;gap:6px;min-width:0}
.field>label,.label{font-weight:600;font-size:14px;color:var(--text)}
.hint{font-size:14px;color:var(--muted);line-height:1.7}
.input,.select,.textarea{width:100%;min-height:42px;padding:9px 12px;border-radius:var(--radius-sm);border:1px solid var(--line-strong);background:var(--surface);font-size:15px;transition:border-color .15s,box-shadow .15s,background .2s}
.input:focus,.select:focus,.textarea:focus{outline:none;border-color:var(--saffron);box-shadow:0 0 0 3px color-mix(in srgb,var(--saffron) 18%,transparent)}
.input[readonly]{background:var(--bg);color:var(--muted)}
.input.ltr,.textarea.ltr{direction:ltr;text-align:left;font-family:var(--mono);font-size:14px}
.input.ltr::placeholder,.textarea.ltr::placeholder{text-align:left}
.textarea{min-height:140px;resize:vertical;line-height:1.7}
.select{appearance:none;-webkit-appearance:none;padding-left:36px;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' fill='none' stroke='%236f5f59' stroke-width='1.8' stroke-linecap='round'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:left 14px center}
.input-group{display:flex;gap:8px;align-items:stretch}
.input-group>.input{flex:1;min-width:0}
/* کلید روشن/خاموش */
.switch{display:flex;align-items:flex-start;gap:12px;cursor:pointer;padding:4px 0}
.switch input{position:absolute;opacity:0;pointer-events:none}
.switch .track{flex:none;position:relative;width:42px;height:24px;border-radius:99px;background:var(--line-strong);transition:background .2s;margin-top:2px}
.switch .track::after{content:"";position:absolute;top:3px;right:3px;width:18px;height:18px;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.25);transition:transform .2s}
.switch input:checked+.track{background:var(--saffron)}
.switch input:checked+.track::after{transform:translateX(-18px)}
.switch input:focus-visible+.track{outline:3px solid color-mix(in srgb,var(--saffron) 55%,transparent);outline-offset:2px}
.switch .switch-text{display:flex;flex-direction:column}
.switch .switch-text b{font-weight:600;font-size:14.5px}
.switch .switch-text span{font-size:14px;color:var(--muted)}
/* اعلان کوتاه */
#toasts{position:fixed;top:16px;left:50%;transform:translateX(-50%);z-index:1000;display:flex;flex-direction:column;gap:8px;align-items:center;pointer-events:none;width:min(92vw,440px)}
.toast{pointer-events:auto;display:flex;gap:10px;align-items:flex-start;width:100%;padding:12px 16px;border-radius:12px;background:var(--indigo-800);color:#fff;font-size:14.5px;box-shadow:0 12px 32px -12px rgba(22,15,51,.6);animation:toastIn .25s ease-out}
.toast.ok{border-inline-start:4px solid #3ecf8e}
.toast.err{border-inline-start:4px solid #ff6b6b}
.toast.info{border-inline-start:4px solid #ffb547}
.toast.out{animation:toastOut .2s ease-in forwards}
@keyframes toastIn{from{opacity:0;transform:translateY(-8px)}}
@keyframes toastOut{to{opacity:0;transform:translateY(-8px)}}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}}
.input.ltr.ph-fa:placeholder-shown{direction:rtl;text-align:right;font-family:var(--font)}
</style>
<script>(function(){try{var t=localStorage.getItem('avatar-theme');if(t!=='dark'&&t!=='light')t=matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';document.documentElement.dataset.theme=t;}catch(e){}})();</script>`;
const Avatar_صفحات = {
	login: `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="#1f1647">
<title>ورود به پنل · Avatar</title>
<meta name="description" content="ورود امن به پنل مدیریت Avatar">
<meta property="og:title" content="Avatar">
<meta property="og:description" content="پنل مدیریت Avatar">
<meta property="og:type" content="website">
<meta property="og:locale" content="fa_IR">
<link rel="icon" href="data:image/svg+xml,%3Csvg viewBox=%220 0 48 48%22 width=%2248%22 height=%2248%22 xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cg transform=%22translate%2824 24%29%22%3E%3Crect x=%22-15%22 y=%22-15%22 width=%2230%22 height=%2230%22 rx=%223%22 fill=%22%23e84a00%22/%3E%3Crect x=%22-15%22 y=%22-15%22 width=%2230%22 height=%2230%22 rx=%223%22 fill=%22%23e84a00%22 transform=%22rotate%2845%29%22/%3E%3Ccircle r=%229.5%22 fill=%22%232c1f62%22/%3E%3Cpath d=%22M0-6.2 5.4 3.1H-5.4Z%22 fill=%22%23fff%22/%3E%3Ccircle r=%221.6%22 cy=%220.8%22 fill=%22%232c1f62%22/%3E%3C/g%3E%3C/svg%3E">
<!--AVATAR:STYLE-->
<style>
body{background:var(--indigo-900);color:#fff;display:grid;place-items:center;padding:24px;overflow-x:hidden}
.pattern{position:fixed;inset:-80px;z-index:0;opacity:.5;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='96' height='96' viewBox='0 0 96 96'%3E%3Cg fill='none' stroke='%23ffffff' stroke-opacity='.13'%3E%3Crect x='34' y='34' width='28' height='28'/%3E%3Crect x='34' y='34' width='28' height='28' transform='rotate%2845 48 48%29'/%3E%3Cpath d='M48 0v14M48 82v14M0 48h14M82 48h14'/%3E%3Ccircle cx='0' cy='0' r='10'/%3E%3Ccircle cx='96' cy='0' r='10'/%3E%3Ccircle cx='0' cy='96' r='10'/%3E%3Ccircle cx='96' cy='96' r='10'/%3E%3C/g%3E%3Ccircle cx='48' cy='48' r='2.2' fill='%23e84a00' fill-opacity='.55'/%3E%3C/svg%3E");background-size:96px 96px;animation:drift 90s linear infinite;pointer-events:none}
.glow{position:fixed;inset:0;z-index:0;background:radial-gradient(60vmax 50vmax at 85% 10%,rgba(232,74,0,.28),transparent 60%),radial-gradient(50vmax 40vmax at 10% 100%,rgba(0,98,137,.35),transparent 60%);pointer-events:none}
@keyframes drift{to{transform:translate(96px,96px)}}
.wrap{position:relative;z-index:1;width:min(100%,420px)}
.card{background:var(--card);color:var(--text);border-radius:20px;padding:36px 32px 28px;box-shadow:0 30px 80px -30px rgba(0,0,0,.6);animation:rise .5s cubic-bezier(.2,.8,.2,1) both}
@keyframes rise{from{opacity:0;transform:translateY(16px)}}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:28px}
.brand .mark svg{animation:turn 60s linear infinite}
@keyframes turn{to{transform:rotate(360deg)}}
h1{font-size:26px;font-weight:800;line-height:1.4;margin-bottom:6px}
.lead{color:var(--muted);font-size:15px;margin-bottom:24px}
.pw{position:relative}
.pw .input{padding-left:48px;direction:ltr;text-align:left;font-family:var(--mono);letter-spacing:.06em;height:48px}
.pw .input::placeholder{font-family:var(--font);letter-spacing:0;text-align:right;direction:rtl}
.eye{position:absolute;left:6px;top:50%;transform:translateY(-50%);width:36px;height:36px;border:0;background:transparent;border-radius:8px;display:grid;place-items:center;cursor:pointer;color:var(--muted)}
.eye:hover{background:var(--indigo-50);color:var(--text)}
.eye svg{width:20px;height:20px}
.submit{width:100%;height:48px;margin-top:16px;font-size:16px}
.error{display:none;margin-top:14px;padding:10px 14px;border-radius:10px;background:var(--crimson-100);color:var(--crimson);font-size:14.5px;font-weight:500}
.error.show{display:block;animation:shake .4s}
@keyframes shake{20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}
.caps{display:none;margin-top:8px;font-size:14px;color:var(--saffron-600)}
.caps.show{display:block}
.foot{margin-top:18px;text-align:center;font-size:14px;color:rgba(255,255,255,.62)}
.foot b{color:#fff;font-weight:700}
@media (max-width:420px){.card{padding:28px 20px 22px}h1{font-size:22px}}
</style>
</head>
<body>
<div class="pattern" aria-hidden="true"></div><div class="glow" aria-hidden="true"></div>
<main class="wrap">
  <section class="card" aria-labelledby="title">
    <div class="brand"><span class="mark"><svg viewBox="0 0 48 48" width="44" height="44" aria-hidden="true"><g transform="translate(24 24)"><rect x="-15" y="-15" width="30" height="30" rx="3" fill="#e84a00"/><rect x="-15" y="-15" width="30" height="30" rx="3" fill="#e84a00" transform="rotate(45)"/><circle r="9.5" fill="#2c1f62"/><path d="M0-6.2 5.4 3.1H-5.4Z" fill="#fff"/><circle r="1.6" cy="0.8" fill="#2c1f62"/></g></svg></span><span class="wordmark">Avatar</span></div>
    <h1 id="title">ورود به پنل مدیریت</h1>
    <p class="lead">برای ادامه، رمز عبور مدیر را وارد کنید.</p>
    <form id="loginForm" novalidate>
      <label class="sr-only" for="password">رمز عبور</label>
      <div class="pw">
        <input class="input" id="password" name="password" type="password" autocomplete="current-password" placeholder="رمز عبور" required autofocus>
        <button class="eye" type="button" id="togglePw" aria-label="نمایش رمز عبور" title="نمایش رمز عبور">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
      </div>
      <p class="caps" id="caps" role="status">کلید Caps Lock روشن است.</p>
      <button class="btn btn-primary submit" id="loginBtn" type="submit">ورود</button>
      <p class="error" id="errorMsg" role="alert"></p>
    </form>
  </section>
  <p class="foot"><b>Avatar</b> · اتصال امن و پایدار</p>
</main>
<script>
(function(){
  var form=document.getElementById('loginForm'),input=document.getElementById('password'),btn=document.getElementById('loginBtn'),err=document.getElementById('errorMsg'),eye=document.getElementById('togglePw'),caps=document.getElementById('caps');
  function showError(t){err.textContent=t;err.classList.remove('show');void err.offsetWidth;err.classList.add('show');}
  eye.addEventListener('click',function(){var v=input.type==='password';input.type=v?'text':'password';var l=v?'پنهان کردن رمز عبور':'نمایش رمز عبور';eye.setAttribute('aria-label',l);eye.title=l;input.focus();});
  input.addEventListener('keyup',function(e){if(e.getModifierState)caps.classList.toggle('show',e.getModifierState('CapsLock'));});
  form.addEventListener('submit',function(e){
    e.preventDefault();
    if(!input.value){showError('لطفاً رمز عبور را وارد کنید.');input.focus();return;}
    err.classList.remove('show');btn.classList.add('is-busy');btn.disabled=true;btn.textContent='در حال بررسی…';
    fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'password='+encodeURIComponent(input.value),credentials:'same-origin'})
      .then(function(r){var ct=r.headers.get('content-type')||'';if(ct.indexOf('application/json')===-1)return {success:false,status:r.status};return r.json().then(function(d){d.status=r.status;return d;});})
      .then(function(d){
        if(d&&d.success){btn.textContent='ورود موفق، در حال انتقال…';location.href='/admin';return;}
        var fa=function(n){return new Intl.NumberFormat('fa-IR').format(n);};
        if(d&&d.status===429){var m=Math.max(1,Math.ceil((d.retryAfter||900)/60));showError('به‌دلیل تلاش‌های ناموفق پیاپی، ورود برای '+fa(m)+' دقیقه قفل شد.');reset();return;}
        var msg=d&&(d.status===401||d.status===200)?'رمز عبور نادرست است.':'ورود ناموفق بود. لحظاتی بعد دوباره تلاش کنید.';
        if(d&&typeof d.remaining==='number'&&d.remaining<=2)msg+=d.remaining>0?' '+fa(d.remaining)+' تلاش دیگر باقی مانده است.':' ورود موقتاً قفل شد.';
        showError(msg);
        input.focus();input.select();reset();
      })
      .catch(function(){showError('ارتباط با سرور برقرار نشد. اتصال اینترنت خود را بررسی کنید.');reset();});
  });
  function reset(){btn.classList.remove('is-busy');btn.disabled=false;btn.textContent='ورود';}
})();
</script>
</body>
</html>
`,
	admin: `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="#1f1647">
<title>پنل مدیریت · Avatar</title>
<meta name="description" content="پنل مدیریت Avatar: اشتراک، تنظیمات گره، آی‌پی‌های بهینه و گزارش‌ها">
<meta property="og:title" content="پنل مدیریت Avatar">
<meta property="og:site_name" content="Avatar">
<meta property="og:type" content="website">
<meta property="og:locale" content="fa_IR">
<link rel="icon" href="data:image/svg+xml,%3Csvg viewBox=%220 0 48 48%22 width=%2248%22 height=%2248%22 xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cg transform=%22translate%2824 24%29%22%3E%3Crect x=%22-15%22 y=%22-15%22 width=%2230%22 height=%2230%22 rx=%223%22 fill=%22%23e84a00%22/%3E%3Crect x=%22-15%22 y=%22-15%22 width=%2230%22 height=%2230%22 rx=%223%22 fill=%22%23e84a00%22 transform=%22rotate%2845%29%22/%3E%3Ccircle r=%229.5%22 fill=%22%232c1f62%22/%3E%3Cpath d=%22M0-6.2 5.4 3.1H-5.4Z%22 fill=%22%23fff%22/%3E%3Ccircle r=%221.6%22 cy=%220.8%22 fill=%22%232c1f62%22/%3E%3C/g%3E%3C/svg%3E">
<!--AVATAR:STYLE-->
<style>body{background:var(--bg)}
/* نوار بالا */
.topbar{position:sticky;top:0;z-index:50;background:var(--indigo-800);color:#fff;border-bottom:3px solid var(--saffron)}
.topbar::before{content:"";position:absolute;inset:0;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='96' height='96' viewBox='0 0 96 96'%3E%3Cg fill='none' stroke='%23ffffff' stroke-opacity='.13'%3E%3Crect x='34' y='34' width='28' height='28'/%3E%3Crect x='34' y='34' width='28' height='28' transform='rotate%2845 48 48%29'/%3E%3Cpath d='M48 0v14M48 82v14M0 48h14M82 48h14'/%3E%3Ccircle cx='0' cy='0' r='10'/%3E%3Ccircle cx='96' cy='0' r='10'/%3E%3Ccircle cx='0' cy='96' r='10'/%3E%3Ccircle cx='96' cy='96' r='10'/%3E%3C/g%3E%3Ccircle cx='48' cy='48' r='2.2' fill='%23e84a00' fill-opacity='.55'/%3E%3C/svg%3E");background-size:96px 96px;opacity:.22;pointer-events:none}
.topbar-in{position:relative;display:flex;align-items:center;gap:14px;max-width:1320px;margin:0 auto;padding:10px 20px;min-height:62px}
.brand{display:flex;align-items:center;gap:10px;color:#fff;text-decoration:none!important}
.brand small{display:block;font-size:14px;color:rgba(255,255,255,.66);font-weight:500;line-height:1.2}
.brand .wordmark{line-height:1.1}
.topbar .spacer{flex:1}
.host-chip{display:inline-flex;align-items:center;gap:8px;max-width:38vw;padding:5px 12px;border-radius:99px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.16);font-family:var(--mono);font-size:13.5px;direction:ltr;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.host-chip i{width:8px;height:8px;border-radius:50%;background:#3ecf8e;box-shadow:0 0 0 3px rgba(62,207,142,.25);flex:none}
.btn-top{background:rgba(255,255,255,.08);border-color:rgba(255,255,255,.2);color:#fff}
.btn-top:hover{background:rgba(255,255,255,.16)}
/* چیدمان */
.shell{display:grid;grid-template-columns:232px minmax(0,1fr);gap:28px;max-width:1320px;margin:0 auto;padding:24px 20px 120px}
.sidenav{position:sticky;top:88px;align-self:start;display:flex;flex-direction:column;gap:2px}
.nav-item{display:flex;align-items:center;gap:12px;padding:10px 14px;border-radius:12px;color:var(--text);font-weight:500;font-size:15px;text-decoration:none!important;position:relative;transition:background .15s,color .15s}
.nav-item svg{width:20px;height:20px;flex:none;color:var(--muted);transition:color .15s}
.nav-item:hover{background:var(--indigo-50)}
.nav-item[aria-current=page]{background:var(--surface);color:var(--accent-ink);font-weight:700;box-shadow:var(--shadow)}
.nav-item[aria-current=page] svg{color:var(--saffron)}
.nav-item[aria-current=page]::before{content:"";position:absolute;inset-inline-start:0;top:10px;bottom:10px;width:3px;border-radius:3px;background:var(--saffron)}
.nav-sep{height:1px;background:var(--line);margin:10px 14px}
.nav-meta{padding:8px 14px;font-size:14px;color:var(--faint)}
main{min-width:0}
.view{display:none;animation:viewIn .25s ease-out}
.view.active{display:block}
@keyframes viewIn{from{opacity:0;transform:translateY(6px)}}
.view-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:18px;flex-wrap:wrap}
.view-head h1{font-size:28px;font-weight:800;line-height:1.35;color:var(--ink);letter-spacing:-.01em}
.view-head p{color:var(--muted);font-size:15.5px;max-width:62ch}
/* کارت */
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);padding:22px;margin-bottom:18px}
.card-h{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:16px}
.card-h h2{font-size:18px;font-weight:700;line-height:1.5}
.card-h p{font-size:14px;color:var(--muted);margin-top:2px}
.grid{display:grid;gap:16px}
.g2{grid-template-columns:repeat(2,minmax(0,1fr))}
.g3{grid-template-columns:repeat(3,minmax(0,1fr))}
.span2{grid-column:span 2}
.stack{display:flex;flex-direction:column;gap:12px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.hidden{display:none!important}
/* انتخاب‌گر بخش‌بندی */
.seg{display:inline-flex;flex-wrap:wrap;gap:4px;padding:4px;background:var(--bg);border:1px solid var(--line);border-radius:12px}
.seg button{border:0;background:transparent;padding:7px 14px;border-radius:9px;font-size:14.5px;font-weight:600;color:var(--muted);cursor:pointer;min-height:36px}
.seg button:hover{color:var(--text)}
.seg button[aria-pressed=true]{background:var(--surface);color:var(--accent-ink);box-shadow:0 1px 3px rgba(42,31,28,.14)}
.choice{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
.choice button{display:flex;flex-direction:column;align-items:flex-start;gap:2px;text-align:start;padding:12px 14px;border-radius:12px;border:1.5px solid var(--line);background:var(--surface);cursor:pointer;transition:border-color .15s,background .15s,transform .15s}
.choice button b{font-size:15.5px;direction:ltr;unicode-bidi:isolate}
.choice button span{font-size:14px;color:var(--muted)}
.choice button:hover{border-color:var(--line-strong);transform:translateY(-1px)}
.card{transition:background-color .25s,border-color .25s}
.empty-cta{display:flex;align-items:center;gap:14px;padding:16px;border-radius:14px;background:var(--bg);border:1px dashed var(--line-strong)}
.empty-cta>svg{width:40px;height:40px;flex:none;color:var(--saffron);padding:8px;border-radius:12px;background:var(--saffron-50)}
.empty-cta div{flex:1;min-width:0}
.empty-cta b{display:block;font-size:15px}
.empty-cta span{display:block;font-size:14px;color:var(--muted);line-height:1.7}
.empty-cta .btn{flex:none}
.ov-col{display:flex;flex-direction:column;gap:18px;min-width:0}
.ov-col>.card{margin-bottom:0}
.theme-btn svg{width:18px;height:18px}
.theme-btn .i-sun{display:none}
:root[data-theme=dark] .theme-btn .i-sun{display:block}
:root[data-theme=dark] .theme-btn .i-moon{display:none}
.choice button[aria-pressed=true]{border-color:var(--saffron);background:var(--saffron-50)}
.choice button[aria-pressed=true] b{color:var(--saffron-600)}
/* اشتراک: کارت شاخص */
.sub-hero{position:relative;overflow:hidden;background:var(--indigo-800);color:#fff;border-radius:20px;padding:26px;margin-bottom:18px;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:26px;box-shadow:0 24px 48px -28px rgba(22,15,51,.8)}
.sub-hero::before{content:"";position:absolute;inset:0;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='96' height='96' viewBox='0 0 96 96'%3E%3Cg fill='none' stroke='%23ffffff' stroke-opacity='.13'%3E%3Crect x='34' y='34' width='28' height='28'/%3E%3Crect x='34' y='34' width='28' height='28' transform='rotate%2845 48 48%29'/%3E%3Cpath d='M48 0v14M48 82v14M0 48h14M82 48h14'/%3E%3Ccircle cx='0' cy='0' r='10'/%3E%3Ccircle cx='96' cy='0' r='10'/%3E%3Ccircle cx='0' cy='96' r='10'/%3E%3Ccircle cx='96' cy='96' r='10'/%3E%3C/g%3E%3Ccircle cx='48' cy='48' r='2.2' fill='%23e84a00' fill-opacity='.55'/%3E%3C/svg%3E");background-size:96px 96px;opacity:.28;pointer-events:none}
.sub-hero::after{content:"";position:absolute;inset-inline-end:-120px;top:-120px;width:340px;height:340px;border-radius:50%;background:radial-gradient(circle,rgba(232,74,0,.45),transparent 65%);pointer-events:none;animation:breathe 9s ease-in-out infinite}
@keyframes breathe{50%{transform:scale(1.12);opacity:.75}}
.sub-hero>*{position:relative;z-index:1}
.sub-hero .eyebrow{font-size:14px;font-weight:600;color:#ffc7a8}
.sub-hero h2{font-size:26px;font-weight:800;line-height:1.4;margin:2px 0 14px}
.sub-url{display:flex;align-items:center;gap:8px;background:rgba(0,0,0,.25);border:1px solid rgba(255,255,255,.14);border-radius:12px;padding:6px 6px 6px 14px}
.sub-url code{flex:1;min-width:0;font-family:var(--mono);font-size:14px;direction:ltr;text-align:left;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:#fff}
.sub-url .btn{flex:none}
.formats{display:flex;flex-wrap:wrap;gap:6px;margin-top:14px}
.formats button{border:1px solid rgba(255,255,255,.2);background:transparent;color:rgba(255,255,255,.85);padding:5px 13px;border-radius:99px;font-size:14px;font-weight:500;cursor:pointer;min-height:34px}
.formats button:hover{background:rgba(255,255,255,.08)}
.formats button[aria-pressed=true]{background:#fff;color:var(--indigo-800);border-color:#fff;font-weight:700}
.imports{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px;align-items:center}
.imports .lbl{font-size:14px;color:rgba(255,255,255,.66);margin-inline-end:4px}
.qr-box{background:#fff;border-radius:16px;padding:12px;display:grid;place-items:center;width:212px;height:212px;cursor:zoom-in;border:0}
.qr-box svg{width:188px;height:188px;display:block}
.qr-cap{text-align:center;color:rgba(255,255,255,.7);font-size:14px;margin-top:8px}
/* آمار */
.overview-grid{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(0,1fr);gap:18px}
.meter{height:12px;border-radius:99px;background:var(--indigo-50);overflow:hidden;margin:14px 0 10px}
.meter i{display:block;height:100%;border-radius:inherit;background:linear-gradient(90deg,var(--teal),var(--saffron));width:0;transition:width .9s cubic-bezier(.2,.8,.2,1)}
.big-num{font-size:34px;font-weight:800;line-height:1.2;color:var(--ink)}
.big-num small{font-size:15px;font-weight:500;color:var(--muted)}
.kv{display:grid;grid-template-columns:auto minmax(0,1fr);gap:0;font-size:14.5px}
.kv dt{color:var(--muted);padding:9px 0;border-bottom:1px dashed var(--line);padding-inline-end:16px;white-space:nowrap}
.kv dd{padding:9px 0;border-bottom:1px dashed var(--line);font-weight:600;text-align:end;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.kv dt:nth-last-of-type(1),.kv dd:last-of-type{border-bottom:0}
.pill{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:99px;font-size:14px;font-weight:600;background:var(--indigo-50);color:var(--accent-ink);white-space:nowrap}
.pill.ok{background:var(--green-100);color:var(--green)}
.pill.warn{background:var(--saffron-50);color:var(--saffron-600)}
.pill.off{background:var(--bg);color:var(--muted)}
.empty-note{color:var(--muted);font-size:14.5px;padding:6px 0}
.link-line{display:flex;gap:8px;align-items:center}
.link-line code{flex:1;min-width:0;font-family:var(--mono);font-size:13.5px;direction:ltr;text-align:left;background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:9px 12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
/* ویرایشگر */
.editor-wrap{position:relative}
.editor-wrap .textarea{min-height:320px;font-size:14px;line-height:1.8}
.editor-meta{display:flex;justify-content:space-between;gap:10px;font-size:14px;color:var(--muted);margin-top:8px;flex-wrap:wrap}
.help-list{display:grid;gap:8px;font-size:14px;color:var(--muted)}
.help-list div{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.2fr);gap:12px;align-items:center;padding:8px 10px;border-radius:10px;background:var(--bg)}
.help-list code{font-family:var(--mono);font-size:13px;direction:ltr;text-align:left;color:var(--accent-ink);overflow-wrap:anywhere}
.result{margin-top:12px;border-radius:12px;padding:12px 14px;font-size:14.5px;display:none}
.result.show{display:block}
.result.ok{background:var(--green-100);color:var(--ok-ink)}
.result.err{background:var(--crimson-100);color:var(--err-ink)}
.result.info{background:var(--indigo-50);color:var(--ink)}
.result pre{margin-top:8px;max-height:220px;overflow:auto;font-family:var(--mono);font-size:13px;direction:ltr;text-align:left;white-space:pre-wrap;word-break:break-all}
/* گزارش‌ها */
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
.toolbar .input{flex:1;min-width:200px}
.toolbar .select{width:auto;min-width:180px}
.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:var(--surface)}
table{width:100%;border-collapse:collapse;font-size:14px}
th{position:sticky;top:0;background:var(--indigo-50);color:var(--ink);font-weight:700;text-align:start;padding:10px 12px;white-space:nowrap}
td{padding:10px 12px;border-top:1px solid var(--line);vertical-align:top}
td.ltr-cell{direction:ltr;text-align:right;font-family:var(--mono);font-size:13px;unicode-bidi:plaintext}
td .ua{display:block;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:ltr;text-align:left;font-family:var(--mono);font-size:13px;color:var(--muted)}
tbody tr:hover{background:var(--saffron-50)}
.type-tag{display:inline-block;padding:1px 9px;border-radius:99px;font-size:14px;font-weight:600;white-space:nowrap;background:var(--indigo-50);color:var(--accent-ink)}
.type-tag.t-sub{background:var(--teal-100);color:var(--info-ink)}
.type-tag.t-login{background:var(--saffron-50);color:var(--saffron-600)}
.type-tag.t-save{background:var(--green-100);color:var(--green)}
.type-tag.t-init{background:var(--crimson-100);color:var(--crimson)}
.pager{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:12px;font-size:14px;color:var(--muted);flex-wrap:wrap}
.empty{text-align:center;padding:48px 20px;color:var(--muted)}
.empty svg{width:56px;height:56px;margin-bottom:10px;opacity:.8}
.empty b{display:block;color:var(--text);font-size:16px;margin-bottom:4px}
/* اسکلت بارگذاری */
.skeleton{background:linear-gradient(90deg,var(--line) 0,var(--skel) 40%,var(--line) 80%);background-size:300% 100%;animation:sk 1.4s ease-in-out infinite;border-radius:10px}
@keyframes sk{from{background-position:100% 0}to{background-position:0 0}}
#boot{display:grid;gap:18px}
#boot .skeleton{height:120px}
#boot .skeleton.tall{height:240px;border-radius:20px}
.fatal{text-align:center;padding:56px 24px}
.fatal h2{font-size:22px;margin:10px 0 6px}
.fatal p{color:var(--muted);margin-bottom:18px}
/* منطقهٔ خطر */
.danger{border-color:color-mix(in srgb,var(--crimson) 30%,var(--line))}
.danger .card-h h2{color:var(--crimson)}
/* نوار ذخیره */
.savebar{position:fixed;bottom:18px;left:50%;transform:translate(-50%,140%);z-index:60;display:flex;align-items:center;gap:12px;padding:10px 10px 10px 10px;padding-inline-start:18px;border-radius:16px;background:var(--indigo-900);color:#fff;box-shadow:0 18px 40px -16px rgba(22,15,51,.8);transition:transform .3s cubic-bezier(.2,.8,.2,1);width:max-content;max-width:calc(100vw - 24px)}
.savebar:not(.show){visibility:hidden;transition:transform .3s var(--ease),visibility 0s .3s}
.savebar.show{transform:translate(-50%,0)}
.savebar .dot{width:9px;height:9px;border-radius:50%;background:var(--saffron);box-shadow:0 0 0 4px rgba(232,74,0,.3);animation:pulse 1.6s ease-in-out infinite;flex:none}
@keyframes pulse{50%{box-shadow:0 0 0 7px rgba(232,74,0,.08)}}
.savebar span{font-size:14.5px;font-weight:500}
.savebar .btn-ghost{color:#fff;border-color:rgba(255,255,255,.25)}
.savebar .btn-ghost:hover{background:rgba(255,255,255,.1)}
/* پنجرهٔ گفت‌وگو */
dialog{border:0;border-radius:18px;padding:0;max-width:min(92vw,460px);width:100%;box-shadow:0 30px 80px -20px rgba(22,15,51,.6);color:var(--text);background:var(--card);margin:auto}
dialog::backdrop{background:rgba(22,15,51,.55);backdrop-filter:blur(3px)}
dialog[open]{animation:dlg .2s ease-out}
@keyframes dlg{from{opacity:0;transform:scale(.97)}}
.dlg-b{padding:24px}
.dlg-b h3{font-size:19px;font-weight:800;margin-bottom:6px}
.dlg-b p{color:var(--muted);font-size:15px}
.dlg-f{display:flex;gap:10px;justify-content:flex-end;padding:0 24px 22px;flex-wrap:wrap}
#qrDialog{max-width:min(92vw,420px)}
#qrDialog .qr-big{background:#fff;border:1px solid var(--line);border-radius:14px;padding:14px;display:grid;place-items:center;margin:14px 0}
#qrDialog .qr-big svg{width:100%;max-width:320px;height:auto}
#qrDialog code{display:block;font-family:var(--mono);font-size:13px;direction:ltr;text-align:left;word-break:break-all;color:var(--muted);background:var(--bg);border-radius:10px;padding:8px 10px;max-height:96px;overflow:auto}
.foot{max-width:1320px;margin:0 auto;padding:0 20px 28px;color:var(--faint);font-size:14px;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}
/* واکنش‌گرا */
@media (max-width:1080px){.overview-grid{grid-template-columns:minmax(0,1fr)}}
@media (max-width:900px){
  .shell{grid-template-columns:minmax(0,1fr);padding-top:0;gap:16px}
  .sidenav{position:sticky;top:65px;z-index:40;flex-direction:row;overflow-x:auto;margin:0 -20px;padding:8px 16px;background:color-mix(in srgb,var(--bg) 92%,transparent);backdrop-filter:blur(8px);border-bottom:1px solid var(--line);scrollbar-width:none}
  .sidenav::-webkit-scrollbar{display:none}
  .sidenav{-webkit-mask-image:linear-gradient(to left,transparent 0,#000 18px,#000 calc(100% - 18px),transparent 100%);mask-image:linear-gradient(to left,transparent 0,#000 18px,#000 calc(100% - 18px),transparent 100%)}
  .nav-item{flex:none;padding:7px 12px;font-size:14.5px}
  .nav-item[aria-current=page]::before{display:none}
  .nav-sep,.nav-meta{display:none}
  .sub-hero{grid-template-columns:minmax(0,1fr)}
  .qr-wrap{display:none}
  .host-chip{display:none}
}
@media (max-width:640px){
  .empty-cta{flex-wrap:wrap}
  .empty-cta .btn{width:100%}
  .g2,.g3,.choice{grid-template-columns:minmax(0,1fr)}
  .span2{grid-column:auto}
  .card{padding:18px}
  .view-head h1{font-size:23px}
  .sub-hero{padding:20px;border-radius:16px}
  .sub-hero h2{font-size:21px}
  .topbar-in{padding:8px 14px}
  .brand small{display:none}
  .btn-top .t{display:none}
  .help-list div{grid-template-columns:minmax(0,1fr)}
  .savebar{bottom:10px;gap:8px;padding-inline-start:12px}
  .savebar span{display:none}
  .kv dd{white-space:normal;overflow-wrap:anywhere}
  table.logs thead{display:none}
  table.logs tr{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 10px;padding:12px;border-top:1px solid var(--line)}
  table.logs td{border:0;padding:0}
  table.logs td.c-path,table.logs td.c-ua,table.logs td.c-asn{grid-column:1/-1}
  table.logs td.c-time{grid-column:1/-1;color:var(--muted);font-size:14px}
}
</style>
</head>
<body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
  <defs>
    <symbol id="i-home" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1Z"/></symbol>
    <symbol id="i-node" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 2v4M12 18v4M4.9 4.9l2.8 2.8M16.3 16.3l2.8 2.8M2 12h4M18 12h4M4.9 19.1l2.8-2.8M16.3 7.7l2.8-2.8"/></symbol>
    <symbol id="i-bolt" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 4 14h7l-1 8 9-12h-7Z"/></symbol>
    <symbol id="i-swap" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h13l-3-3M20 17H7l3 3"/></symbol>
    <symbol id="i-shield" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6Z"/><path d="m9 12 2 2 4-4"/></symbol>
    <symbol id="i-plug" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 2v6M15 2v6M6 8h12v3a6 6 0 0 1-12 0Z"/><path d="M12 17v5"/></symbol>
    <symbol id="i-list" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></symbol>
    <symbol id="i-code" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m8 7-5 5 5 5M16 7l5 5-5 5"/></symbol>
    <symbol id="i-copy" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></symbol>
    <symbol id="i-qr" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3M21 14v.01M14 21h3M21 17v4h-1"/></symbol>
    <symbol id="i-out" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l-5-5 5-5M5 12h12"/></symbol>
    <symbol id="i-ext" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 4h6v6M20 4 10 14M19 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5"/></symbol>
    <symbol id="i-refresh" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 11a8 8 0 0 0-14.9-3M4 4v4h4M4 13a8 8 0 0 0 14.9 3M20 20v-4h-4"/></symbol>
    <symbol id="i-down" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12M7 10l5 5 5-5M4 21h16"/></symbol>
    <symbol id="i-up" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 21V9M7 14l5-5 5 5M4 3h16"/></symbol>
    <symbol id="i-chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 18-6-6 6-6"/></symbol>
    <symbol id="i-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5Z"/></symbol>
    <symbol id="i-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></symbol>
    <symbol id="i-chart" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><path d="m7 15 4-4 3 3 5-6"/></symbol>
    <symbol id="i-inbox" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.5 5h13L22 12v6a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-6Z"/></symbol>
  </defs>
</svg>

<a class="skip" href="#main" id="skipLink">رفتن به محتوای اصلی</a>
<header class="topbar">
  <div class="topbar-in">
    <a class="brand" href="#overview" aria-label="Avatar، صفحهٔ پیشخوان"><span class="mark"><svg viewBox="0 0 48 48" width="36" height="36" aria-hidden="true"><g transform="translate(24 24)"><rect x="-15" y="-15" width="30" height="30" rx="3" fill="#e84a00"/><rect x="-15" y="-15" width="30" height="30" rx="3" fill="#e84a00" transform="rotate(45)"/><circle r="9.5" fill="#2c1f62"/><path d="M0-6.2 5.4 3.1H-5.4Z" fill="#fff"/><circle r="1.6" cy="0.8" fill="#2c1f62"/></g></svg></span><span><span class="wordmark">Avatar</span><small>پنل مدیریت</small></span></a>
    <span class="spacer"></span>
    <span class="host-chip" id="hostChip" title="دامنهٔ فعلی"><i></i><span id="hostText">…</span></span>
    <button class="btn btn-sm btn-top theme-btn" type="button" id="themeBtn" aria-label="تغییر پوسته به تیره" title="تغییر پوسته"><svg class="i-moon"><use href="#i-moon"/></svg><svg class="i-sun"><use href="#i-sun"/></svg></button>
    <a class="btn btn-sm btn-top" href="/logout" id="logoutBtn"><svg class="flip"><use href="#i-out"/></svg><span class="t">خروج</span></a>
  </div>
</header>

<div class="shell">
  <nav class="sidenav" aria-label="بخش‌های پنل">
    <a class="nav-item" href="#overview" data-view="overview"><svg><use href="#i-home"/></svg>پیشخوان</a>
    <a class="nav-item" href="#node" data-view="node"><svg><use href="#i-node"/></svg>گره و پروتکل</a>
    <a class="nav-item" href="#preferred" data-view="preferred"><svg><use href="#i-bolt"/></svg>آی‌پی‌های بهینه</a>
    <a class="nav-item" href="#convert" data-view="convert"><svg><use href="#i-swap"/></svg>تبدیل اشتراک</a>
    <a class="nav-item" href="#proxy" data-view="proxy"><svg><use href="#i-shield"/></svg>پراکسی و مسیریابی</a>
    <a class="nav-item" href="#integrations" data-view="integrations"><svg><use href="#i-plug"/></svg>اعلان و آمار</a>
    <a class="nav-item" href="#logs" data-view="logs"><svg><use href="#i-list"/></svg>گزارش‌ها</a>
    <div class="nav-sep"></div>
    <a class="nav-item" href="#advanced" data-view="advanced"><svg><use href="#i-code"/></svg>پیشرفته</a>
    <div class="nav-meta" id="navMeta"></div>
  </nav>

  <main id="main" tabindex="-1">
    <div id="boot" aria-busy="true" aria-label="در حال بارگذاری"><div class="skeleton tall"></div><div class="skeleton"></div><div class="skeleton"></div></div>
    <div id="fatal" class="card fatal hidden" role="alert">
      <span class="mark"><svg viewBox="0 0 48 48" width="48" height="48" aria-hidden="true"><g transform="translate(24 24)"><rect x="-15" y="-15" width="30" height="30" rx="3" fill="#e84a00"/><rect x="-15" y="-15" width="30" height="30" rx="3" fill="#e84a00" transform="rotate(45)"/><circle r="9.5" fill="#2c1f62"/><path d="M0-6.2 5.4 3.1H-5.4Z" fill="#fff"/><circle r="1.6" cy="0.8" fill="#2c1f62"/></g></svg></span>
      <h2>بارگذاری تنظیمات ناموفق بود</h2>
      <p id="fatalMsg">ارتباط با سرور برقرار نشد.</p>
      <button class="btn btn-primary" type="button" id="retryBtn"><svg><use href="#i-refresh"/></svg>تلاش دوباره</button>
    </div>

    <!-- پیشخوان -->
    <section class="view" id="view-overview" aria-labelledby="h-overview">
      <div class="view-head"><div><h1 id="h-overview">پیشخوان</h1><p>لینک اشتراک را بردارید، به برنامه اضافه کنید و وضعیت سرویس را یک‌جا ببینید.</p></div></div>
      <div class="sub-hero">
        <div>
          <div class="eyebrow">لینک اشتراک شخصی</div>
          <h2 id="subName">اشتراک</h2>
          <div class="sub-url"><code id="subUrl" title="لینک اشتراک">…</code><button class="btn btn-primary btn-sm" type="button" id="copySub"><svg><use href="#i-copy"/></svg>کپی</button><button class="btn btn-sm btn-top" type="button" id="qrSubBtn" aria-label="نمایش کد QR"><svg><use href="#i-qr"/></svg></button></div>
          <div class="formats" id="formats" role="group" aria-label="قالب اشتراک"></div>
          <div class="imports" id="imports"><span class="lbl">افزودن مستقیم به:</span></div>
        </div>
        <div class="qr-wrap"><button class="qr-box" type="button" id="qrInline" aria-label="بزرگ‌نمایی کد QR"></button><div class="qr-cap">با برنامهٔ خود اسکن کنید</div></div>
      </div>
      <div class="overview-grid">
        <div class="ov-col">
        <div class="card">
          <div class="card-h"><div><h2>پیکربندی فعال</h2><p>خلاصهٔ تنظیماتی که در لینک‌ها اعمال می‌شود</p></div></div>
          <dl class="kv" id="summaryKv"></dl>
        </div>
        <div class="card">
          <div class="card-h"><div><h2>لینک تک‌گره</h2><p>برای افزودن مستقیم یک گره، بدون اشتراک</p></div></div>
          <div class="link-line"><code id="nodeLink">…</code><button class="btn btn-ghost btn-sm" type="button" id="copyNode"><svg><use href="#i-copy"/></svg>کپی</button><button class="btn btn-ghost btn-sm" type="button" id="qrNode" aria-label="کد QR لینک تک‌گره"><svg><use href="#i-qr"/></svg></button></div>
          <p class="hint" style="margin-top:10px">شناسهٔ کاربر (UUID): <span class="mono" id="uuidText">…</span></p>
        </div>
        </div>
        <div class="ov-col">
        <div class="card">
          <div class="card-h"><div><h2>مصرف امروز درخواست‌ها</h2><p>آمار روزانهٔ Workers و Pages در حساب Cloudflare</p></div><span class="pill off" id="usagePill">غیرفعال</span></div>
          <div id="usageBody">
            <div class="big-num" id="usageNum">—</div>
            <div class="meter" aria-hidden="true"><i id="usageBar"></i></div>
            <div class="row" style="justify-content:space-between;font-size:14px;color:var(--muted)"><span id="usageSplit"></span><span id="usagePct"></span></div>
          </div>
          <div class="empty-cta hidden" id="usageEmpty"><svg aria-hidden="true"><use href="#i-chart"/></svg><div><b>آمار مصرف هنوز وصل نشده</b><span>حساب Cloudflare را وصل کنید تا مصرف روزانه این‌جا دیده شود.</span></div><a class="btn btn-ghost btn-sm" href="#integrations">اتصال حساب</a></div>
        </div>
        <div class="card">
          <div class="card-h"><div><h2>اتصال فعلی شما</h2><p>آن‌چه Cloudflare از این نشست می‌بیند</p></div><button class="btn btn-ghost btn-sm" type="button" id="reloadEdge"><svg><use href="#i-refresh"/></svg>به‌روزرسانی</button></div>
          <dl class="kv" id="edgeKv"><dt>وضعیت</dt><dd>در حال دریافت…</dd></dl>
        </div>
        </div>
      </div>
    </section>

    <!-- گره -->
    <section class="view" id="view-node" aria-labelledby="h-node">
      <div class="view-head"><div><h1 id="h-node">گره و پروتکل</h1><p>نوع پروتکل، روش انتقال و جزئیات امنیتی گره‌ها را تعیین کنید. تغییرات پس از ذخیره روی همهٔ لینک‌ها اعمال می‌شود.</p></div></div>
      <div class="card">
        <div class="card-h"><div><h2>پروتکل</h2><p>پروتکلی که برنامه‌ها برای اتصال به کار می‌برند</p></div></div>
        <div class="choice" id="protoChoice" role="group" aria-label="انتخاب پروتکل"></div>
      </div>
      <div class="card">
        <div class="card-h"><div><h2>انتقال</h2><p>روش جابه‌جایی داده میان برنامه و سرور</p></div></div>
        <div class="grid g2">
          <div class="field"><span class="label">روش انتقال</span><div class="seg" id="transportSeg" role="group" aria-label="روش انتقال"><button type="button" data-v="ws">WebSocket</button><button type="button" data-v="grpc">gRPC</button><button type="button" data-v="xhttp">XHTTP</button></div><span class="hint" id="transportHint"></span></div>
          <div class="field"><label for="f-path">مسیر (Path)</label><input class="input ltr" id="f-path" data-bind="PATH" placeholder="/" spellcheck="false"><span class="hint">مسیر درخواست‌ها؛ اگر متغیر محیطی PATH تعریف شده باشد، آن مقدار اولویت دارد.</span></div>
          <div class="field grpc-only"><label for="f-grpcmode">حالت gRPC</label><select class="select" id="f-grpcmode" data-bind="gRPC模式"><option value="gun">Gun (پیش‌فرض)</option><option value="multi">Multi</option></select></div>
          <div class="field grpc-only"><label for="f-grpcua">User-Agent در gRPC</label><input class="input ltr" id="f-grpcua" data-bind="gRPCUserAgent" spellcheck="false"><span class="hint">در خروجی Clash و Sing-box به‌کار می‌رود.</span></div>
        </div>
      </div>
      <div class="card ss-only">
        <div class="card-h"><div><h2 id="ssTitle">تنظیمات رمزنگاری</h2><p>رمزنگاری AEAD برای محتوای انتقالی</p></div></div>
        <div class="grid g2">
          <div class="field"><label for="f-sscipher">روش رمزنگاری</label><select class="select" id="f-sscipher" data-bind="SS.加密方式"><option value="aes-128-gcm">aes-128-gcm</option><option value="aes-256-gcm">aes-256-gcm</option></select></div>
          <label class="switch"><input type="checkbox" data-bind="SS.TLS" data-type="bool"><span class="track"></span><span class="switch-text"><b>استفاده از TLS</b><span>با خاموش‌کردن، درگاه‌ها به‌طور خودکار به درگاه‌های بدون TLS تبدیل می‌شوند.</span></span></label>
        </div>
      </div>
      <div class="card">
        <div class="card-h"><div><h2>TLS و اثر انگشت</h2><p>شبیه‌سازی مرورگر و جزئیات دست‌دهی</p></div></div>
        <div class="grid g3">
          <div class="field"><label for="f-fp">اثر انگشت مرورگر</label><select class="select ltr" id="f-fp" data-bind="Fingerprint"><option value="chrome">chrome</option><option value="firefox">firefox</option><option value="safari">safari</option><option value="ios">ios</option><option value="android">android</option><option value="edge">edge</option><option value="360">360</option><option value="qq">qq</option><option value="random">random</option><option value="randomized">randomized</option></select></div>
          <div class="field"><label for="f-alpn">ALPN</label><input class="input ltr" id="f-alpn" data-bind="ALPN" list="alpnList" placeholder="h2,http/1.1" spellcheck="false"><datalist id="alpnList"><option value="h2,http/1.1"><option value="http/1.1"><option value="h2"><option value="h3"></datalist><span class="hint">خالی بگذارید تا پیش‌فرض برنامه استفاده شود.</span></div>
          <div class="field"><label for="f-frag">قطعه‌بندی TLS</label><select class="select" id="f-frag" data-bind="TLS分片" data-type="nullable"><option value="">خاموش</option><option value="Shadowrocket">سازگار با Shadowrocket</option><option value="Happ">سازگار با Happ</option></select><span class="hint">برای عبور از فیلترینگ مبتنی بر SNI.</span></div>
        </div>
        <div class="grid g2" style="margin-top:16px">
          <label class="switch"><input type="checkbox" data-bind="跳过证书验证" data-type="bool"><span class="track"></span><span class="switch-text"><b>نادیده‌گرفتن اعتبار گواهی</b><span>فقط برای آزمایش؛ در خروجی Base64 اعمال نمی‌شود.</span></span></label>
          <label class="switch"><input type="checkbox" data-bind="启用0RTT" data-type="bool"><span class="track"></span><span class="switch-text"><b>فعال‌سازی 0-RTT</b><span>ارسال دادهٔ اولیه همراه دست‌دهی WebSocket برای اتصال سریع‌تر.</span></span></label>
          <label class="switch"><input type="checkbox" data-bind="随机路径" data-type="bool"><span class="track"></span><span class="switch-text"><b>مسیر تصادفی</b><span>به ابتدای مسیر هر گره یک بخش تصادفی افزوده می‌شود.</span></span></label>
          <label class="switch"><input type="checkbox" data-bind="ECH" data-type="bool" id="f-ech"><span class="track"></span><span class="switch-text"><b>ECH (رمزنگاری کامل ClientHello)</b><span>نام دامنه در دست‌دهی TLS پنهان می‌ماند.</span></span></label>
        </div>
        <div class="grid g2 ech-only" style="margin-top:16px">
          <div class="field"><label for="f-echdns">سرویس DoH برای ECH</label><input class="input ltr" id="f-echdns" data-bind="ECHConfig.DNS" spellcheck="false"></div>
          <div class="field"><label for="f-echsni">SNI برای ECH</label><input class="input ltr" id="f-echsni" data-bind="ECHConfig.SNI" spellcheck="false"></div>
        </div>
      </div>
      <div class="card">
        <div class="card-h"><div><h2>دامنه‌ها</h2><p>دامنه‌هایی که در لینک‌ها به‌صورت چرخشی به کار می‌روند</p></div></div>
        <div class="grid g2">
          <div class="field"><label for="f-hosts">فهرست دامنه‌ها</label><textarea class="textarea ltr" id="f-hosts" data-bind="HOSTS" data-type="list" rows="5" spellcheck="false" placeholder="sub.example.com"></textarea><span class="hint">هر دامنه در یک خط. از <span class="mono">*</span> برای زیردامنهٔ تصادفی استفاده کنید. متغیر محیطی HOST بر این فهرست مقدم است.</span></div>
          <div class="stack">
            <div class="field"><label for="f-host">دامنهٔ فعلی</label><input class="input ltr" id="f-host" readonly></div>
            <div class="field"><label for="f-uuid">UUID</label><div class="input-group"><input class="input ltr" id="f-uuid" readonly><button class="btn btn-ghost" type="button" id="copyUuid" aria-label="کپی UUID"><svg><use href="#i-copy"/></svg></button></div><span class="hint">از رمز مدیر و کلید رمزنگاری ساخته می‌شود؛ برای تغییر، متغیر UUID یا ADMIN را عوض کنید.</span></div>
          </div>
        </div>
      </div>
    </section>

    <!-- آی‌پی‌های بهینه -->
    <section class="view" id="view-preferred" aria-labelledby="h-preferred">
      <div class="view-head"><div><h1 id="h-preferred">آی‌پی‌های بهینه</h1><p>تعیین کنید گره‌های اشتراک با کدام آی‌پی‌ها یا دامنه‌های Cloudflare ساخته شوند.</p></div></div>
      <div class="card">
        <div class="card-h"><div><h2>منبع آی‌پی‌ها</h2></div></div>
        <div class="seg" id="sourceSeg" role="group" aria-label="منبع آی‌پی‌ها"><button type="button" data-v="local">فهرست محلی</button><button type="button" data-v="remote">تولیدکنندهٔ اشتراک بیرونی</button></div>
        <div class="grid g3 local-only" style="margin-top:18px">
          <label class="switch span2"><input type="checkbox" data-bind="优选订阅生成.本地IP库.随机IP" data-type="bool" id="f-random"><span class="track"></span><span class="switch-text"><b>تولید خودکار آی‌پی تصادفی</b><span>از بازه‌های رسمی Cloudflare آی‌پی می‌سازد. با خاموش‌کردن، فهرست سفارشی زیر به کار می‌رود.</span></span></label>
          <div class="field random-only"><label for="f-count">تعداد آی‌پی‌ها</label><input class="input ltr" id="f-count" type="number" min="1" max="512" data-bind="优选订阅生成.本地IP库.随机数量" data-type="num"></div>
          <div class="field random-only"><label for="f-port">درگاه</label><select class="select" id="f-port" data-bind="优选订阅生成.本地IP库.指定端口" data-type="num"><option value="-1">تصادفی از درگاه‌های TLS</option><option value="443">443</option><option value="2053">2053</option><option value="2083">2083</option><option value="2087">2087</option><option value="2096">2096</option><option value="8443">8443</option></select></div>
        </div>
        <div class="field remote-only" style="margin-top:18px"><label for="f-subgen">نشانی تولیدکنندهٔ اشتراک</label><input class="input ltr" id="f-subgen" data-bind="优选订阅生成.SUB" data-type="nullable" placeholder="sub.example.com" spellcheck="false"><span class="hint">دامنهٔ سرویسی که فهرست آی‌پی‌های بهینه را می‌دهد. با پارامتر <span class="mono">sub=</span> در لینک اشتراک هم می‌توانید آن را موقتاً عوض کنید.</span></div>
      </div>
      <div class="card">
        <div class="card-h"><div><h2>مشخصات اشتراک</h2></div></div>
        <div class="grid g2">
          <div class="field"><label for="f-subname">نام اشتراک</label><input class="input" id="f-subname" data-bind="优选订阅生成.SUBNAME" dir="auto"><span class="hint">در برنامه‌ها به‌عنوان نام پروفایل نمایش داده می‌شود.</span></div>
          <div class="field"><label for="f-subtime">بازهٔ به‌روزرسانی خودکار (ساعت)</label><input class="input ltr" id="f-subtime" type="number" min="1" max="168" data-bind="优选订阅生成.SUBUpdateTime" data-type="num"></div>
        </div>
      </div>
      <div class="card" id="addCard">
        <div class="card-h"><div><h2>فهرست سفارشی</h2><p id="addNote">هر خط یک آی‌پی، دامنه، API یا گره کامل</p></div><div class="row"><button class="btn btn-ghost btn-sm" type="button" id="addReload"><svg><use href="#i-refresh"/></svg>بارگذاری دوباره</button><button class="btn btn-dark btn-sm" type="button" id="addSave">ذخیرهٔ فهرست</button></div></div>
        <div class="editor-wrap"><textarea class="textarea ltr" id="addText" spellcheck="false" aria-label="فهرست سفارشی آی‌پی‌ها" placeholder="104.16.1.1:443#Tehran"></textarea></div>
        <div class="editor-meta"><span id="addCount"></span><span id="addState"></span></div>
        <details style="margin-top:14px"><summary style="cursor:pointer;font-weight:600;font-size:14.5px">راهنمای قالب خطوط</summary>
          <div class="help-list" style="margin-top:10px">
            <div><code>104.16.1.1:443#نام دلخواه</code><span>آی‌پی همراه درگاه و برچسب</span></div>
            <div><code>[2606:4700::]:2053#IPv6</code><span>نشانی IPv6 داخل کروشه</span></div>
            <div><code>cdn.example.com:8443</code><span>دامنه به‌جای آی‌پی</span></div>
            <div><code>*.example.com#Wildcard</code><span>زیردامنهٔ تصادفی با ستاره</span></div>
            <div><code>https://api.example.com/ips.txt</code><span>فراخوانی فهرست آی‌پی از یک API</span></div>
            <div><code>sub://sub.example.com</code><span>دریافت از تولیدکنندهٔ اشتراک دیگر</span></div>
            <div><code>1.1.1.1:443#نام $socks5://user:pass@host:1080</code><span>گره با پراکسی زنجیره‌ای</span></div>
          </div>
        </details>
      </div>
      <div class="card">
        <div class="card-h"><div><h2>آزمایش API آی‌پی بهینه</h2><p>پیش از افزودن، خروجی یک API را بررسی کنید</p></div></div>
        <div class="grid g3">
          <div class="field span2"><label for="apiUrl">نشانی API</label><input class="input ltr" id="apiUrl" placeholder="https://example.com/best-ip.txt" spellcheck="false"></div>
          <div class="field"><label for="apiPort">درگاه پیش‌فرض</label><input class="input ltr" id="apiPort" type="number" value="443" min="1" max="65535"></div>
        </div>
        <div class="row" style="margin-top:14px"><button class="btn btn-dark" type="button" id="apiTest">آزمایش</button><button class="btn btn-ghost hidden" type="button" id="apiAppend">افزودن به فهرست سفارشی</button></div>
        <div class="result" id="apiResult" role="status"></div>
      </div>
    </section>

    <!-- تبدیل اشتراک -->
    <section class="view" id="view-convert" aria-labelledby="h-convert">
      <div class="view-head"><div><h1 id="h-convert">تبدیل اشتراک</h1><p>برای قالب‌های Clash، Surge، Quantumult X و Loon، اشتراک از راه این سرویس تبدیل می‌شود.</p></div></div>
      <div class="card">
        <div class="card-h"><div><h2>سرویس تبدیل</h2></div></div>
        <div class="grid">
          <div class="field"><label for="f-subapi">نشانی سرویس تبدیل (Backend)</label><input class="input ltr ph-fa" id="f-subapi" data-bind="订阅转换配置.SUBAPI" spellcheck="false" placeholder="خالی بگذارید تا سرویس پیش‌فرض به کار رود"><span class="hint">نشانی کامل با https:// و بدون / در انتها.</span></div>
          <div class="field"><label for="f-subcfg">فایل قوانین (Config)</label><input class="input ltr ph-fa" id="f-subcfg" data-bind="订阅转换配置.SUBCONFIG" spellcheck="false" placeholder="خالی بگذارید تا قوانین پیش‌فرض به کار رود"><span class="hint">نشانی یک فایل ini سازگار با subconverter.</span></div>
        </div>
      </div>
      <div class="card">
        <div class="card-h"><div><h2>گزینه‌های خروجی</h2></div></div>
        <div class="grid g2">
          <label class="switch"><input type="checkbox" data-bind="订阅转换配置.SUBEMOJI" data-type="bool"><span class="track"></span><span class="switch-text"><b>افزودن پرچم و ایموجی</b><span>نام گره‌ها با پرچم کشور نمایش داده می‌شود.</span></span></label>
          <label class="switch"><input type="checkbox" data-bind="订阅转换配置.SUBLIST" data-type="bool"><span class="track"></span><span class="switch-text"><b>فقط فهرست گره‌ها</b><span>قوانین و گروه‌ها حذف و فقط گره‌ها خروجی داده می‌شوند.</span></span></label>
          <label class="switch"><input type="checkbox" data-bind="订阅转换配置.UDP" data-type="bool"><span class="track"></span><span class="switch-text"><b>فعال‌سازی UDP</b><span>برای تماس صوتی، بازی و DNS.</span></span></label>
          <label class="switch"><input type="checkbox" data-bind="订阅转换配置.XUDP" data-type="bool"><span class="track"></span><span class="switch-text"><b>فعال‌سازی XUDP</b><span>چندگانه‌سازی UDP روی یک اتصال.</span></span></label>
          <label class="switch"><input type="checkbox" data-bind="订阅转换配置.TLS13" data-type="bool"><span class="track"></span><span class="switch-text"><b>اجبار به TLS 1.3</b><span>اتصال فقط با نسخهٔ ۱٫۳ برقرار شود.</span></span></label>
          <label class="switch"><input type="checkbox" data-bind="订阅转换配置.APPEND_TYPE" data-type="bool"><span class="track"></span><span class="switch-text"><b>افزودن نوع گره به نام</b><span>نوع پروتکل در ابتدای نام هر گره درج می‌شود.</span></span></label>
          <label class="switch"><input type="checkbox" data-bind="订阅转换配置.SORT" data-type="bool"><span class="track"></span><span class="switch-text"><b>مرتب‌سازی گره‌ها</b><span>گره‌ها بر پایهٔ نام مرتب می‌شوند.</span></span></label>
          <label class="switch"><input type="checkbox" data-bind="订阅转换配置.EXPAND" data-type="bool"><span class="track"></span><span class="switch-text"><b>درج کامل قوانین</b><span>متن کامل قوانین به‌جای ارجاع به فایل‌های بیرونی.</span></span></label>
        </div>
      </div>
    </section>

    <!-- پراکسی -->
    <section class="view" id="view-proxy" aria-labelledby="h-proxy">
      <div class="view-head"><div><h1 id="h-proxy">پراکسی و مسیریابی</h1><p>مسیر خروج ترافیک به سایت‌هایی که روی Cloudflare میزبانی می‌شوند و پراکسی زنجیره‌ای را تنظیم کنید.</p></div></div>
      <div class="card">
        <div class="card-h"><div><h2 id="pipTitle">آی‌پی پراکسی معکوس</h2><p>برای دسترسی به سایت‌های پشت Cloudflare لازم است</p></div></div>
        <div class="seg" id="pipSeg" role="group" aria-label="حالت آی‌پی پراکسی"><button type="button" data-v="auto">خودکار</button><button type="button" data-v="custom">سفارشی</button></div>
        <p class="hint" id="pipAutoHint" style="margin-top:10px">نزدیک‌ترین آی‌پی بر پایهٔ مرکز دادهٔ Cloudflare انتخاب می‌شود. اگر متغیر محیطی آن تعریف شده باشد، همان به کار می‌رود.</p>
        <div class="field hidden" id="pipCustom" style="margin-top:14px"><label for="f-pip">نشانی</label><input class="input ltr" id="f-pip" placeholder="proxy.example.com:443" spellcheck="false"><span class="hint">دامنه یا آی‌پی به همراه درگاه اختیاری. دامنه‌ها از رکورد TXT، A و AAAA خوانده می‌شوند.</span></div>
      </div>
      <div class="card">
        <div class="card-h"><div><h2>پراکسی زنجیره‌ای</h2><p>ترافیک خروجی از یک پراکسی دیگر عبور کند</p></div></div>
        <div class="grid g2">
          <div class="field"><label for="f-chain">نوع پراکسی</label><select class="select" id="f-chain" data-bind="反代.SOCKS5.启用" data-type="nullable"><option value="">غیرفعال</option><option value="socks5">SOCKS5</option><option value="http">HTTP</option><option value="https">HTTPS</option><option value="turn">TURN</option><option value="sstp">SSTP (SoftEther)</option></select></div>
          <label class="switch chain-only"><input type="checkbox" data-bind="反代.SOCKS5.全局" data-type="bool"><span class="track"></span><span class="switch-text"><b>حالت سراسری</b><span>همهٔ ترافیک از این پراکسی عبور کند، نه فقط فهرست مجاز.</span></span></label>
          <div class="field span2 chain-only"><label for="f-acc">نشانی و حساب</label><div class="input-group"><input class="input ltr" id="f-acc" data-bind="反代.SOCKS5.账号" placeholder="user:pass@host:port" spellcheck="false" autocomplete="off"><button class="btn btn-dark" type="button" id="chainTest">آزمایش اتصال</button></div><span class="hint">قالب: <span class="mono">user:pass@host:port</span> یا فقط <span class="mono">host:port</span>.</span></div>
        </div>
        <div class="result" id="chainResult" role="status"></div>
        <div class="field" style="margin-top:16px"><label for="f-white">فهرست مجاز (همیشه از پراکسی زنجیره‌ای)</label><textarea class="textarea ltr" id="f-white" data-bind="反代.SOCKS5.白名单" data-type="list" rows="5" spellcheck="false"></textarea><span class="hint">هر دامنه در یک خط؛ <span class="mono">*</span> برای هر زیردامنه. متغیر GO2SOCKS5 به این فهرست افزوده می‌شود.</span></div>
      </div>
    </section>

    <!-- اعلان و آمار -->
    <section class="view" id="view-integrations" aria-labelledby="h-integrations">
      <div class="view-head"><div><h1 id="h-integrations">اعلان و آمار</h1><p>اعلان ورود و دریافت اشتراک در تلگرام، و نمایش مصرف روزانهٔ Cloudflare.</p></div></div>
      <div class="card">
        <div class="card-h"><div><h2>اعلان تلگرام</h2><p>هر ورود به پنل یا دریافت اشتراک به ربات شما گزارش می‌شود</p></div><span class="pill off" id="tgPill">تنظیم نشده</span></div>
        <label class="switch"><input type="checkbox" data-bind="TG.启用" data-type="bool"><span class="track"></span><span class="switch-text"><b>ارسال اعلان</b><span>این گزینه با دکمهٔ «ذخیرهٔ تغییرات» پایین صفحه ذخیره می‌شود.</span></span></label>
        <div class="grid g2" style="margin-top:16px">
          <div class="field"><label for="tgToken">توکن ربات (Bot Token)</label><input class="input ltr" id="tgToken" placeholder="123456:ABC-DEF…" spellcheck="false" autocomplete="off"></div>
          <div class="field"><label for="tgChat">شناسهٔ گفت‌وگو (Chat ID)</label><input class="input ltr" id="tgChat" placeholder="123456789" spellcheck="false" autocomplete="off"></div>
        </div>
        <div class="row" style="margin-top:14px"><button class="btn btn-dark" type="button" id="tgSave">ذخیرهٔ ربات</button><button class="btn btn-danger" type="button" id="tgClear">حذف اطلاعات ربات</button></div>
      </div>
      <div class="card">
        <div class="card-h"><div><h2>آمار مصرف Cloudflare</h2><p>نمایش تعداد درخواست‌های امروز در پیشخوان و سربرگ اشتراک</p></div><span class="pill off" id="cfPill">تنظیم نشده</span></div>
        <div class="seg" id="cfSeg" role="group" aria-label="روش احراز هویت"><button type="button" data-v="token">Account ID و API Token</button><button type="button" data-v="global">ایمیل و Global API Key</button><button type="button" data-v="api">نشانی API آمار</button></div>
        <div class="grid g2" style="margin-top:16px">
          <div class="field cf-token"><label for="cfAcc">Account ID</label><input class="input ltr" id="cfAcc" spellcheck="false" autocomplete="off"></div>
          <div class="field cf-token"><label for="cfTok">API Token</label><input class="input ltr" id="cfTok" spellcheck="false" autocomplete="off"><span class="hint">دسترسی لازم: Account Analytics (Read).</span></div>
          <div class="field cf-global"><label for="cfMail">ایمیل حساب</label><input class="input ltr" id="cfMail" type="email" spellcheck="false" autocomplete="off"></div>
          <div class="field cf-global"><label for="cfKey">Global API Key</label><input class="input ltr" id="cfKey" spellcheck="false" autocomplete="off"></div>
          <div class="field span2 cf-api"><label for="cfApi">نشانی API آمار</label><input class="input ltr" id="cfApi" placeholder="https://usage.example.com/api" spellcheck="false"><span class="hint">باید خروجی JSON با فیلدهای success، pages، workers، total و max بدهد.</span></div>
        </div>
        <div class="row" style="margin-top:14px"><button class="btn btn-ghost" type="button" id="cfTest">آزمایش</button><button class="btn btn-dark" type="button" id="cfSave">ذخیره</button><button class="btn btn-danger" type="button" id="cfClear">حذف اطلاعات</button></div>
        <div class="result" id="cfResult" role="status"></div>
      </div>
    </section>

    <!-- گزارش‌ها -->
    <section class="view" id="view-logs" aria-labelledby="h-logs">
      <div class="view-head"><div><h1 id="h-logs">گزارش‌ها</h1><p>ورودها، ذخیره‌سازی‌ها و دریافت‌های اشتراک، از جدیدترین به قدیمی‌ترین.</p></div><div class="row"><button class="btn btn-ghost btn-sm" type="button" id="logExport"><svg><use href="#i-down"/></svg>دریافت فایل</button><button class="btn btn-dark btn-sm" type="button" id="logReload"><svg><use href="#i-refresh"/></svg>به‌روزرسانی</button></div></div>
      <div class="card">
        <div class="toolbar"><input class="input" id="logSearch" type="search" placeholder="جست‌وجو در آی‌پی، کشور، مسیر یا برنامه…" aria-label="جست‌وجو در گزارش‌ها"><select class="select" id="logType" aria-label="فیلتر نوع رویداد"><option value="">همهٔ رویدادها</option></select></div>
        <div id="logBody"></div>
        <div class="pager" id="logPager"></div>
      </div>
    </section>

    <!-- پیشرفته -->
    <section class="view" id="view-advanced" aria-labelledby="h-advanced">
      <div class="view-head"><div><h1 id="h-advanced">پیشرفته</h1><p>ویرایش مستقیم پیکربندی، پشتیبان‌گیری و بازنشانی.</p></div></div>
      <div class="card">
        <div class="card-h"><div><h2>پیکربندی خام (JSON)</h2><p>کلیدها را تغییر ندهید؛ فقط مقدارها را ویرایش کنید</p></div><div class="row"><button class="btn btn-ghost btn-sm" type="button" id="rawFormat">مرتب‌سازی</button><button class="btn btn-dark btn-sm" type="button" id="rawApply">اعمال در فرم‌ها</button></div></div>
        <textarea class="textarea ltr" id="rawJson" rows="18" spellcheck="false" aria-label="پیکربندی خام" style="min-height:380px;font-size:13.5px"></textarea>
        <div class="result" id="rawResult" role="status"></div>
      </div>
      <div class="card">
        <div class="card-h"><div><h2>پشتیبان‌گیری</h2><p>نسخه‌ای از پیکربندی را دریافت یا بازیابی کنید</p></div></div>
        <div class="row"><button class="btn btn-ghost" type="button" id="backupDl"><svg><use href="#i-down"/></svg>دریافت پشتیبان</button><label class="btn btn-ghost" for="backupFile"><svg><use href="#i-up"/></svg>بازیابی از فایل</label><input type="file" id="backupFile" accept="application/json,.json" class="sr-only"></div>
      </div>
      <div class="card danger">
        <div class="card-h"><div><h2>بازنشانی کامل</h2><p>همهٔ تنظیمات به حالت پیش‌فرض برمی‌گردد. فهرست سفارشی، گزارش‌ها و اطلاعات ربات حفظ می‌شوند.</p></div></div>
        <button class="btn btn-danger" type="button" id="resetBtn">بازنشانی به پیش‌فرض</button>
      </div>
    </section>
  </main>
</div>
<footer class="foot"><span>© <span id="year"></span> Avatar</span><span id="footVer"></span></footer>

<div class="savebar" id="savebar" role="region" aria-label="تغییرات ذخیره‌نشده"><i class="dot"></i><span>تغییرات ذخیره‌نشده دارید</span><button class="btn btn-ghost btn-sm" type="button" id="discardBtn">لغو تغییرات</button><button class="btn btn-primary btn-sm" type="button" id="saveBtn">ذخیرهٔ تغییرات</button></div>
<div id="toasts" aria-live="polite"></div>

<dialog id="confirmDlg"><form method="dialog"><div class="dlg-b"><h3 id="cfmTitle"></h3><p id="cfmText"></p></div><div class="dlg-f"><button class="btn btn-ghost" value="cancel">انصراف</button><button class="btn btn-primary" value="ok" id="cfmOk">تأیید</button></div></form></dialog>
<dialog id="qrDialog"><div class="dlg-b"><h3 id="qrTitle">کد QR</h3><p>این کد را با برنامهٔ خود اسکن کنید.</p><div class="qr-big" id="qrBig"></div><code id="qrText"></code></div><div class="dlg-f"><button class="btn btn-ghost" type="button" id="qrDownload"><svg><use href="#i-down"/></svg>دریافت تصویر</button><button class="btn btn-primary" type="button" id="qrClose">بستن</button></div></dialog>

<script>/* Avatar QR: رمزگذار سبک QR (حالت بایت، تصحیح خطای M) */
var AvatarQR=(function(){
  var ECC=[[-1,7,10,15,20,26,18,20,24,30,18,20,24,26,30,22,24,28,30,28,28,28,28,30,30,26,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30],
  [-1,10,16,26,18,24,16,18,22,22,26,30,22,22,24,24,28,28,26,26,26,26,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28],
  [-1,13,22,18,26,18,24,18,22,20,24,28,26,24,20,30,24,28,28,26,30,28,30,30,30,30,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30],
  [-1,17,28,22,16,22,28,26,26,24,28,24,28,22,24,24,30,28,28,26,28,30,24,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30]];
  var BLK=[[-1,1,1,1,1,1,2,2,2,2,4,4,4,4,4,6,6,6,6,7,8,8,9,9,10,12,12,12,13,14,15,16,17,18,19,19,20,21,22,24,25],
  [-1,1,1,1,2,2,4,4,4,5,5,5,8,9,9,10,10,11,13,14,16,17,17,18,20,21,23,25,26,28,29,31,33,35,37,38,40,43,45,47,49],
  [-1,1,1,2,2,4,4,6,6,8,8,8,10,12,16,12,17,16,18,21,20,23,23,25,27,29,34,34,35,38,40,43,45,48,51,53,56,59,62,65,68],
  [-1,1,1,2,4,4,4,5,6,8,8,11,11,16,16,18,16,19,21,25,25,25,34,30,32,35,37,40,42,45,48,51,54,57,60,63,66,70,74,77,81]];
  var FMT=[1,0,3,2];// L M Q H
  function raw(v){var r=(16*v+128)*v+64;if(v>=2){var n=Math.floor(v/7)+2;r-=(25*n-10)*n-55;if(v>=7)r-=36;}return r;}
  function dataCw(v,e){return Math.floor(raw(v)/8)-ECC[e][v]*BLK[e][v];}
  function mul(x,y){var z=0;for(var i=7;i>=0;i--){z=(z<<1)^((z>>>7)*0x11D);z^=((y>>>i)&1)*x;}return z&255;}
  function rsDiv(d){var r=[];for(var i=0;i<d-1;i++)r.push(0);r.push(1);var root=1;for(i=0;i<d;i++){for(var j=0;j<r.length;j++){r[j]=mul(r[j],root);if(j+1<r.length)r[j]^=r[j+1];}root=mul(root,2);}return r;}
  function rsRem(data,div){var r=div.map(function(){return 0;});data.forEach(function(b){var f=b^r.shift();r.push(0);div.forEach(function(c,i){r[i]^=mul(c,f);});});return r;}
  function utf8(s){return Array.from(new TextEncoder().encode(s));}
  function align(v,size){if(v===1)return[];var n=Math.floor(v/7)+2,step=(v===32)?26:Math.ceil((v*4+4)/(n*2-2))*2,res=[6];for(var p=size-7;res.length<n;p-=step)res.splice(1,0,p);return res;}
  function encode(text,eclName){
    var e={L:0,M:1,Q:2,H:3}[eclName||'M'],bytes=utf8(text),ver=0;
    for(var v=1;v<=40;v++){var cc=v<=9?8:16;if(4+cc+bytes.length*8<=dataCw(v,e)*8){ver=v;break;}}
    if(!ver)throw new Error('متن برای کد QR بیش از حد طولانی است');
    var bits=[];function put(val,len){for(var i=len-1;i>=0;i--)bits.push((val>>>i)&1);}
    put(4,4);put(bytes.length,ver<=9?8:16);bytes.forEach(function(b){put(b,8);});
    var cap=dataCw(ver,e)*8;put(0,Math.min(4,cap-bits.length));put(0,(8-bits.length%8)%8);
    for(var pad=0xEC;bits.length<cap;pad^=0xEC^0x11)put(pad,8);
    var data=[];for(var i=0;i<bits.length;i+=8){var b=0;for(var k=0;k<8;k++)b=(b<<1)|bits[i+k];data.push(b);}
    // ECC + درهم‌آمیزی
    var nb=BLK[e][ver],el=ECC[e][ver],rc=Math.floor(raw(ver)/8),ns=nb-rc%nb,sl=Math.floor(rc/nb),blocks=[],div=rsDiv(el),p=0;
    for(i=0;i<nb;i++){var dat=data.slice(p,p+sl-el+(i<ns?0:1));p+=dat.length;var ec=rsRem(dat,div);if(i<ns)dat.push(0);blocks.push(dat.concat(ec));}
    var all=[];for(i=0;i<blocks[0].length;i++)for(var j=0;j<blocks.length;j++)if(i!==sl-el||j>=ns)all.push(blocks[j][i]);
    var size=ver*4+17,m=[],fn=[];for(i=0;i<size;i++){m.push(new Array(size).fill(false));fn.push(new Array(size).fill(false));}
    function set(x,y,d){m[y][x]=d;fn[y][x]=true;}
    for(i=0;i<size;i++){set(6,i,i%2===0);set(i,6,i%2===0);}
    function finder(cx,cy){for(var dy=-4;dy<=4;dy++)for(var dx=-4;dx<=4;dx++){var d=Math.max(Math.abs(dx),Math.abs(dy)),x=cx+dx,y=cy+dy;if(x>=0&&x<size&&y>=0&&y<size)set(x,y,d!==2&&d!==4);}}
    finder(3,3);finder(size-4,3);finder(3,size-4);
    var ap=align(ver,size),na=ap.length;
    for(i=0;i<na;i++)for(j=0;j<na;j++){if((i===0&&j===0)||(i===0&&j===na-1)||(i===na-1&&j===0))continue;for(var dy=-2;dy<=2;dy++)for(var dx=-2;dx<=2;dx++)set(ap[i]+dx,ap[j]+dy,Math.max(Math.abs(dx),Math.abs(dy))!==1);}
    function fmt(mask){var d=FMT[e]<<3|mask,r=d;for(var i=0;i<10;i++)r=(r<<1)^((r>>>9)*0x537);var b=((d<<10)|r)^0x5412;function bt(i){return((b>>>i)&1)!==0;}
      for(i=0;i<=5;i++)set(8,i,bt(i));set(8,7,bt(6));set(8,8,bt(7));set(7,8,bt(8));for(i=9;i<15;i++)set(14-i,8,bt(i));
      for(i=0;i<8;i++)set(size-1-i,8,bt(i));for(i=8;i<15;i++)set(8,size-15+i,bt(i));set(8,size-8,true);}
    fmt(0);
    if(ver>=7){var r=ver;for(i=0;i<12;i++)r=(r<<1)^((r>>>11)*0x1F25);var vb=ver<<12|r;for(i=0;i<18;i++){var bt=((vb>>>i)&1)!==0,a=size-11+i%3,c=Math.floor(i/3);set(a,c,bt);set(c,a,bt);}}
    var bi=0;
    for(var right=size-1;right>=1;right-=2){if(right===6)right=5;for(var vert=0;vert<size;vert++)for(j=0;j<2;j++){var x=right-j,up=((right+1)&2)===0,y=up?size-1-vert:vert;if(!fn[y][x]&&bi<all.length*8){m[y][x]=((all[bi>>>3]>>>(7-(bi&7)))&1)!==0;bi++;}}}
    function maskF(k,x,y){switch(k){case 0:return(x+y)%2===0;case 1:return y%2===0;case 2:return x%3===0;case 3:return(x+y)%3===0;case 4:return(Math.floor(x/3)+Math.floor(y/2))%2===0;case 5:return x*y%2+x*y%3===0;case 6:return(x*y%2+x*y%3)%2===0;default:return((x+y)%2+x*y%3)%2===0;}}
    function apply(k){for(var y=0;y<size;y++)for(var x=0;x<size;x++)if(!fn[y][x]&&maskF(k,x,y))m[y][x]=!m[y][x];}
    function penalty(){var s=0,dark=0,x,y,run,c;
      for(y=0;y<size;y++){run=1;for(x=1;x<size;x++){if(m[y][x]===m[y][x-1]){run++;if(run===5)s+=3;else if(run>5)s++;}else run=1;}}
      for(x=0;x<size;x++){run=1;for(y=1;y<size;y++){if(m[y][x]===m[y-1][x]){run++;if(run===5)s+=3;else if(run>5)s++;}else run=1;}}
      for(y=0;y<size-1;y++)for(x=0;x<size-1;x++){c=m[y][x];if(c===m[y][x+1]&&c===m[y+1][x]&&c===m[y+1][x+1])s+=3;}
      for(y=0;y<size;y++)for(x=0;x<size;x++)if(m[y][x])dark++;
      s+=Math.floor(Math.abs(dark*20-size*size*10)/(size*size))*10;return s;}
    var best=0,bestS=Infinity;
    for(var k=0;k<8;k++){apply(k);fmt(k);var ps=penalty();if(ps<bestS){bestS=ps;best=k;}apply(k);}
    apply(best);fmt(best);
    return {size:size,modules:m};
  }
  function svg(text,opt){opt=opt||{};var q=encode(text,opt.ecl),b=opt.border==null?2:opt.border,n=q.size+b*2,d='';
    for(var y=0;y<q.size;y++)for(var x=0;x<q.size;x++)if(q.modules[y][x])d+='M'+(x+b)+','+(y+b)+'h1v1h-1z';
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 '+n+' '+n+'" shape-rendering="crispEdges" role="img" aria-label="کد QR"><rect width="100%" height="100%" fill="#fff"/><path d="'+d+'" fill="'+(opt.color||'#160f33')+'"/></svg>';}
  return {encode:encode,svg:svg};
})();
</script>
<script>/* Avatar · منطق پنل مدیریت */
(function(){
'use strict';
var P='PROXY'+'IP';
var PROTO=[{v:'vl'+'ess',name:'VL'+'ESS',d:'سبک و سریع؛ پیشنهاد برای بیشتر برنامه‌ها'},{v:'tro'+'jan',name:'Tro'+'jan',d:'سازگاری گسترده، مناسب Surge'},{v:'ss',name:'Shadow'+'socks',d:'رمزنگاری AEAD روی WebSocket'}];
var FORMATS=[{k:'',t:'خودکار'},{k:'b64',t:'Base64'},{k:'clash',t:'Clash / Mihomo'},{k:'sb',t:'Sing-box'},{k:'surge',t:'Surge'},{k:'quanx',t:'Quantumult X'},{k:'loon',t:'Loon'}];
var LOG_TYPES={Get_SUB:['دریافت اشتراک','t-sub'],Get_Best_SUB:['دریافت فهرست بهینه','t-sub'],Admin_Login:['ورود به پنل','t-login'],Save_Config:['ذخیرهٔ تنظیمات','t-save'],Save_Custom_IPs:['ذخیرهٔ فهرست سفارشی','t-save'],Init_Config:['بازنشانی تنظیمات','t-init']};
var cfg=null,snap='',edgeLoaded=false,addLoaded=false,logs=[],logPage=1,LOG_PER=40,apiLast=null,subFmt='';
var $=function(id){return document.getElementById(id);};
var nf=new Intl.NumberFormat('fa-IR');
function fa(n){return nf.format(n);}
function faDigits(s){return String(s).replace(/\\./g,'٫').replace(/[0-9]/g,function(d){return '۰۱۲۳۴۵۶۷۸۹'[d];});}
var dtf;try{dtf=new Intl.DateTimeFormat('fa-IR-u-ca-persian',{timeZone:'Asia/Tehran',year:'numeric',month:'long',day:'numeric',hour:'2-digit',minute:'2-digit'});}catch(e){dtf=new Intl.DateTimeFormat('fa-IR',{dateStyle:'medium',timeStyle:'short'});}
var region;try{region=new Intl.DisplayNames(['fa'],{type:'region'});}catch(e){region=null;}
function country(cc){if(!cc||cc==='N/A')return 'نامشخص';try{return region?region.of(cc.toUpperCase()):cc;}catch(e){return cc;}}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function clone(o){return JSON.parse(JSON.stringify(o));}
function getPath(o,p){return p.split('.').reduce(function(a,k){return a==null?undefined:a[k];},o);}
function setPath(o,p,v){var ks=p.split('.'),last=ks.pop(),t=ks.reduce(function(a,k){if(a[k]==null||typeof a[k]!=='object')a[k]={};return a[k];},o);t[last]=v;}

/* اعلان */
function toast(msg,type){var el=document.createElement('div');el.className='toast '+(type||'info');el.setAttribute('role',type==='err'?'alert':'status');el.textContent=msg;$('toasts').appendChild(el);setTimeout(function(){el.classList.add('out');setTimeout(function(){el.remove();},220);},type==='err'?5200:3200);}
function busy(btn,on){if(!btn)return;btn.classList.toggle('is-busy',!!on);btn.disabled=!!on;}
function confirmBox(title,text,okText,danger){return new Promise(function(res){var d=$('confirmDlg');$('cfmTitle').textContent=title;$('cfmText').textContent=text;var ok=$('cfmOk');ok.textContent=okText||'تأیید';ok.className='btn '+(danger?'btn-danger':'btn-primary');d.returnValue='';d.showModal();d.addEventListener('close',function h(){d.removeEventListener('close',h);res(d.returnValue==='ok');});});}
function copy(text,label){var done=function(){toast((label||'متن')+' کپی شد','ok');};var fail=function(){toast('کپی خودکار ممکن نشد؛ متن را دستی انتخاب کنید.','err');};
  if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(text).then(done,function(){legacy()?done():fail();});}else{legacy()?done():fail();}
  function legacy(){try{var t=document.createElement('textarea');t.value=text;t.setAttribute('readonly','');t.style.position='fixed';t.style.opacity='0';document.body.appendChild(t);t.select();var ok=document.execCommand('copy');t.remove();return ok;}catch(e){return false;}}}

/* درخواست به سرور */
function api(path,opt){opt=opt||{};opt.credentials='same-origin';opt.cache='no-store';
  return fetch(path,opt).then(function(r){
    if(r.redirected&&/\\/login$/.test(new URL(r.url).pathname)){toast('نشست شما به پایان رسیده است؛ دوباره وارد شوید.','err');setTimeout(function(){location.href='/login';},900);throw new Error('session');}
    return r;});}
function apiJSON(path,opt){return api(path,opt).then(function(r){var ct=r.headers.get('content-type')||'';if(ct.indexOf('json')===-1){if(ct.indexOf('html')>-1){location.href='/login';throw new Error('session');}throw new Error('پاسخ نامعتبر از سرور ('+fa(r.status)+')');}
  return r.json().then(function(d){if(!r.ok){var m=(d&&(d.error||d.msg))||('خطای سرور ('+fa(r.status)+')');var err=new Error(m);err.data=d;throw err;}return d;});});}

/* بارگذاری پیکربندی */
function loadConfig(){return apiJSON('/admin/config.json').then(function(d){cfg=d;normalize();fillAll();snap=JSON.stringify(cfg);updateDirty();return d;});}
function normalize(){cfg.反代=cfg.反代||{};cfg.反代.SOCKS5=cfg.反代.SOCKS5||{启用:null,全局:false,账号:'',白名单:[]};cfg.优选订阅生成=cfg.优选订阅生成||{};cfg.优选订阅生成.本地IP库=cfg.优选订阅生成.本地IP库||{随机IP:true,随机数量:16,指定端口:-1};cfg.订阅转换配置=cfg.订阅转换配置||{};cfg.ECHConfig=cfg.ECHConfig||{DNS:'',SNI:''};cfg.SS=cfg.SS||{加密方式:'aes-128-gcm',TLS:true};cfg.TG=cfg.TG||{};cfg.CF=cfg.CF||{Usage:{success:false}};}

function fillAll(){
  document.querySelectorAll('[data-bind]').forEach(function(el){var v=getPath(cfg,el.dataset.bind),t=el.dataset.type;
    if(t==='bool')el.checked=!!v;else if(t==='list')el.value=Array.isArray(v)?v.join('\\n'):(v||'');else if(t==='nullable')el.value=v==null?'':String(v);else el.value=v==null?'':String(v);
    if(el.tagName==='SELECT'&&el.selectedIndex===-1&&v!=null&&v!==''){var o=document.createElement('option');o.value=String(v);o.textContent=String(v);el.appendChild(o);el.value=String(v);}});
  setSeg('transportSeg',cfg.传输协议||'ws');
  setSeg('sourceSeg',cfg.优选订阅生成.local===false?'remote':'local');
  var pip=cfg.反代[P];setSeg('pipSeg',(!pip||pip==='auto')?'auto':'custom');$('f-pip').value=(!pip||pip==='auto')?'':pip;
  renderProto();
  $('f-host').value=cfg.HOST||'';$('f-uuid').value=cfg.UUID||'';$('uuidText').textContent=cfg.UUID||'';
  $('hostText').textContent=cfg.HOST||location.host;
  $('tgChat').value=cfg.TG.ChatID||'';$('tgToken').value='';$('tgToken').placeholder=cfg.TG.BotToken||'123456:ABC-DEF…';
  $('cfMail').value=cfg.CF.Email||'';$('cfKey').placeholder=cfg.CF.GlobalAPIKey||'';$('cfAcc').placeholder=cfg.CF.AccountID||'';$('cfTok').placeholder=cfg.CF.APIToken||'';
  if(cfg.CF.Email)setSeg('cfSeg','global');else if(cfg.CF.AccountID)setSeg('cfSeg','token');else if(!document.querySelector('#cfSeg [aria-pressed=true]'))setSeg('cfSeg','token');
  setPill('tgPill',cfg.TG.BotToken&&cfg.TG.ChatID?(cfg.TG.启用?['فعال','ok']:['ذخیره‌شده، خاموش','warn']):['تنظیم نشده','off']);
  setPill('cfPill',cfg.CF.Usage&&cfg.CF.Usage.success?['متصل','ok']:(cfg.CF.Email||cfg.CF.AccountID)?['خطا در دریافت','warn']:['تنظیم نشده','off']);
  if($('view-advanced').classList.contains('active'))$('rawJson').value=JSON.stringify(cfg,null,2);
  visibility();renderOverview();
}
function setPill(id,a){var el=$(id);el.textContent=a[0];el.className='pill '+a[1];}
function setSeg(id,v){document.querySelectorAll('#'+id+' button').forEach(function(b){b.setAttribute('aria-pressed',String(b.dataset.v===v));});}
function segVal(id){var b=document.querySelector('#'+id+' button[aria-pressed=true]');return b?b.dataset.v:null;}
function renderProto(){var box=$('protoChoice');box.innerHTML='';PROTO.forEach(function(p){var b=document.createElement('button');b.type='button';b.setAttribute('aria-pressed',String(cfg.协议类型===p.v));b.innerHTML='<b>'+esc(p.name)+'</b><span>'+esc(p.d)+'</span>';b.addEventListener('click',function(){cfg.协议类型=p.v;renderProto();visibility();changed();});box.appendChild(b);});$('ssTitle').textContent='تنظیمات '+PROTO[2].name;}
function visibility(){
  var tr=cfg.传输协议||'ws',isSS=cfg.协议类型==='ss';
  toggleAll('.grpc-only',tr==='grpc'&&!isSS);
  toggleAll('.ss-only',isSS);
  toggleAll('.ech-only',!!cfg.ECH);
  var local=cfg.优选订阅生成.local!==false,rnd=!!cfg.优选订阅生成.本地IP库.随机IP;
  toggleAll('.local-only',local);toggleAll('.remote-only',!local);toggleAll('.random-only',local&&rnd);
  toggleAll('.chain-only',!!cfg.反代.SOCKS5.启用);
  var mode=segVal('cfSeg')||'token';toggleAll('.cf-token',mode==='token');toggleAll('.cf-global',mode==='global');toggleAll('.cf-api',mode==='api');$('cfTest').classList.toggle('hidden',mode==='api');
  $('pipCustom').classList.toggle('hidden',segVal('pipSeg')!=='custom');$('pipAutoHint').classList.toggle('hidden',segVal('pipSeg')==='custom');
  var hint={ws:'سازگارترین گزینه؛ با همهٔ برنامه‌ها کار می‌کند.',grpc:'پایدار روی شبکه‌های پرنوسان؛ برنامه باید از gRPC پشتیبانی کند.',xhttp:'جدیدترین روش؛ به هستهٔ به‌روز نیاز دارد.'}[tr]||'';
  if(isSS)hint='در این پروتکل فقط WebSocket به کار می‌رود.';
  $('transportHint').textContent=hint;
  document.querySelectorAll('#transportSeg button').forEach(function(b){b.disabled=isSS&&b.dataset.v!=='ws';});
  var usingAdd=local&&!rnd;$('addNote').textContent=usingAdd?'این فهرست هم‌اکنون برای ساخت گره‌ها به کار می‌رود.':'برای استفاده از این فهرست، «تولید خودکار آی‌پی تصادفی» را خاموش کنید.';
}
function toggleAll(sel,show){document.querySelectorAll(sel).forEach(function(el){el.classList.toggle('hidden',!show);});}

/* تغییرات */
function changed(){updateDirty();if(document.querySelector('#view-overview.active'))renderOverview();}
function updateDirty(){var d=cfg&&JSON.stringify(cfg)!==snap;$('savebar').classList.toggle('show',!!d);return d;}
document.addEventListener('input',onField);document.addEventListener('change',onField);
function onField(e){var el=e.target;if(!el.dataset||!el.dataset.bind||!cfg)return;var t=el.dataset.type,v;
  if(t==='bool')v=el.checked;else if(t==='num'){v=el.value===''?0:Number(el.value);if(!isFinite(v))return;}else if(t==='list')v=el.value.split('\\n').map(function(s){return s.trim();}).filter(Boolean);else if(t==='nullable')v=el.value.trim()===''?null:el.value.trim();else v=el.value;
  setPath(cfg,el.dataset.bind,v);visibility();changed();}
function bindSeg(id,fn){$(id).addEventListener('click',function(e){var b=e.target.closest('button');if(!b||b.disabled)return;setSeg(id,b.dataset.v);fn(b.dataset.v);visibility();});}
bindSeg('transportSeg',function(v){cfg.传输协议=v;changed();});
bindSeg('sourceSeg',function(v){cfg.优选订阅生成.local=v==='local';changed();});
bindSeg('pipSeg',function(v){if(v==='auto'){cfg.反代[P]='auto';}else{var x=$('f-pip').value.trim();cfg.反代[P]=x||'auto';setTimeout(function(){$('f-pip').focus();},30);}changed();});
bindSeg('cfSeg',function(){$('cfResult').className='result';});
$('f-pip').addEventListener('input',function(){var x=this.value.trim();cfg.反代[P]=x||'auto';changed();});

$('saveBtn').addEventListener('click',save);
$('discardBtn').addEventListener('click',function(){cfg=JSON.parse(snap);fillAll();updateDirty();toast('تغییرات لغو شد','info');});
function save(){var b=$('saveBtn');
  if(!cfg.HOSTS||!cfg.HOSTS.length){toast('فهرست دامنه‌ها نمی‌تواند خالی باشد.','err');location.hash='#node';return;}
  var n=Number(getPath(cfg,'优选订阅生成.本地IP库.随机数量'));if(!(n>=1)){toast('تعداد آی‌پی‌ها باید دست‌کم ۱ باشد.','err');location.hash='#preferred';return;}
  var h=Number(getPath(cfg,'优选订阅生成.SUBUpdateTime'));if(!(h>=1)){toast('بازهٔ به‌روزرسانی باید دست‌کم ۱ ساعت باشد.','err');location.hash='#preferred';return;}
  busy(b,true);
  apiJSON('/admin/config.json',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)})
   .then(function(d){toast(d.message||'تنظیمات ذخیره شد','ok');return loadConfig();})
   .catch(function(e){if(e.message!=='session')toast('ذخیره ناموفق بود: '+e.message,'err');})
   .finally(function(){busy(b,false);});}
window.addEventListener('beforeunload',function(e){if(updateDirty()){e.preventDefault();e.returnValue='';}});
document.addEventListener('keydown',function(e){if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='s'){e.preventDefault();if(updateDirty())save();}});

/* پیشخوان */
function subBase(){return location.origin+'/sub?token='+encodeURIComponent(cfg.优选订阅生成.TOKEN||'');}
function subUrl(k){return subBase()+(k?'&'+k:'');}
function renderOverview(){if(!cfg)return;
  var name=cfg.优选订阅生成.SUBNAME||'Avatar';$('subName').textContent=name;
  var u=subUrl(subFmt);$('subUrl').textContent=u;$('subUrl').title=u;
  var f=$('formats');if(!f.childElementCount){FORMATS.forEach(function(x){var b=document.createElement('button');b.type='button';b.textContent=x.t;b.dataset.k=x.k;b.addEventListener('click',function(){subFmt=x.k;renderOverview();});f.appendChild(b);});}
  f.querySelectorAll('button').forEach(function(b){b.setAttribute('aria-pressed',String(b.dataset.k===subFmt));});
  var im=$('imports');im.querySelectorAll('a').forEach(function(a){a.remove();});
  var base=subBase(),en=encodeURIComponent,b64=btoa(unescape(en(base)));
  [['Hiddify','hiddify://import/'+base+'#'+en(name)],['Clash','clash://install-config?url='+en(base+'&clash')+'&name='+en(name)],['Sing-box','sing-box://import-remote-profile?url='+en(base+'&sb')+'#'+en(name)],['Shadowrocket','shadowrocket://add/sub://'+b64+'?remark='+en(name)]].forEach(function(x){var a=document.createElement('a');a.className='btn btn-sm btn-top';a.href=x[1];a.textContent=x[0];a.setAttribute('rel','noopener');im.appendChild(a);});
  try{$('qrInline').innerHTML=AvatarQR.svg(u,{border:1});}catch(e){$('qrInline').textContent='';}
  $('nodeLink').textContent=cfg.LINK||'';$('nodeLink').title=cfg.LINK||'';
  // مصرف
  var us=cfg.CF.Usage||{};if(us.success){var tot=Number(us.total)||0,max=Number(us.max)||100000,pct=Math.min(100,tot/max*100);
    $('usageBody').classList.remove('hidden');$('usageEmpty').classList.add('hidden');
    $('usageNum').innerHTML=esc(fa(tot))+' <small>از '+esc(fa(max))+' درخواست</small>';
    $('usageBar').style.width=pct.toFixed(1)+'%';$('usagePct').textContent=faDigits(pct.toFixed(1))+'٪';
    $('usageSplit').textContent='Workers: '+fa(Number(us.workers)||0)+' · Pages: '+fa(Number(us.pages)||0);
    setPill('usagePill',pct>=90?['نزدیک به سقف','warn']:['فعال','ok']);}
  else{$('usageBody').classList.add('hidden');$('usageEmpty').classList.remove('hidden');setPill('usagePill',['غیرفعال','off']);}
  // خلاصه
  var pr=PROTO.filter(function(p){return p.v===cfg.协议类型;})[0],tr={ws:'WebSocket',grpc:'gRPC',xhttp:'XHTTP'}[cfg.传输协议]||'WebSocket';
  var chain=cfg.反代.SOCKS5.启用?String(cfg.反代.SOCKS5.启用).toUpperCase()+(cfg.反代.SOCKS5.全局?' (سراسری)':''):'خاموش';
  var local=cfg.优选订阅生成.local!==false,src=local?(cfg.优选订阅生成.本地IP库.随机IP?'تصادفی، '+fa(cfg.优选订阅生成.本地IP库.随机数量||0)+' آی‌پی':'فهرست سفارشی'):'تولیدکنندهٔ بیرونی';
  var pip=cfg.反代[P];
  var rows=[['پروتکل',pr?pr.name:cfg.协议类型,1],['انتقال',cfg.协议类型==='ss'?'WebSocket':tr,1],['دامنه‌ها',fa((cfg.HOSTS||[]).length)+' دامنه'],['منبع آی‌پی',src],['آی‌پی پراکسی',(!pip||pip==='auto')?'خودکار':pip,(!pip||pip==='auto')?0:1],['پراکسی زنجیره‌ای',chain],['ECH',cfg.ECH?'روشن':'خاموش'],['زمان آماده‌سازی',cfg.加载时间?faDigits(String(cfg.加载时间).replace('ms',''))+' میلی‌ثانیه':'—']];
  $('summaryKv').innerHTML=rows.map(function(r){return '<dt>'+esc(r[0])+'</dt><dd'+(r[2]?' class="ltr" style="text-align:left"':'')+' title="'+esc(r[1])+'">'+esc(r[1])+'</dd>';}).join('');
}
function loadEdge(){var kv=$('edgeKv');kv.innerHTML='<dt>وضعیت</dt><dd>در حال دریافت…</dd>';
  apiJSON('/admin/cf.json').then(function(c){edgeLoaded=true;
    var rows=[['مرکز داده',c.colo?c.colo+(c.city?' · '+c.city:''):'—',1],['کشور',country(c.country)],['شبکه',(c.asn?'AS'+c.asn+' ':'')+(c.asOrganization||''),1],['پروتکل',[c.httpProtocol,c.tlsVersion].filter(Boolean).join(' · ')||'—',1],['تأخیر TCP',c.clientTcpRtt!=null?fa(c.clientTcpRtt)+' میلی‌ثانیه':'—']];
    kv.innerHTML=rows.map(function(r){return '<dt>'+esc(r[0])+'</dt><dd'+(r[2]?' class="ltr" style="text-align:left"':'')+' title="'+esc(r[1])+'">'+esc(r[1])+'</dd>';}).join('');})
  .catch(function(e){if(e.message!=='session')kv.innerHTML='<dt>وضعیت</dt><dd>دریافت اطلاعات ممکن نشد</dd>';});}
$('reloadEdge').addEventListener('click',loadEdge);
$('copySub').addEventListener('click',function(){copy(subUrl(subFmt),'لینک اشتراک');});
$('copyNode').addEventListener('click',function(){copy(cfg.LINK||'','لینک گره');});
$('copyUuid').addEventListener('click',function(){copy(cfg.UUID||'','UUID');});
$('uuidText').addEventListener('click',function(){copy(cfg.UUID||'','UUID');});
function openQR(title,text){$('qrTitle').textContent=title;$('qrText').textContent=text;try{$('qrBig').innerHTML=AvatarQR.svg(text,{border:2});}catch(e){$('qrBig').textContent=e.message;}$('qrDialog').showModal();}
$('qrSubBtn').addEventListener('click',function(){openQR('کد QR اشتراک',subUrl(subFmt));});
$('qrInline').addEventListener('click',function(){openQR('کد QR اشتراک',subUrl(subFmt));});
$('qrNode').addEventListener('click',function(){openQR('کد QR لینک تک‌گره',cfg.LINK||'');});
$('qrClose').addEventListener('click',function(){$('qrDialog').close();});
$('qrDialog').addEventListener('click',function(e){if(e.target===this)this.close();});
$('qrDownload').addEventListener('click',function(){var svg=$('qrBig').querySelector('svg');if(!svg)return;var img=new Image(),s=new XMLSerializer().serializeToString(svg);img.onload=function(){var c=document.createElement('canvas');c.width=c.height=720;var x=c.getContext('2d');x.drawImage(img,0,0,720,720);c.toBlob(function(b){dl(b,'avatar-qr.png');});};img.src='data:image/svg+xml;charset=utf-8,'+encodeURIComponent(s);});
function dl(blob,name){var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;document.body.appendChild(a);a.click();setTimeout(function(){URL.revokeObjectURL(a.href);a.remove();},500);}

/* فهرست سفارشی */
function countLines(){var n=$('addText').value.split('\\n').filter(function(s){return s.trim();}).length;$('addCount').textContent=fa(n)+' خط';}
function loadAdd(){var b=$('addReload');busy(b,true);$('addState').textContent='در حال بارگذاری…';
  api('/admin/ADD.txt').then(function(r){if(!r.ok)throw new Error('خطای سرور ('+fa(r.status)+')');return r.text();}).then(function(t){addLoaded=true;$('addText').value=t;countLines();$('addState').textContent='همگام با سرور';})
  .catch(function(e){if(e.message!=='session'){$('addState').textContent='بارگذاری ناموفق بود';toast('دریافت فهرست ناموفق بود: '+e.message,'err');}}).finally(function(){busy(b,false);});}
$('addReload').addEventListener('click',function(){if($('addState').dataset.dirty==='1'){confirmBox('بارگذاری دوباره؟','تغییرات ذخیره‌نشدهٔ این فهرست از بین می‌رود.','بارگذاری دوباره').then(function(ok){if(ok){$('addState').dataset.dirty='';loadAdd();}});}else loadAdd();});
$('addText').addEventListener('input',function(){countLines();$('addState').textContent='ذخیره نشده';$('addState').dataset.dirty='1';});
$('addSave').addEventListener('click',function(){var b=this;busy(b,true);
  apiJSON('/admin/ADD.txt',{method:'POST',headers:{'Content-Type':'text/plain;charset=utf-8'},body:$('addText').value})
  .then(function(d){toast(d.message||'فهرست ذخیره شد','ok');$('addState').textContent='همگام با سرور';$('addState').dataset.dirty='';})
  .catch(function(e){if(e.message!=='session')toast('ذخیرهٔ فهرست ناموفق بود: '+e.message,'err');}).finally(function(){busy(b,false);});});
$('apiTest').addEventListener('click',function(){var u=$('apiUrl').value.trim(),port=$('apiPort').value||'443',box=$('apiResult');
  try{new URL(u);}catch(e){box.className='result show err';box.textContent='نشانی واردشده معتبر نیست؛ با https:// شروع کنید.';return;}
  var b=this;busy(b,true);box.className='result show info';box.textContent='در حال دریافت…';$('apiAppend').classList.add('hidden');
  apiJSON('/admin/getADDAPI?url='+encodeURIComponent(u)+'&port='+encodeURIComponent(port)).then(function(d){var list=d.data||[];apiLast=u;
    if(!list.length){box.className='result show err';box.textContent='این API هیچ آی‌پی معتبری برنگرداند.';return;}
    box.className='result show ok';box.innerHTML='<b>'+esc(fa(list.length))+' مورد دریافت شد.</b><pre>'+esc(list.slice(0,200).join('\\n'))+(list.length>200?'\\n…':'')+'</pre>';$('apiAppend').classList.remove('hidden');})
  .catch(function(e){if(e.message!=='session'){box.className='result show err';box.textContent='دریافت ناموفق بود: '+e.message;}}).finally(function(){busy(b,false);});});
$('apiAppend').addEventListener('click',function(){if(!apiLast)return;var t=$('addText'),v=t.value.replace(/\\s+$/,'');t.value=(v?v+'\\n':'')+apiLast;t.dispatchEvent(new Event('input'));toast('نشانی API به فهرست افزوده شد؛ فراموش نکنید ذخیره کنید.','info');});

/* پراکسی زنجیره‌ای */
$('chainTest').addEventListener('click',function(){var type=cfg.反代.SOCKS5.启用,acc=$('f-acc').value.trim(),box=$('chainResult');
  if(!type){box.className='result show err';box.textContent='ابتدا نوع پراکسی را انتخاب کنید.';return;}
  if(!acc){box.className='result show err';box.textContent='نشانی پراکسی را وارد کنید.';return;}
  var b=this;busy(b,true);box.className='result show info';box.textContent='در حال آزمایش اتصال…';
  apiJSON('/admin/check?'+encodeURIComponent(type)+'='+encodeURIComponent(acc)).then(function(d){
    if(d.success){box.className='result show ok';box.innerHTML='<b>اتصال برقرار شد.</b> آی‌پی خروجی: <span class="mono">'+esc(d.ip)+'</span> · '+esc(country(d.loc))+' · زمان پاسخ: '+esc(fa(d.responseTime||0))+' میلی‌ثانیه';}
    else{box.className='result show err';box.innerHTML='<b>اتصال برقرار نشد.</b> '+esc(d.error||'')+' <span class="hint">('+esc(fa(d.responseTime||0))+' میلی‌ثانیه)</span>';}})
  .catch(function(e){if(e.message!=='session'){box.className='result show err';box.textContent='آزمایش ناموفق بود: '+e.message;}}).finally(function(){busy(b,false);});});

/* تلگرام */
$('tgSave').addEventListener('click',function(){var t=$('tgToken').value.trim(),c=$('tgChat').value.trim();
  if(!t||!c){toast('توکن ربات و شناسهٔ گفت‌وگو هر دو لازم‌اند.','err');return;}
  if(!/^\\d+:[\\w-]{20,}$/.test(t)){toast('قالب توکن ربات درست به نظر نمی‌رسد.','err');return;}
  var b=this;busy(b,true);apiJSON('/admin/tg.json',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({BotToken:t,ChatID:c})})
  .then(function(d){toast(d.message||'ربات ذخیره شد','ok');return reloadKeepDraft();}).catch(function(e){if(e.message!=='session')toast('ذخیره ناموفق بود: '+e.message,'err');}).finally(function(){busy(b,false);});});
$('tgClear').addEventListener('click',function(){var b=this;confirmBox('حذف اطلاعات ربات؟','توکن و شناسهٔ گفت‌وگو پاک می‌شوند و اعلانی ارسال نخواهد شد.','حذف',true).then(function(ok){if(!ok)return;busy(b,true);
  apiJSON('/admin/tg.json',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({init:true})}).then(function(){toast('اطلاعات ربات حذف شد','ok');return reloadKeepDraft();}).catch(function(e){if(e.message!=='session')toast('حذف ناموفق بود: '+e.message,'err');}).finally(function(){busy(b,false);});});});
/* Cloudflare */
function cfBody(){var m=segVal('cfSeg');if(m==='global')return {Email:$('cfMail').value.trim(),GlobalAPIKey:$('cfKey').value.trim()};if(m==='api')return {UsageAPI:$('cfApi').value.trim()};return {AccountID:$('cfAcc').value.trim(),APIToken:$('cfTok').value.trim()};}
function cfValid(b){var ks=Object.keys(b);for(var i=0;i<ks.length;i++)if(!b[ks[i]])return false;if(b.UsageAPI){try{new URL(b.UsageAPI);}catch(e){return false;}}return true;}
$('cfTest').addEventListener('click',function(){var body=cfBody(),box=$('cfResult');if(!cfValid(body)){box.className='result show err';box.textContent='همهٔ فیلدهای این روش را کامل کنید.';return;}
  var b=this;busy(b,true);box.className='result show info';box.textContent='در حال بررسی…';
  apiJSON('/admin/getCloudflareUsage?'+new URLSearchParams(body).toString()).then(function(d){if(d.success){box.className='result show ok';box.innerHTML='<b>اتصال موفق بود.</b> درخواست‌های امروز: '+esc(fa(d.total))+' از '+esc(fa(d.max))+' (Workers: '+esc(fa(d.workers))+' · Pages: '+esc(fa(d.pages))+')';}else{box.className='result show err';box.textContent='آمار دریافت نشد. اطلاعات ورود یا سطح دسترسی توکن را بررسی کنید.';}})
  .catch(function(e){if(e.message!=='session'){box.className='result show err';box.textContent='بررسی ناموفق بود: '+e.message;}}).finally(function(){busy(b,false);});});
$('cfSave').addEventListener('click',function(){var body=cfBody();if(!cfValid(body)){toast('همهٔ فیلدهای این روش را کامل کنید.','err');return;}
  var b=this;busy(b,true);apiJSON('/admin/cf.json',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(d){toast(d.message||'ذخیره شد','ok');['cfKey','cfTok','cfApi'].forEach(function(i){$(i).value='';});return reloadKeepDraft();})
  .catch(function(e){if(e.message!=='session')toast('ذخیره ناموفق بود: '+e.message,'err');}).finally(function(){busy(b,false);});});
$('cfClear').addEventListener('click',function(){var b=this;confirmBox('حذف اطلاعات Cloudflare؟','نمایش آمار مصرف متوقف می‌شود.','حذف',true).then(function(ok){if(!ok)return;busy(b,true);
  apiJSON('/admin/cf.json',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({init:true})}).then(function(){toast('اطلاعات Cloudflare حذف شد','ok');['cfMail','cfKey','cfAcc','cfTok','cfApi'].forEach(function(i){$(i).value='';});return reloadKeepDraft();}).catch(function(e){if(e.message!=='session')toast('حذف ناموفق بود: '+e.message,'err');}).finally(function(){busy(b,false);});});});
function reloadKeepDraft(){var draft=updateDirty()?clone(cfg):null;return apiJSON('/admin/config.json').then(function(d){
  if(draft){draft.TG=d.TG;draft.CF=d.CF;cfg=draft;var s=JSON.parse(snap);s.TG=d.TG;s.CF=d.CF;snap=JSON.stringify(s);}else{cfg=d;normalize();snap=JSON.stringify(cfg);}fillAll();updateDirty();});}

/* گزارش‌ها */
function loadLogs(){var b=$('logReload');busy(b,true);$('logBody').innerHTML='<div class="skeleton" style="height:220px"></div>';
  apiJSON('/admin/log.json').then(function(d){logs=(Array.isArray(d)?d:[]).slice().sort(function(a,b){return (b.TIME||0)-(a.TIME||0);});
    var sel=$('logType'),cur=sel.value,types={};logs.forEach(function(l){types[l.TYPE]=1;});sel.innerHTML='<option value="">همهٔ رویدادها</option>'+Object.keys(types).map(function(t){return '<option value="'+esc(t)+'">'+esc((LOG_TYPES[t]||[t])[0])+'</option>';}).join('');sel.value=types[cur]?cur:'';
    logPage=1;renderLogs();})
  .catch(function(e){if(e.message!=='session')$('logBody').innerHTML='<div class="empty"><b>دریافت گزارش‌ها ناموفق بود</b>'+esc(e.message)+'</div>';}).finally(function(){busy(b,false);});}
function filteredLogs(){var q=$('logSearch').value.trim().toLowerCase(),t=$('logType').value;return logs.filter(function(l){if(t&&l.TYPE!==t)return false;if(!q)return true;return [l.IP,l.CC,l.ASN,l.URL,l.UA,country(String(l.CC||'').split(' ')[0])].join(' ').toLowerCase().indexOf(q)>-1;});}
function renderLogs(){var list=filteredLogs(),pages=Math.max(1,Math.ceil(list.length/LOG_PER));if(logPage>pages)logPage=pages;
  if(!list.length){$('logBody').innerHTML='<div class="empty"><svg><use href="#i-inbox"/></svg><b>'+(logs.length?'موردی با این فیلتر پیدا نشد':'هنوز رویدادی ثبت نشده است')+'</b>'+(logs.length?'عبارت جست‌وجو یا فیلتر را تغییر دهید.':'پس از ورود به پنل یا دریافت اشتراک، رویدادها این‌جا نمایش داده می‌شوند.')+'</div>';$('logPager').innerHTML='';return;}
  var rows=list.slice((logPage-1)*LOG_PER,logPage*LOG_PER).map(function(l){var tp=LOG_TYPES[l.TYPE]||[l.TYPE,''],cc=String(l.CC||'').split(' '),path='';try{var u=new URL(l.URL);path=u.pathname+u.search;}catch(e){path=l.URL||'';}
    path=path.replace(/token=[^&]+/,'token=…');
    return '<tr><td class="c-time">'+esc(l.TIME?dtf.format(new Date(l.TIME)):'—')+'</td><td class="c-type"><span class="type-tag '+tp[1]+'">'+esc(tp[0])+'</span></td><td class="ltr-cell c-ip">'+esc(l.IP)+'</td><td class="c-loc">'+esc(country(cc[0]))+(cc[1]&&cc[1]!=='N/A'?'، <span class="ltr">'+esc(cc.slice(1).join(' '))+'</span>':'')+'</td><td class="ltr-cell c-asn">'+esc(l.ASN)+'</td><td class="ltr-cell c-path">'+esc(path)+'</td><td class="c-ua"><span class="ua" title="'+esc(l.UA)+'">'+esc(l.UA)+'</span></td></tr>';}).join('');
  $('logBody').innerHTML='<div class="table-wrap"><table class="logs"><thead><tr><th>زمان</th><th>رویداد</th><th>آی‌پی</th><th>موقعیت</th><th>شبکه</th><th>مسیر</th><th>User-Agent</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
  $('logPager').innerHTML='<span>'+fa(list.length)+' رویداد'+(list.length!==logs.length?' از '+fa(logs.length):'')+'</span><span class="row"><button class="btn btn-ghost btn-sm" type="button" data-p="-1" '+(logPage<=1?'disabled':'')+'><svg style="transform:scaleX(-1)"><use href="#i-chev"/></svg>قبلی</button><span>صفحهٔ '+fa(logPage)+' از '+fa(pages)+'</span><button class="btn btn-ghost btn-sm" type="button" data-p="1" '+(logPage>=pages?'disabled':'')+'>بعدی<svg><use href="#i-chev"/></svg></button></span>';}
$('logPager').addEventListener('click',function(e){var b=e.target.closest('button[data-p]');if(!b)return;logPage+=Number(b.dataset.p);renderLogs();$('view-logs').scrollIntoView({behavior:'smooth',block:'start'});});
$('logSearch').addEventListener('input',function(){logPage=1;renderLogs();});
$('logType').addEventListener('change',function(){logPage=1;renderLogs();});
$('logReload').addEventListener('click',loadLogs);
$('logExport').addEventListener('click',function(){if(!logs.length){toast('گزارشی برای دریافت وجود ندارد.','info');return;}dl(new Blob([JSON.stringify(logs,null,2)],{type:'application/json'}),'avatar-logs-'+stamp()+'.json');});
function stamp(){var d=new Date();return d.getFullYear()+String(d.getMonth()+1).padStart(2,'0')+String(d.getDate()).padStart(2,'0');}

/* پیشرفته */
function applyObject(o,src){if(!o||typeof o!=='object'||Array.isArray(o))throw new Error('ساختار باید یک شیء JSON باشد.');if(!o.UUID||!o.HOST)throw new Error('کلیدهای UUID و HOST الزامی‌اند.');
  var keep={UUID:cfg.UUID,HOST:cfg.HOST,TG:cfg.TG,CF:cfg.CF};cfg=o;Object.keys(keep).forEach(function(k){cfg[k]=keep[k];});normalize();fillAll();updateDirty();
  toast(src+' در فرم‌ها اعمال شد؛ برای ماندگاری، «ذخیرهٔ تغییرات» را بزنید.','info');}
$('rawFormat').addEventListener('click',function(){var box=$('rawResult');try{$('rawJson').value=JSON.stringify(JSON.parse($('rawJson').value),null,2);box.className='result';}catch(e){box.className='result show err';box.textContent='JSON نامعتبر است: '+e.message;}});
$('rawApply').addEventListener('click',function(){var box=$('rawResult');try{applyObject(JSON.parse($('rawJson').value),'پیکربندی');box.className='result';}catch(e){box.className='result show err';box.textContent=(e instanceof SyntaxError?'JSON نامعتبر است: ':'')+e.message;}});
$('backupDl').addEventListener('click',function(){dl(new Blob([JSON.stringify(cfg,null,2)],{type:'application/json'}),'avatar-config-'+stamp()+'.json');});
$('backupFile').addEventListener('change',function(){var f=this.files[0];if(!f)return;var r=new FileReader();r.onload=function(){try{applyObject(JSON.parse(r.result),'پشتیبان');}catch(e){toast('فایل پشتیبان معتبر نیست: '+e.message,'err');}};r.readAsText(f);this.value='';});
$('resetBtn').addEventListener('click',function(){var b=this;confirmBox('بازنشانی همهٔ تنظیمات؟','همهٔ تنظیمات گره، اشتراک و پراکسی به حالت پیش‌فرض برمی‌گردد. این کار بازگشت‌پذیر نیست.','بازنشانی',true).then(function(ok){if(!ok)return;busy(b,true);
  apiJSON('/admin/init',{method:'POST'}).then(function(d){toast(d.init||'تنظیمات بازنشانی شد','ok');return loadConfig();}).catch(function(e){if(e.message!=='session')toast('بازنشانی ناموفق بود: '+e.message,'err');}).finally(function(){busy(b,false);});});});

/* مسیریابی بخش‌ها */
var VIEWS=['overview','node','preferred','convert','proxy','integrations','logs','advanced'];
function route(){var v=location.hash.replace('#','');if(VIEWS.indexOf(v)===-1)v='overview';
  document.querySelectorAll('.view').forEach(function(s){s.classList.toggle('active',s.id==='view-'+v);});
  document.querySelectorAll('.nav-item').forEach(function(a){var on=a.dataset.view===v;if(on){a.setAttribute('aria-current','page');if(a.scrollIntoView&&window.innerWidth<=900)a.scrollIntoView({block:'nearest',inline:'center'});}else a.removeAttribute('aria-current');});
  var titles={overview:'پیشخوان',node:'گره و پروتکل',preferred:'آی‌پی‌های بهینه',convert:'تبدیل اشتراک',proxy:'پراکسی و مسیریابی',integrations:'اعلان و آمار',logs:'گزارش‌ها',advanced:'پیشرفته'};
  document.title=titles[v]+' · Avatar';
  if(!cfg)return;
  if(v==='overview'){renderOverview();if(!edgeLoaded)loadEdge();}
  if(v==='preferred'&&!addLoaded)loadAdd();
  if(v==='logs')loadLogs();
  if(v==='advanced'){$('rawJson').value=JSON.stringify(cfg,null,2);$('rawResult').className='result';}
  window.scrollTo({top:0});}
window.addEventListener('hashchange',route);

/* آغاز */
try{$('year').textContent=new Intl.DateTimeFormat('fa-IR-u-ca-persian',{year:'numeric'}).format(new Date());}catch(e){$('year').textContent=fa(new Date().getFullYear());}
var VER='{{VERSION}}'.split('|'),verTxt='نسخهٔ '+faDigits(VER[0]);
try{if(VER[1])verTxt+=' · '+new Intl.DateTimeFormat('fa-IR-u-ca-persian',{timeZone:'Asia/Tehran',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date(VER[1]+'T12:00:00Z'));}catch(e){}
$('footVer').textContent=verTxt;$('navMeta').textContent=verTxt;
function syncTheme(){var dark=document.documentElement.dataset.theme==='dark',l=dark?'تغییر پوسته به روشن':'تغییر پوسته به تیره';$('themeBtn').setAttribute('aria-label',l);$('themeBtn').title=l;var m=document.querySelector('meta[name=theme-color]');if(m)m.content=dark?'#0e0a1f':'#1f1647';}
$('themeBtn').addEventListener('click',function(){var t=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=t;try{localStorage.setItem('avatar-theme',t);}catch(e){}syncTheme();});
syncTheme();
$('skipLink').addEventListener('click',function(e){e.preventDefault();$('main').focus();});
function boot(){$('fatal').classList.add('hidden');$('boot').classList.remove('hidden');
  loadConfig().then(function(){$('boot').classList.add('hidden');route();})
  .catch(function(e){if(e.message==='session')return;$('boot').classList.add('hidden');$('fatalMsg').textContent=e.message||'ارتباط با سرور برقرار نشد.';$('fatal').classList.remove('hidden');});}
$('retryBtn').addEventListener('click',boot);
$('logoutBtn').addEventListener('click',function(e){if(updateDirty()){e.preventDefault();var href=this.href;confirmBox('خروج بدون ذخیره؟','تغییرات ذخیره‌نشده از بین می‌رود.','خروج',true).then(function(ok){if(ok){snap=JSON.stringify(cfg);location.href=href;}});}});
boot();
})();
</script>
</body>
</html>
`,
	noADMIN: `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="#1f1647">
<title>راه‌اندازی رمز مدیر · Avatar</title>
<meta name="description" content="راهنمای راه‌اندازی اولیهٔ Avatar">
<link rel="icon" href="data:image/svg+xml,%3Csvg viewBox=%220 0 48 48%22 width=%2248%22 height=%2248%22 xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cg transform=%22translate%2824 24%29%22%3E%3Crect x=%22-15%22 y=%22-15%22 width=%2230%22 height=%2230%22 rx=%223%22 fill=%22%23e84a00%22/%3E%3Crect x=%22-15%22 y=%22-15%22 width=%2230%22 height=%2230%22 rx=%223%22 fill=%22%23e84a00%22 transform=%22rotate%2845%29%22/%3E%3Ccircle r=%229.5%22 fill=%22%232c1f62%22/%3E%3Cpath d=%22M0-6.2 5.4 3.1H-5.4Z%22 fill=%22%23fff%22/%3E%3Ccircle r=%221.6%22 cy=%220.8%22 fill=%22%232c1f62%22/%3E%3C/g%3E%3C/svg%3E">
<!--AVATAR:STYLE-->
<style>body{background:var(--bg);padding:24px;display:grid;place-items:center}
.wrap{width:min(100%,640px)}
.top{display:flex;align-items:center;gap:10px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:20px;box-shadow:var(--shadow);overflow:hidden}
.band{background:var(--indigo-800);color:#fff;padding:28px 28px 24px;position:relative;overflow:hidden}
.band::after{content:"";position:absolute;inset:0;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='96' height='96' viewBox='0 0 96 96'%3E%3Cg fill='none' stroke='%23ffffff' stroke-opacity='.13'%3E%3Crect x='34' y='34' width='28' height='28'/%3E%3Crect x='34' y='34' width='28' height='28' transform='rotate%2845 48 48%29'/%3E%3Cpath d='M48 0v14M48 82v14M0 48h14M82 48h14'/%3E%3Ccircle cx='0' cy='0' r='10'/%3E%3Ccircle cx='96' cy='0' r='10'/%3E%3Ccircle cx='0' cy='96' r='10'/%3E%3Ccircle cx='96' cy='96' r='10'/%3E%3C/g%3E%3Ccircle cx='48' cy='48' r='2.2' fill='%23e84a00' fill-opacity='.55'/%3E%3C/svg%3E");background-size:96px 96px;opacity:.35;pointer-events:none}
.band>*{position:relative;z-index:1}
.tag{display:inline-block;font-size:14px;font-weight:600;padding:2px 12px;border-radius:99px;background:rgba(232,74,0,.22);color:#ffc7a8;margin-bottom:10px}
h1{font-size:26px;font-weight:800;line-height:1.45}
.band p{color:rgba(255,255,255,.78);margin-top:6px;font-size:15.5px}
.body{padding:24px 28px 28px}
ol{list-style:none;counter-reset:s;display:flex;flex-direction:column;gap:16px}
ol li{counter-increment:s;display:grid;grid-template-columns:32px 1fr;gap:12px;align-items:start}
ol li::before{content:counter(s,persian);display:grid;place-items:center;width:32px;height:32px;border-radius:50%;background:var(--saffron-50);color:var(--saffron-600);font-weight:800;border:1px solid var(--saffron-100)}
ol li b{display:block;font-weight:700;margin-bottom:2px}
ol li span{color:var(--muted);font-size:15px}
code{font-family:var(--mono);font-size:13.5px;background:var(--indigo-50);color:var(--accent-ink);padding:1px 7px;border-radius:6px;direction:ltr;unicode-bidi:isolate;white-space:nowrap}
.path{display:inline-block;direction:ltr;unicode-bidi:isolate;font-size:14.5px;color:var(--text);background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:1px 8px;margin:2px 0}
.note{margin-top:22px;padding:12px 14px;border-radius:12px;background:var(--teal-100);color:var(--info-ink);font-size:14.5px}
.actions{display:flex;gap:10px;margin-top:22px;flex-wrap:wrap}
.foot{text-align:center;margin-top:16px;color:var(--faint);font-size:14px}
@media (max-width:480px){.band,.body{padding-inline:20px}h1{font-size:22px}}
</style>
</head>
<body>
<main class="wrap">
  <div class="top"><span class="mark"><svg viewBox="0 0 48 48" width="36" height="36" aria-hidden="true"><g transform="translate(24 24)"><rect x="-15" y="-15" width="30" height="30" rx="3" fill="#e84a00"/><rect x="-15" y="-15" width="30" height="30" rx="3" fill="#e84a00" transform="rotate(45)"/><circle r="9.5" fill="#2c1f62"/><path d="M0-6.2 5.4 3.1H-5.4Z" fill="#fff"/><circle r="1.6" cy="0.8" fill="#2c1f62"/></g></svg></span><span class="wordmark">Avatar</span></div>
  <section class="card">
    <div class="band">
      <span class="tag">گام اول راه‌اندازی</span>
      <h1>رمز عبور مدیر هنوز تعریف نشده است</h1>
      <p>تا زمانی که متغیر <code style="background:rgba(255,255,255,.14);color:#fff">ADMIN</code> را تنظیم نکنید، پنل و اتصال‌ها غیرفعال می‌مانند.</p>
    </div>
    <div class="body">
      <ol>
        <li><div><b>پیشخوان Cloudflare را باز کنید</b><span>به بخش <span class="path">Workers &amp; Pages</span> بروید و پروژهٔ Avatar را انتخاب کنید.</span></div></li>
        <li><div><b>متغیر محیطی بسازید</b><span>در <span class="path">Settings → Variables and Secrets</span> روی <span class="path">Add</span> بزنید، نام را <code>ADMIN</code> بگذارید و یک رمز عبور قوی وارد کنید.</span></div></li>
        <li><div><b>ذخیره و استقرار دوباره</b><span>تغییرات را ذخیره کنید. در پروژه‌های Pages یک استقرار تازه هم لازم است.</span></div></li>
        <li><div><b>وارد پنل شوید</b><span>نشانی <code>/admin</code> را روی همین دامنه باز کنید و با رمز تازه وارد شوید.</span></div></li>
      </ol>
      <p class="note">پیشنهاد: رمز را دست‌کم ۱۲ نویسه و ترکیبی از حروف، عدد و نماد انتخاب کنید و هنگام کپی‌کردن، فاصله یا خط تازهٔ اضافه نگذارید.</p>
      <div class="actions"><button class="btn btn-primary" type="button" onclick="location.reload()">بررسی دوباره</button></div>
    </div>
  </section>
  <p class="foot">Avatar</p>
</main>
</body>
</html>
`,
	noKV: `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="#1f1647">
<title>اتصال فضای ذخیره‌سازی · Avatar</title>
<meta name="description" content="راهنمای اتصال فضای نام KV به Avatar">
<link rel="icon" href="data:image/svg+xml,%3Csvg viewBox=%220 0 48 48%22 width=%2248%22 height=%2248%22 xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cg transform=%22translate%2824 24%29%22%3E%3Crect x=%22-15%22 y=%22-15%22 width=%2230%22 height=%2230%22 rx=%223%22 fill=%22%23e84a00%22/%3E%3Crect x=%22-15%22 y=%22-15%22 width=%2230%22 height=%2230%22 rx=%223%22 fill=%22%23e84a00%22 transform=%22rotate%2845%29%22/%3E%3Ccircle r=%229.5%22 fill=%22%232c1f62%22/%3E%3Cpath d=%22M0-6.2 5.4 3.1H-5.4Z%22 fill=%22%23fff%22/%3E%3Ccircle r=%221.6%22 cy=%220.8%22 fill=%22%232c1f62%22/%3E%3C/g%3E%3C/svg%3E">
<!--AVATAR:STYLE-->
<style>body{background:var(--bg);padding:24px;display:grid;place-items:center}
.wrap{width:min(100%,640px)}
.top{display:flex;align-items:center;gap:10px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:20px;box-shadow:var(--shadow);overflow:hidden}
.band{background:var(--indigo-800);color:#fff;padding:28px 28px 24px;position:relative;overflow:hidden}
.band::after{content:"";position:absolute;inset:0;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='96' height='96' viewBox='0 0 96 96'%3E%3Cg fill='none' stroke='%23ffffff' stroke-opacity='.13'%3E%3Crect x='34' y='34' width='28' height='28'/%3E%3Crect x='34' y='34' width='28' height='28' transform='rotate%2845 48 48%29'/%3E%3Cpath d='M48 0v14M48 82v14M0 48h14M82 48h14'/%3E%3Ccircle cx='0' cy='0' r='10'/%3E%3Ccircle cx='96' cy='0' r='10'/%3E%3Ccircle cx='0' cy='96' r='10'/%3E%3Ccircle cx='96' cy='96' r='10'/%3E%3C/g%3E%3Ccircle cx='48' cy='48' r='2.2' fill='%23e84a00' fill-opacity='.55'/%3E%3C/svg%3E");background-size:96px 96px;opacity:.35;pointer-events:none}
.band>*{position:relative;z-index:1}
.tag{display:inline-block;font-size:14px;font-weight:600;padding:2px 12px;border-radius:99px;background:rgba(232,74,0,.22);color:#ffc7a8;margin-bottom:10px}
h1{font-size:26px;font-weight:800;line-height:1.45}
.band p{color:rgba(255,255,255,.78);margin-top:6px;font-size:15.5px}
.body{padding:24px 28px 28px}
ol{list-style:none;counter-reset:s;display:flex;flex-direction:column;gap:16px}
ol li{counter-increment:s;display:grid;grid-template-columns:32px 1fr;gap:12px;align-items:start}
ol li::before{content:counter(s,persian);display:grid;place-items:center;width:32px;height:32px;border-radius:50%;background:var(--saffron-50);color:var(--saffron-600);font-weight:800;border:1px solid var(--saffron-100)}
ol li b{display:block;font-weight:700;margin-bottom:2px}
ol li span{color:var(--muted);font-size:15px}
code{font-family:var(--mono);font-size:13.5px;background:var(--indigo-50);color:var(--accent-ink);padding:1px 7px;border-radius:6px;direction:ltr;unicode-bidi:isolate;white-space:nowrap}
.path{display:inline-block;direction:ltr;unicode-bidi:isolate;font-size:14.5px;color:var(--text);background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:1px 8px;margin:2px 0}
.note{margin-top:22px;padding:12px 14px;border-radius:12px;background:var(--teal-100);color:var(--info-ink);font-size:14.5px}
.actions{display:flex;gap:10px;margin-top:22px;flex-wrap:wrap}
.foot{text-align:center;margin-top:16px;color:var(--faint);font-size:14px}
@media (max-width:480px){.band,.body{padding-inline:20px}h1{font-size:22px}}
</style>
</head>
<body>
<main class="wrap">
  <div class="top"><span class="mark"><svg viewBox="0 0 48 48" width="36" height="36" aria-hidden="true"><g transform="translate(24 24)"><rect x="-15" y="-15" width="30" height="30" rx="3" fill="#e84a00"/><rect x="-15" y="-15" width="30" height="30" rx="3" fill="#e84a00" transform="rotate(45)"/><circle r="9.5" fill="#2c1f62"/><path d="M0-6.2 5.4 3.1H-5.4Z" fill="#fff"/><circle r="1.6" cy="0.8" fill="#2c1f62"/></g></svg></span><span class="wordmark">Avatar</span></div>
  <section class="card">
    <div class="band">
      <span class="tag">گام دوم راه‌اندازی</span>
      <h1>فضای ذخیره‌سازی KV متصل نیست</h1>
      <p>Avatar تنظیمات، گزارش‌ها و فهرست آی‌پی‌ها را در یک فضای نام KV نگه می‌دارد. بدون آن، پنل مدیریت در دسترس نیست.</p>
    </div>
    <div class="body">
      <ol>
        <li><div><b>یک فضای نام KV بسازید</b><span>در پیشخوان Cloudflare به <span class="path">Storage &amp; Databases → KV</span> بروید و روی <span class="path">Create</span> بزنید.</span></div></li>
        <li><div><b>آن را به پروژه وصل کنید</b><span>در تنظیمات پروژهٔ Avatar بخش <span class="path">Bindings → Add → KV namespace</span> را باز کنید.</span></div></li>
        <li><div><b>نام متغیر را دقیق وارد کنید</b><span>نام اتصال باید دقیقاً <code>KV</code> (با حروف بزرگ) باشد. سپس فضای نامی را که ساختید انتخاب کنید.</span></div></li>
        <li><div><b>ذخیره و بارگذاری دوباره</b><span>پس از ذخیره (و در Pages، استقرار دوباره) همین صفحه را تازه کنید.</span></div></li>
      </ol>
      <p class="note">اگر نمی‌خواهید از KV استفاده کنید، می‌توانید متغیر <code>UUID</code> را با یک شناسهٔ استاندارد UUIDv4 تنظیم کنید تا اتصال‌ها بدون پنل کار کنند.</p>
      <div class="actions"><button class="btn btn-primary" type="button" onclick="location.reload()">بررسی دوباره</button></div>
    </div>
  </section>
  <p class="foot">Avatar</p>
</main>
</body>
</html>
`,
};
function Avatar页面(名称, 状态码 = 200) {
	const 版本 = '2.1|' + String(Version).slice(0, 10);
	const html = Avatar_صفحات[名称].replace('<!--AVATAR:STYLE-->', () => Avatar_سبک_پایه).replace('{{VERSION}}', () => 版本);
	return new Response(html, {
		status: 状态码,
		headers: {
			'Content-Type': 'text/html; charset=utf-8',
			'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
			'Pragma': 'no-cache',
			'Expires': '0',
			'X-Frame-Options': 'DENY',
			'X-Content-Type-Options': 'nosniff',
			'Referrer-Policy': 'no-referrer',
		}
	});
}
