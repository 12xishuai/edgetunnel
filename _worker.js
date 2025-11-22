importimport { connect } from "cloudflare:sockets";
let config_JSON, 反代IP = '', 启用SOCKS5反代 = null, 启用SOCKS5全局反代 = false, 我的SOCKS5账号 = '', parsedSocks5Address = {};
let SOCKS5白名单 = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];
const Pages静态页面 = 'https://edt-pages.github.io';
///////////////////////////////////////////////////////主程序入口///////////////////////////////////////////////
export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const UA = request.headers.get('User-Agent') || 'null';
        const upgradeHeader = request.headers.get('Upgrade');
        const 管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY;
        const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
        const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);
        const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
        const envUUID = env.UUID || env.uuid;
        const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), userIDMD5.slice(16, 20), userIDMD5.slice(20)].join('-');
         //  新添加的代码在这里
        if (url.pathname === '/tgwebhook') {
            return await handleTelegramWebhook(request, env);
        }
        // ... 现有代码继续 ...
        if (env.PROXYIP) {
            const proxyIPs = await 整理成数组(env.PROXYIP);
            反代IP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
        } else 反代IP = (request.cf.colo + '.PrOxYIp.CmLiUsSsS.nEt').toLowerCase();
        const 访问IP = request.headers.get('X-Real-IP') || request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || request.headers.get('True-Client-IP') || request.headers.get('Fly-Client-IP') || request.headers.get('X-Appengine-Remote-Addr') || request.headers.get('X-Forwarded-For') || request.headers.get('X-Real-IP') || request.headers.get('X-Cluster-Client-IP') || request.cf?.clientTcpRtt || '未知IP';
        if (env.GO2SOCKS5) SOCKS5白名单 = await 整理成数组(env.GO2SOCKS5);
        if (!upgradeHeader || upgradeHeader !== 'websocket') {
            if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
            if (!管理员密码) return fetch(Pages静态页面 + '/noADMIN').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }); });
            if (!env.KV) return fetch(Pages静态页面 + '/noKV').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }); });
            const 访问路径 = url.pathname.slice(1).toLowerCase();
            const 区分大小写访问路径 = url.pathname.slice(1);
            if (访问路径 === 加密秘钥 && 加密秘钥 !== '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改') {//快速订阅
                const params = new URLSearchParams(url.search);
                params.set('token', await MD5MD5(url.host + userID));
                return new Response('重定向中...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
            } else if (访问路径 === 'login') {//处理登录页面和登录请求
                const cookies = request.headers.get('Cookie') || '';
                const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
                if (authCookie == await MD5MD5(UA + 加密秘钥 + 管理员密码)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/admin' } });
                if (request.method === 'POST') {
                    const formData = await request.text();
                    const params = new URLSearchParams(formData);
                    const 输入密码 = params.get('password');
                    if (输入密码 === 管理员密码) {
                        // 密码正确，设置cookie并返回成功标记
                        const 响应 = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        响应.headers.set('Set-Cookie', `auth=${await MD5MD5(UA + 加密秘钥 + 管理员密码)}; Path=/; Max-Age=86400; HttpOnly`);
                        return 响应;
                    }
                }
                return fetch(Pages静态页面 + '/login');
            } else if (访问路径 == 'admin' || 访问路径.startsWith('admin/')) {//验证cookie后响应管理页面
                const cookies = request.headers.get('Cookie') || '';
                const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
                // 没有cookie或cookie错误，跳转到/login页面
                if (!authCookie || authCookie !== await MD5MD5(UA + 加密秘钥 + 管理员密码)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
                if (访问路径 === 'admin/log.json') {// 读取日志内容
                    const 读取日志内容 = await env.KV.get('log.json') || '[]';
                    return new Response(读取日志内容, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                } else if (区分大小写访问路径 === 'admin/getCloudflareUsage') {// 查询请求量
                    try {
                        const Usage_JSON = await getCloudflareUsage(url.searchParams.get('Email'), url.searchParams.get('GlobalAPIKey'), url.searchParams.get('AccountID'), url.searchParams.get('APIToken'));
                        return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
                    } catch (err) {
                        const errorResponse = { msg: '查询请求量失败，失败原因：' + err.message, error: err.message };
                        return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    }
                } else if (区分大小写访问路径 === 'admin/getADDAPI') {// 验证优选API
                    if (url.searchParams.get('url')) {
                        const 待验证优选URL = url.searchParams.get('url');
                        try {
                            new URL(待验证优选URL);
                            const 优选API的IP = await 请求优选API([待验证优选URL], url.searchParams.get('port') || '443');
                            return new Response(JSON.stringify({ success: true, data: 优选API的IP }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        } catch (err) {
                            const errorResponse = { msg: '验证优选API失败，失败原因：' + err.message, error: err.message };
                            return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                    }
                    return new Response(JSON.stringify({ success: false, data: [] }, null, 2), { status: 403, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                } else if (访问路径 === 'admin/check') {// SOCKS5代理检查
                    let 检测代理响应;
                    if (url.searchParams.has('socks5')) {
                        检测代理响应 = await SOCKS5可用性验证('socks5', url.searchParams.get('socks5'));
                    } else if (url.searchParams.has('http')) {
                        检测代理响应 = await SOCKS5可用性验证('http', url.searchParams.get('http'));
                    } else {
                        return new Response(JSON.stringify({ error: '缺少代理参数' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    }
                    return new Response(JSON.stringify(检测代理响应, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                }

                config_JSON = await 读取config_JSON(env, url.host, userID);

                if (访问路径 === 'admin/init') {// 重置配置为默认值
                    try {
                        config_JSON = await 读取config_JSON(env, url.host, userID, true);
                        await 请求日志记录(env, request, 访问IP, 'Init_Config', config_JSON);
                        config_JSON.init = '配置已重置为默认值';
                        return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    } catch (err) {
                        const errorResponse = { msg: '配置重置失败，失败原因：' + err.message, error: err.message };
                        return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    }
                } else if (request.method === 'POST') {// 处理 KV 操作（POST 请求）
                    if (访问路径 === 'admin/config.json') { // 保存config.json配置
                        try {
                            const newConfig = await request.json();
                            // 验证配置完整性
                            if (!newConfig.UUID || !newConfig.HOST) return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });

                            // 保存到 KV
                            await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
                            await 请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON);
                            return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        } catch (error) {
                            console.error('保存配置失败:', error);
                            return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                    } else if (访问路径 === 'admin/cf.json') { // 保存cf.json配置
                        try {
                            const newConfig = await request.json();
                            const CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null };
                            if (!newConfig.init || newConfig.init !== true) {
                                if (newConfig.Email && newConfig.GlobalAPIKey) {
                                    CF_JSON.Email = newConfig.Email;
                                    CF_JSON.GlobalAPIKey = newConfig.GlobalAPIKey;
                                    CF_JSON.AccountID = null;
                                    CF_JSON.APIToken = null;
                                } else if (newConfig.AccountID && newConfig.APIToken) {
                                    CF_JSON.Email = null;
                                    CF_JSON.GlobalAPIKey = null;
                                    CF_JSON.AccountID = newConfig.AccountID;
                                    CF_JSON.APIToken = newConfig.APIToken;
                                } else {
                                    return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                                }
                            }

                            // 保存到 KV
                            await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
                            await 请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON);
                            return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        } catch (error) {
                            console.error('保存配置失败:', error);
                            return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                    } else if (访问路径 === 'admin/tg.json') { // 保存tg.json配置
                        try {
                            const newConfig = await request.json();
                            if (newConfig.init && newConfig.init === true) {
                                const TG_JSON = { BotToken: null, ChatID: null };
                                await env.KV.put('tg.json', JSON.stringify(TG_JSON, null, 2));
                            } else {
                                if (!newConfig.BotToken || !newConfig.ChatID) return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                                await env.KV.put('tg.json', JSON.stringify(newConfig, null, 2));
                            }
                            await 请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON);
                            return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        } catch (error) {
                            console.error('保存配置失败:', error);
                            return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                    } else if (区分大小写访问路径 === 'admin/ADD.txt') { // 保存自定义优选IP
                        try {
                            const customIPs = await request.text();
                            await env.KV.put('ADD.txt', customIPs);// 保存到 KV
                            await 请求日志记录(env, request, 访问IP, 'Save_Custom_IPs', config_JSON);
                            return new Response(JSON.stringify({ success: true, message: '自定义IP已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        } catch (error) {
                            console.error('保存自定义IP失败:', error);
                            return new Response(JSON.stringify({ error: '保存自定义IP失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                    } else return new Response(JSON.stringify({ error: '不支持的POST请求路径' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                } else if (访问路径 === 'admin/config.json') {// 处理 admin/config.json 请求，返回JSON
                    return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
                } else if (区分大小写访问路径 === 'admin/ADD.txt') {// 处理 admin/ADD.txt 请求，返回本地优选IP
                    let 本地优选IP = await env.KV.get('ADD.txt') || 'null';
                    if (本地优选IP == 'null') 本地优选IP = (await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口))[1];
                    return new Response(本地优选IP, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8', 'asn': request.cf.asn } });
                } else if (访问路径 === 'admin/cf.json') {// CF配置文件
                    return new Response(JSON.stringify(request.cf, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                }

                await 请求日志记录(env, request, 访问IP, 'Admin_Login', config_JSON);
                return fetch(Pages静态页面 + '/admin');
            } else if (访问路径 === 'logout') {//清除cookie并跳转到登录页面
                const 响应 = new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
                响应.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
                return 响应;
            } else if (访问路径 === 'sub') {//处理订阅请求
                const 订阅TOKEN = await MD5MD5(url.host + userID);
                if (url.searchParams.get('token') === 订阅TOKEN) {
                    config_JSON = await 读取config_JSON(env, url.host, userID);
                    await 请求日志记录(env, request, 访问IP, 'Get_SUB', config_JSON);
                    const ua = UA.toLowerCase();
                    const expire = 4102329600;//2099-12-31 到期时间
                    const now = Date.now();
                    const today = new Date(now);
                    today.setHours(0, 0, 0, 0);
                    const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
                    let pagesSum = UD, workersSum = UD, total = 24 * 1099511627776;
                    if (config_JSON.CF.Usage.success) {
                        pagesSum = config_JSON.CF.Usage.pages;
                        workersSum = config_JSON.CF.Usage.workers;
                        total = 1024 * 100;
                    }
                    const responseHeaders = {
                        "content-type": "text/plain; charset=utf-8",
                        "Profile-Update-Interval": config_JSON.优选订阅生成.SUBUpdateTime,
                        "Profile-web-page-url": url.protocol + '//' + url.host + '/admin',
                        "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                        "Cache-Control": "no-store",
                    };
                    const isSubConverterRequest = request.headers.has('b64') || request.headers.has('base64') || request.headers.get('subconverter-request') || request.headers.get('subconverter-version') || ua.includes('subconverter') || ua.includes(('CF-Workers-SUB').toLowerCase());
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
                                        : 'mixed';

                    if (!ua.includes('mozilla')) responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`;
                    const 协议类型 = (url.searchParams.has('surge') || ua.includes('surge')) ? 'tro' + 'jan' : config_JSON.协议类型;
                    let 订阅内容 = '';
                    if (订阅类型 === 'mixed') {
                        const 节点路径 = config_JSON.启用0RTT ? config_JSON.PATH + '?ed=2560' : config_JSON.PATH;
                        const TLS分片参数 = config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
                        const 完整优选列表 = config_JSON.优选订阅生成.本地IP库.随机IP ? (await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口))[0] : await env.KV.get('ADD.txt') ? await 整理成数组(await env.KV.get('ADD.txt')) : (await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口))[0];
                        const 优选API = [], 优选IP = [], 其他节点 = [];
                        for (const 元素 of 完整优选列表) {
                            if (元素.toLowerCase().startsWith('https://')) 优选API.push(元素);
                            else if (元素.toLowerCase().includes('://')) 其他节点.push(元素);
                            else 优选IP.push(元素);
                        }
                        const 其他节点LINK = 其他节点.join('\n') + '\n';
                        if (!url.searchParams.has('sub') && config_JSON.优选订阅生成.local) { // 本地生成订阅
                            const 优选API的IP = await 请求优选API(优选API);
                            const 完整优选IP = [...new Set(优选IP.concat(优选API的IP))];
                            订阅内容 = 完整优选IP.map(原始地址 => {
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
                                    节点端口 = match[2] || "443";  // 端口,默认443
                                    节点备注 = match[3] || 节点地址;  // 备注,默认为地址本身
                                } else {
                                    // 不规范的格式，跳过处理返回null
                                    console.warn(`[订阅内容] 不规范的IP格式已忽略: ${原始地址}`);
                                    return null;
                                }

                                return `${协议类型}://${config_JSON.UUID}@${节点地址}:${节点端口}?security=tls&type=${config_JSON.传输协议}&host=${config_JSON.HOST}&sni=${config_JSON.HOST}&path=${encodeURIComponent((随机路径() + 节点路径).replace('/?', '?')) + TLS分片参数}&encryption=none${config_JSON.跳过证书验证 ? '&allowInsecure=1' : ''}#${encodeURIComponent(节点备注)}`;
                            }).filter(item => item !== null).join('\n');
                            订阅内容 = btoa(其他节点LINK + 订阅内容);
                        } else { // 优选订阅生成器
                            let 优选订阅生成器HOST = url.searchParams.get('sub') || config_JSON.优选订阅生成.SUB;
                            优选订阅生成器HOST = 优选订阅生成器HOST && !/^https?:\/\//i.test(优选订阅生成器HOST) ? `https://${优选订阅生成器HOST}` : 优选订阅生成器HOST;
                            const 优选订阅生成器URL = `${优选订阅生成器HOST}/sub?host=example.com&${协议类型 === ('v' + 'le' + 'ss') ? 'uuid' : 'pw'}=00000000-0000-4000-0000-000000000000&path=${encodeURIComponent((随机路径() + 节点路径).replace('/?', '?')) + TLS分片参数}&type=${config_JSON.传输协议}`;
                            try {
                                const response = await fetch(优选订阅生成器URL, { headers: { 'User-Agent': 'v2rayN/edge' + 'tunnel (https://github.com/cmliu/edge' + 'tunnel)' } });
                                if (response.ok) 订阅内容 = btoa(其他节点LINK + atob(await response.text()));
                                else return new Response('优选订阅生成器异常：' + response.statusText, { status: response.status });
                            } catch (error) {
                                return new Response('优选订阅生成器异常：' + error.message, { status: 403 });
                            }
                        }
                    } else { // 订阅转换
                        const 订阅转换URL = `${config_JSON.订阅转换配置.SUBAPI}/sub?target=${订阅类型}&url=${encodeURIComponent(url.protocol + '//' + url.host + '/sub?target=mixed&token=' + 订阅TOKEN) + (url.searchParams.has('sub') && url.searchParams.get('sub') != '' ? `&sub=${url.searchParams.get('sub')}` : '')}&config=${encodeURIComponent(config_JSON.订阅转换配置.SUBCONFIG)}&emoji=${config_JSON.订阅转换配置.SUBEMOJI}&scv=${config_JSON.跳过证书验证}`;
                        try {
                            const response = await fetch(订阅转换URL, { headers: { 'User-Agent': 'Subconverter for ' + 订阅类型 + ' edge' + 'tunnel(https://github.com/cmliu/edge' + 'tunnel)' } });
                            if (response.ok) {
                                订阅内容 = await response.text();
                                if (url.searchParams.has('surge') || ua.includes('surge')) 订阅内容 = surge(订阅内容, url.protocol + '//' + url.host + '/sub?token=' + 订阅TOKEN + '&surge', config_JSON);
                            } else return new Response('订阅转换后端异常：' + response.statusText, { status: response.status });
                        } catch (error) {
                            return new Response('订阅转换后端异常：' + error.message, { status: 403 });
                        }
                    }
                    if (订阅类型 === 'mixed') {
                        订阅内容 = atob(订阅内容).replace(/example.com/g, config_JSON.HOST).replace(/00000000-0000-4000-0000-000000000000/g, config_JSON.UUID);
                        if (!ua.includes('mozilla')) 订阅内容 = btoa(订阅内容);
                    } else 订阅内容 = 订阅内容.replace(/example.com/g, config_JSON.HOST).replace(/00000000-0000-4000-0000-000000000000/g, config_JSON.UUID);
                    if (订阅类型 === 'singbox') {
                        订阅内容 = JSON.stringify(JSON.parse(订阅内容), null, 2);
                        responseHeaders["content-type"] = 'application/json; charset=utf-8';
                    } else if (订阅类型 === 'clash') {
                        responseHeaders["content-type"] = 'application/x-yaml; charset=utf-8';
                    }
                    return new Response(订阅内容, { status: 200, headers: responseHeaders });
                }
                return new Response('无效的订阅TOKEN', { status: 403 });
            } else if (访问路径 === 'locations') return fetch(new Request('https://speed.cloudflare.com/locations'));
        } else if (管理员密码) {// ws代理
            await 反代参数获取(request);
            return await 处理WS请求(request, userID);
        }

        let 伪装页URL = env.URL || 'nginx';
        if (伪装页URL && 伪装页URL !== 'nginx' && 伪装页URL !== '1101') {
            伪装页URL = 伪装页URL.trim().replace(/\/$/, '');
            if (!伪装页URL.match(/^https?:\/\//i)) 伪装页URL = 'https://' + 伪装页URL;
            if (伪装页URL.toLowerCase().startsWith('http://')) 伪装页URL = 'https://' + 伪装页URL.substring(7);
            try { const u = new URL(伪装页URL); 伪装页URL = u.protocol + '//' + u.host; } catch (e) { 伪装页URL = 'nginx'; }
        }
        if (伪装页URL === '1101') return new Response(await html1101(url.host, 访问IP), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
        try {
            const 反代URL = new URL(伪装页URL), 新请求头 = new Headers(request.headers);
            新请求头.set('Host', 反代URL.host);
            if (新请求头.has('Referer')) { const u = new URL(新请求头.get('Referer')); 新请求头.set('Referer', 反代URL.protocol + '//' + 反代URL.host + u.pathname + u.search); }
            if (新请求头.has('Origin')) 新请求头.set('Origin', 反代URL.protocol + '//' + 反代URL.host);
            if (!新请求头.has('User-Agent') && UA && UA !== 'null') 新请求头.set('User-Agent', UA);
            return fetch(new Request(反代URL.protocol + 反代URL.host + url.pathname + url.search, { method: request.method, headers: 新请求头, body: request.body, cf: request.cf }));
        } catch (error) { }
        return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
    }
};
///////////////////////////////////////////////////////////////////////WS传输数据///////////////////////////////////////////////
/**
 * @name 处理WS请求
 * @description 处理WebSocket代理请求，添加完整的错误处理和资源清理
 */
async function 处理WS请求(request, yourUUID) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    
    // 🔧 修复：添加完整的错误处理包装
    try {
        serverSock.accept();
        
        // 🔧 修复：添加WebSocket错误事件监听
        serverSock.addEventListener('error', (error) => {
            console.error('WebSocket server error:', error);
            closeSocketQuietly(serverSock);
        });
        
        clientSock.addEventListener('error', (error) => {
            console.error('WebSocket client error:', error);
            closeSocketQuietly(clientSock);
        });

        // 🔧 修复：添加关闭事件清理资源
        serverSock.addEventListener('close', () => {
            console.log('WebSocket server closed');
            // 确保远程连接也被清理
            if (remoteConnWrapper.socket) {
                closeSocketQuietly(remoteConnWrapper.socket);
            }
        });

        let remoteConnWrapper = { socket: null };
        let isDnsQuery = false;
        const earlyData = request.headers.get('sec-websocket-protocol') || '';
        const readable = makeReadableStr(serverSock, earlyData);
        let 判断是否是木马 = null;
        
        // 🔧 修复：包装整个管道流程，添加错误处理
        const 管道处理 = async () => {
            await readable.pipeTo(new WritableStream({
                async write(chunk) {
                    try {
                        if (isDnsQuery) {
                            await forwardataudp(chunk, serverSock, null);
                            return;
                        }
                        
                        if (remoteConnWrapper.socket) {
                            const writer = remoteConnWrapper.socket.writable.getWriter();
                            await writer.write(chunk);
                            writer.releaseLock();
                            return;
                        }

                        if (判断是否是木马 === null) {
                            const bytes = new Uint8Array(chunk);
                            判断是否是木马 = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a;
                        }

                        if (remoteConnWrapper.socket) {
                            const writer = remoteConnWrapper.socket.writable.getWriter();
                            await writer.write(chunk);
                            writer.releaseLock();
                            return;
                        }

                        if (判断是否是木马) {
                            const { port, hostname, rawClientData, hasError, message } = 解析木马请求(chunk, yourUUID);
                            if (hasError) {
                                throw new Error(`Trojan解析错误: ${message}`);
                            }
                            if (isSpeedTestSite(hostname)) {
                                throw new Error('Speedtest site is blocked');
                            }
                            await forwardataTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper);
                        } else {
                            const { port, hostname, rawIndex, version, isUDP, hasError, message } = 解析魏烈思请求(chunk, yourUUID);
                            if (hasError) {
                                throw new Error(`VLESS解析错误: ${message}`);
                            }
                            if (isSpeedTestSite(hostname)) {
                                throw new Error('Speedtest site is blocked');
                            }
                            if (isUDP) {
                                if (port === 53) {
                                    isDnsQuery = true;
                                } else {
                                    throw new Error('UDP is not supported');
                                }
                            }
                            const respHeader = new Uint8Array([version[0], 0]);
                            const rawData = chunk.slice(rawIndex);
                            if (isDnsQuery) {
                                await forwardataudp(rawData, serverSock, respHeader);
                                return;
                            }
                            await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper);
                        }
                    } catch (error) {
                        console.error('WebSocket数据写入错误:', error);
                        // 关闭连接而不是静默失败
                        closeSocketQuietly(serverSock);
                        if (remoteConnWrapper.socket) {
                            closeSocketQuietly(remoteConnWrapper.socket);
                        }
                        throw error; // 重新抛出以触发外层catch
                    }
                },
                
                // 🔧 修复：添加abort处理
                abort(reason) {
                    console.log('WebSocket写入流被中止:', reason);
                    closeSocketQuietly(serverSock);
                    if (remoteConnWrapper.socket) {
                        closeSocketQuietly(remoteConnWrapper.socket);
                    }
                }
            }));
        };

        // 启动管道处理但不等待，避免阻塞响应
        管道处理().catch((error) => {
            console.error('WebSocket管道处理错误:', error);
            // 错误已经在内部处理，这里只记录
        });

        return new Response(null, { status: 101, webSocket: clientSock });
        
    } catch (error) {
        // 🔧 修复：初始设置阶段的错误处理
        console.error('WebSocket初始化错误:', error);
        closeSocketQuietly(serverSock);
        closeSocketQuietly(clientSock);
        return new Response('WebSocket connection failed', { status: 500 });
    }
}

function 解析木马请求(buffer, passwordPlainText) {
    const sha224Password = sha224(passwordPlainText);
    if (buffer.byteLength < 56) return { hasError: true, message: "invalid data" };
    let crLfIndex = 56;
    if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) return { hasError: true, message: "invalid header format" };
    const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
    if (password !== sha224Password) return { hasError: true, message: "invalid password" };

    const socks5DataBuffer = buffer.slice(crLfIndex + 2);
    if (socks5DataBuffer.byteLength < 6) return { hasError: true, message: "invalid S5 request data" };

    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd !== 1) return { hasError: true, message: "unsupported command, only TCP is allowed" };

    const atype = view.getUint8(1);
    let addressLength = 0;
    let addressIndex = 2;
    let address = "";
    switch (atype) {
        case 1: // IPv4
            addressLength = 4;
            address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join(".");
            break;
        case 3: // Domain
            addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0];
            addressIndex += 1;
            address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            break;
        case 4: // IPv6
            addressLength = 16;
            const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
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
    const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);

    return {
        hasError: false,
        addressType: atype,
        port: portRemote,
        hostname: address,
        rawClientData: socks5DataBuffer.slice(portIndex + 4)
    };
}

function 解析魏烈思请求(chunk, token) {
    if (chunk.byteLength < 24) return { hasError: true, message: 'Invalid data' };
    const version = new Uint8Array(chunk.slice(0, 1));
    if (formatIdentifier(new Uint8Array(chunk.slice(1, 17))) !== token) return { hasError: true, message: 'Invalid uuid' };
    const optLen = new Uint8Array(chunk.slice(17, 18))[0];
    const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];
    let isUDP = false;
    if (cmd === 1) { } else if (cmd === 2) { isUDP = true; } else { return { hasError: true, message: 'Invalid command' }; }
    const portIdx = 19 + optLen;
    const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);
    let addrIdx = portIdx + 2, addrLen = 0, addrValIdx = addrIdx + 1, hostname = '';
    const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0];
    switch (addressType) {
        case 1:
            addrLen = 4;
            hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.');
            break;
        case 2:
            addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0];
            addrValIdx += 1;
            hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen));
            break;
        case 3:
            addrLen = 16;
            const ipv6 = [];
            const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen));
            for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
            hostname = ipv6.join(':');
            break;
        default:
            return { hasError: true, message: `Invalid address type: ${addressType}` };
    }
    if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
    return { hasError: false, addressType, port, hostname, isUDP, rawIndex: addrValIdx + addrLen, version };
}
/**
 * @name forwardataTCP
 * @description 转发TCP数据，添加连接超时控制和更好的错误处理
 */
async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper) {
    const 连接超时时间 = 10000; // 10秒连接超时
    const 数据传输超时 = 30000; // 30秒数据传输超时
    
    console.log(JSON.stringify({ 
        configJSON: { 
            目标地址: host, 
            目标端口: portNum, 
            反代IP: 反代IP, 
            代理类型: 启用SOCKS5反代, 
            全局代理: 启用SOCKS5全局反代, 
            代理账号: 我的SOCKS5账号 
        } 
    }));
    
    /**
     * @name connectWithTimeout
     * @description 带超时控制的TCP连接
     */
    async function connectWithTimeout(address, port, data) {
        return new Promise(async (resolve, reject) => {
            const timeoutId = setTimeout(() => {
                reject(new Error(`TCP连接超时: ${address}:${port} (${连接超时时间}ms)`));
            }, 连接超时时间);
            
            try {
                const remoteSock = connect({ hostname: address, port: port });
                
                // 🔧 修复：添加socket错误监听
                remoteSock.closed.catch(error => {
                    console.error(`TCP连接关闭错误: ${address}:${port}`, error);
                });
                
                const writer = remoteSock.writable.getWriter();
                await writer.write(data);
                writer.releaseLock();
                
                clearTimeout(timeoutId);
                console.log(`TCP连接成功: ${address}:${port}`);
                resolve(remoteSock);
                
            } catch (error) {
                clearTimeout(timeoutId);
                console.error(`TCP连接失败: ${address}:${port}`, error);
                reject(error);
            }
        });
    }
    
    /**
     * @name connecttoPry
     * @description 连接到代理服务器
     */
    async function connecttoPry() {
        let newSocket;
        try {
            if (启用SOCKS5反代 === 'socks5') {
                newSocket = await socks5Connect(host, portNum, rawData);
            } else if (启用SOCKS5反代 === 'http' || 启用SOCKS5反代 === 'https') {
                newSocket = await httpConnect(host, portNum, rawData);
            } else {
                try {
                    const [反代IP地址, 反代IP端口] = await 解析地址端口(反代IP);
                    newSocket = await connectWithTimeout(反代IP地址, 反代IP端口, rawData);
                } catch (proxyError) {
                    console.error('反代连接失败，尝试备用地址:', proxyError);
                    // 备用连接
                    newSocket = await connectWithTimeout(atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg=='), 1, rawData);
                }
            }
            
            remoteConnWrapper.socket = newSocket;
            
            // 🔧 修复：添加数据传输超时监控
            const dataTransferTimeout = setTimeout(() => {
                console.warn(`数据传输超时: ${host}:${portNum}`);
                closeSocketQuietly(newSocket);
            }, 数据传输超时);
            
            newSocket.closed.catch(() => { })
                .finally(() => {
                    clearTimeout(dataTransferTimeout);
                    closeSocketQuietly(ws);
                });
                
            connectStreams(newSocket, ws, respHeader, null);
            
        } catch (err) {
            console.error('代理连接失败:', err);
            throw err;
        }
    }

    // 🔧 修复：主连接逻辑也添加超时控制
    if (启用SOCKS5反代 && 启用SOCKS5全局反代) {
        try {
            await connecttoPry();
        } catch (err) {
            console.error('全局代理模式连接失败:', err);
            throw err;
        }
    } else {
        try {
            // 先尝试直连，带超时控制
            const initialSocket = await connectWithTimeout(host, portNum, rawData);
            remoteConnWrapper.socket = initialSocket;
            connectStreams(initialSocket, ws, respHeader, connecttoPry);
        } catch (err) {
            console.log(`直连失败，尝试代理连接: ${err.message}`);
            await connecttoPry();
        }
    }
}

async function forwardataudp(udpChunk, webSocket, respHeader) {
    try {
        const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
        let vlessHeader = respHeader;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WebSocket.OPEN) {
                    if (vlessHeader) {
                        const response = new Uint8Array(vlessHeader.length + chunk.byteLength);
                        response.set(vlessHeader, 0);
                        response.set(chunk, vlessHeader.length);
                        webSocket.send(response.buffer);
                        vlessHeader = null;
                    } else {
                        webSocket.send(chunk);
                    }
                }
            },
        }));
    } catch (error) {
        // console.error('UDP forward error:', error);
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
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
    let header = headerData, hasData = false;
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            async write(chunk, controller) {
                hasData = true;
                if (webSocket.readyState !== WebSocket.OPEN) controller.error('ws.readyState is not open');
                if (header) {
                    const response = new Uint8Array(header.length + chunk.byteLength);
                    response.set(header, 0);
                    response.set(chunk, header.length);
                    webSocket.send(response.buffer);
                    header = null;
                } else {
                    webSocket.send(chunk);
                }
            },
            abort() { },
        })
    ).catch((err) => {
        closeSocketQuietly(webSocket);
    });
    if (!hasData && retryFunc) {
        await retryFunc();
    }
}

function makeReadableStr(socket, earlyDataHeader) {
    let cancelled = false;
    return new ReadableStream({
        start(controller) {
            socket.addEventListener('message', (event) => {
                if (!cancelled) controller.enqueue(event.data);
            });
            socket.addEventListener('close', () => {
                if (!cancelled) {
                    closeSocketQuietly(socket);
                    controller.close();
                }
            });
            socket.addEventListener('error', (err) => controller.error(err));
            const { earlyData, error } = base64ToArray(earlyDataHeader);
            if (error) controller.error(error);
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() {
            cancelled = true;
            closeSocketQuietly(socket);
        }
    });
}

function isSpeedTestSite(hostname) {
    const speedTestDomains = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
    if (speedTestDomains.includes(hostname)) {
        return true;
    }

    for (const domain of speedTestDomains) {
        if (hostname.endsWith('.' + domain) || hostname === domain) {
            return true;
        }
    }
    return false;
}

function base64ToArray(b64Str) {
    if (!b64Str) return { error: null };
    try {
        const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return { earlyData: bytes.buffer, error: null };
    } catch (error) {
        return { error };
    }
}
////////////////////////////////SOCKS5/HTTP函数///////////////////////////////////////////////
async function socks5Connect(targetHost, targetPort, initialData) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const socket = connect({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
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

        await writer.write(initialData);
        writer.releaseLock(); reader.releaseLock();
        return socket;
    } catch (error) {
        try { writer.releaseLock(); } catch (e) { }
        try { reader.releaseLock(); } catch (e) { }
        try { socket.close(); } catch (e) { }
        throw error;
    }
}

async function httpConnect(targetHost, targetPort, initialData) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const socket = connect({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
    try {
        const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
        const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
        await writer.write(new TextEncoder().encode(request));

        let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
        while (headerEndIndex === -1 && bytesRead < 8192) {
            const { done, value } = await reader.read();
            if (done) throw new Error('Connection closed before receiving HTTP response');
            responseBuffer = new Uint8Array([...responseBuffer, ...value]);
            bytesRead = responseBuffer.length;
            const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
            if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
        }

        if (headerEndIndex === -1) throw new Error('Invalid HTTP response');
        const statusCode = parseInt(new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/)[1]);
        if (statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

        await writer.write(initialData);
        writer.releaseLock(); reader.releaseLock();
        return socket;
    } catch (error) {
        try { writer.releaseLock(); } catch (e) { }
        try { reader.releaseLock(); } catch (e) { }
        try { socket.close(); } catch (e) { }
        throw error;
    }
}
//////////////////////////////////////////////////功能性函数///////////////////////////////////////////////
function surge(content, url, config_JSON) {
    let 每行内容;
    if (content.includes('\r\n')) {
        每行内容 = content.split('\r\n');
    } else {
        每行内容 = content.split('\n');
    }

    let 输出内容 = "";
    for (let x of 每行内容) {
        if (x.includes('= tro' + 'jan,')) {
            const host = x.split("sni=")[1].split(",")[0];
            const 备改内容 = `sni=${host}, skip-cert-verify=${config_JSON.跳过证书验证}`;
            const 正确内容 = `sni=${host}, skip-cert-verify=${config_JSON.跳过证书验证}, ws=true, ws-path=${config_JSON.PATH}, ws-headers=Host:"${host}"`;
            输出内容 += x.replace(new RegExp(备改内容, 'g'), 正确内容).replace("[", "").replace("]", "") + '\n';
        } else {
            输出内容 += x + '\n';
        }
    }

    输出内容 = `#!MANAGED-CONFIG ${url} interval=${config_JSON.优选订阅生成.SUBUpdateTime * 60 * 60} strict=false` + 输出内容.substring(输出内容.indexOf('\n'));
    return 输出内容;
}
/**
 * @name 清理大对象
 * @description 清理配置对象中的临时数据，减少内存占用
 * @param {Object} config 配置对象
 * @returns {Object} 清理后的配置对象
 */
function 清理大对象(config) {
    if (!config || typeof config !== 'object') {
        return config;
    }
    
    // 创建清理后的副本，避免修改原对象
    const 清理后配置 = { ...config };
    
    // 移除可能的大数据字段或转换为轻量版本
    if (清理后配置.临时数据) {
        delete 清理后配置.临时数据;
    }
    
    if (清理后配置.调试信息) {
        delete 清理后配置.调试信息;
    }
    
    // 限制日志数组大小
    if (清理后配置.日志 && Array.isArray(清理后配置.日志)) {
        if (清理后配置.日志.length > 100) {
            清理后配置.日志 = 清理后配置.日志.slice(-100);
        }
    }
    
    // 清理嵌套大对象
    if (清理后配置.优选订阅生成 && 清理后配置.优选订阅生成.本地IP库) {
        const ip库 = 清理后配置.优选订阅生成.本地IP库;
        if (ip库.原始数据 && Array.isArray(ip库.原始数据) && ip库.原始数据.length > 1000) {
            ip库.原始数据 = ip库.原始数据.slice(0, 1000); // 只保留前1000条
        }
    }
    
    return 清理后配置;
}

/**
 * @name 流式响应大内容
 * @description 使用流式响应处理大内容，避免内存爆炸
 * @param {string} content 内容
 * @param {Object} headers 响应头
 * @returns {Response} 流式响应
 */
function 流式响应大内容(content, headers = {}) {
    return new Response(
        new ReadableStream({
            start(controller) {
                // 分批发送数据
                const 块大小 = 64 * 1024; // 64KB chunks
                let 位置 = 0;
                
                function push() {
                    if (位置 >= content.length) {
                        controller.close();
                        return;
                    }
                    
                    const 块 = content.slice(位置, 位置 + 块大小);
                    controller.enqueue(new TextEncoder().encode(块));
                    位置 += 块大小;
                    
                    // 使用微任务继续，避免阻塞
                    Promise.resolve().then(push);
                }
                
                push();
            },
            cancel() {
                console.log('流式响应被取消');
            }
        }),
        {
            headers: {
                'Content-Type': 'text/plain; charset=utf-8',
                ...headers
            }
        }
    );
}

/**
 * @name 优化订阅内容生成
 * @description 优化大订阅内容的内存使用
 */
async function 优化订阅内容生成(完整优选列表, 配置) {
    // 🔧 修复：使用增量处理避免大数组操作
    const 结果 = [];
    let 处理数量 = 0;
    const 最大处理数量 = 500; // 限制处理数量
    
    for (const 元素 of 完整优选列表) {
        if (处理数量 >= 最大处理数量) {
            console.log(`达到最大处理数量限制: ${最大处理数量}`);
            break;
        }
        
        // 原有的处理逻辑，但使用增量方式
        if (元素.toLowerCase().startsWith('https://')) {
            结果.push(元素);
        } else if (元素.toLowerCase().includes('://')) {
            结果.push(元素);
        } else {
            结果.push(元素);
        }
        
        处理数量++;
    }
    
    return 结果;
}

// 🔧 修复：在关键函数调用处添加内存优化
async function 读取config_JSON(env, host, userID, 重置配置 = false) {
    // ... 原有代码
    
    // 在返回前清理大对象
    const 优化后配置 = 清理大对象(config_JSON);
    return 优化后配置;
}

// 🔧 修复：在订阅生成处使用流式响应
async function 生成订阅响应(订阅内容, 响应头) {
    if (订阅内容.length > 1024 * 1024) { // 大于1MB使用流式
        console.log('使用流式响应处理大订阅内容');
        return 流式响应大内容(订阅内容, 响应头);
    } else {
        return new Response(订阅内容, { headers: 响应头 });
    }
}
/**
 * @name 请求日志记录
 * @description 记录请求日志到KV存储，优化性能和存储限制
 */
async function 请求日志记录(env, request, 访问IP, 请求类型 = "Get_SUB", config_JSON) {
    const KV容量限制 = 4; // MB
    const 最大日志条数 = 800; // 基于平均日志大小估算
    const 最小保留条数 = 100; // 确保不会清空所有日志
    
    try {
        // 统计和异常检测（保持不变）
        await 更新统计(env, 请求类型);
        const 异常特征 = await 检测异常访问(request, 访问IP, config_JSON);
        if (异常特征.length > 0 && config_JSON.TG.启用) {
            await sendMessage(config_JSON.TG.BotToken, config_JSON.TG.ChatID, {
                TYPE: '异常访问',
                IP: 访问IP,
                异常类型: 异常特征.join(','),
                URL: request.url,
                UA: request.headers.get('User-Agent') || 'Unknown',
                TIME: new Date().getTime()
            }, config_JSON);
        }

        const 当前时间 = new Date();
        const 日志内容 = { 
            TYPE: 请求类型, 
            IP: 访问IP, 
            ASN: `AS${request.cf.asn || '0'} ${request.cf.asOrganization || 'Unknown'}`, 
            CC: `${request.cf.country || 'N/A'} ${request.cf.city || 'N/A'}`, 
            URL: request.url, 
            UA: request.headers.get('User-Agent') || 'Unknown', 
            TIME: 当前时间.getTime() 
        };
        
        let 日志数组 = [];
        const 现有日志 = await env.KV.get('log.json');
        
        if (现有日志) {
            try {
                日志数组 = JSON.parse(现有日志);
                if (!Array.isArray(日志数组)) { 
                    日志数组 = [日志内容]; 
                } else if (请求类型 !== "Get_SUB") {
                    // 去重逻辑保持不变
                    const 三十分钟前时间戳 = 当前时间.getTime() - 30 * 60 * 1000;
                    if (日志数组.some(log => log.TYPE !== "Get_SUB" && log.IP === 访问IP && log.URL === request.url && log.UA === (request.headers.get('User-Agent') || 'Unknown') && log.TIME >= 三十分钟前时间戳)) {
                        return; // 重复日志，直接返回
                    }
                    日志数组.push(日志内容);
                } else {
                    日志数组.push(日志内容);
                }
                
                // 🔧 优化：使用条数限制替代频繁的JSON.stringify
                if (日志数组.length > 最大日志条数) {
                    console.log(`日志条数超限，从 ${日志数组.length} 条裁剪到 ${最大日志条数} 条`);
                    日志数组 = 日志数组.slice(-最大日志条数);
                }
                
                // 🔧 优化：只在必要时检查大小
                const 日志文本 = JSON.stringify(日志数组);
                if (日志文本.length > KV容量限制 * 1024 * 1024) {
                    console.log(`日志大小超限，进一步裁剪`);
                    日志数组 = 日志数组.slice(-最小保留条数);
                }
                
            } catch (e) { 
                日志数组 = [日志内容]; 
            }
        } else { 
            日志数组 = [日志内容]; 
        }
        
        // Telegram通知（保持不变）
        if (config_JSON && config_JSON.TG && config_JSON.TG.启用) {
            try {
                const TG_TXT = await env.KV.get('tg.json');
                const TG_JSON = JSON.parse(TG_TXT);
                await sendMessage(TG_JSON.BotToken, TG_JSON.ChatID, 日志内容, config_JSON);
            } catch (error) { 
                console.error(`读取tg.json出错: ${error.message}`); 
            }
        }
        
        await env.KV.put('log.json', JSON.stringify(日志数组));
        
    } catch (error) { 
        console.error(`日志记录失败: ${error.message}`); 
    }
}

/**
 * @name 更新统计
 * @description 记录每日访问统计数据
 */
async function 更新统计(env, 请求类型) {
    try {
        const 今日 = new Date().toISOString().split('T')[0];
        const 统计键 = `stats_${今日}`;
        
        let 今日统计 = await env.KV.get(统计键);
        今日统计 = 今日统计 ? JSON.parse(今日统计) : { 
            访问次数: 0, 
            订阅生成: 0, 
            管理登录: 0,
            首次访问时间: new Date().toISOString()
        };
        
        switch(请求类型) {
            case 'Get_SUB': 今日统计.订阅生成++; break;
            case 'Admin_Login': 今日统计.管理登录++; break;
            default: 今日统计.访问次数++;
        }
        
        await env.KV.put(统计键, JSON.stringify(今日统计));
    } catch (error) {
        console.error('统计更新失败:', error);
    }
}

/**
 * @name 检测异常访问
 * @description 检测可疑访问行为
 */
async function 检测异常访问(请求, 访问IP, config_JSON) {
    const 异常特征 = [];
    
    try {
        const UA = 请求.headers.get('User-Agent') || '';
        const URL = 请求.url;
        
        // 检测爬虫
        if (UA.toLowerCase().includes('bot') || UA.includes('crawler')) {
            异常特征.push('疑似爬虫');
        }
        
        // 检测可疑路径
        const 可疑路径 = ['/wp-admin', '/phpmyadmin', '/.env', '/config', '/adminer'];
        if (可疑路径.some(路径 => URL.includes(路径))) {
            异常特征.push('可疑路径访问');
        }
        
        // 检测异常User-Agent
        if (!UA || UA === 'null' || UA.length < 10) {
            异常特征.push('异常UA');
        }
        
    } catch (error) {
        console.error('异常检测失败:', error);
    }
    
    return 异常特征;
}
// 这里就是现有的 sendMessage 函数
async function sendMessage(BotToken, ChatID, 日志内容, config_JSON) {
    if (!BotToken || !ChatID) return;

    try {
        const 请求时间 = new Date(日志内容.TIME).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
        const 请求URL = new URL(日志内容.URL);
        const msg = `<b>#${config_JSON.优选订阅生成.SUBNAME} 日志通知</b>\n\n` +
            `📌 <b>类型：</b>#${日志内容.TYPE}\n` +
            `🌐 <b>IP：</b><code>${日志内容.IP}</code>\n` +
            `📍 <b>位置：</b>${日志内容.CC}\n` +
            `🏢 <b>ASN：</b>${日志内容.ASN}\n` +
            `🔗 <b>域名：</b><code>${请求URL.host}</code>\n` +
            `🔍 <b>路径：</b><code>${请求URL.pathname + 请求URL.search}</code>\n` +
            `🤖 <b>UA：</b><code>${日志内容.UA}</code>\n` +
            `📅 <b>时间：</b>${请求时间}\n` +
            `${config_JSON.CF.Usage.success ? `📊 <b>请求用量：</b>${config_JSON.CF.Usage.total}/100000 <b>${((config_JSON.CF.Usage.total / 100000) * 100).toFixed(2)}%</b>\n` : ''}`;

        const url = `https://api.telegram.org/bot${BotToken}/sendMessage?chat_id=${ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
        return fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'Accept-Encoding': 'gzip, deflate, br',
                'User-Agent': 日志内容.UA || 'Unknown',
            }
        });
    } catch (error) { console.error('Error sending message:', error) }
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

function 随机路径() {
    const 常用路径目录 = ["#","about","account","acg","act","activity","ad","admin","ads","ajax","album","albums","anime","api","app","apps","archive","archives","article","articles","ask","auth","avatar","bbs","bd","blog","blogs","book","books","bt","buy","cart","category","categories","cb","channel","channels","chat","china","city","class","classify","clip","clips","club","cn","code","collect","collection","comic","comics","community","company","config","contact","content","course","courses","cp","data","detail","details","dh","directory","discount","discuss","dl","dload","doc","docs","document","documents","doujin","download","downloads","drama","edu","en","ep","episode","episodes","event","events","f","faq","favorite","favourites","favs","feedback","file","files","film","films","forum","forums","friend","friends","game","games","gif","go","go.html","go.php","group","groups","help","home","hot","htm","html","image","images","img","index","info","intro","item","items","ja","jp","jump","jump.html","jump.php","jumping","knowledge","lang","lesson","lessons","lib","library","link","links","list","live","lives","login","logout","m","mag","magnet","mall","manhua","map","member","members","message","messages","mobile","movie","movies","music","my","new","news","note","novel","novels","online","order","out","out.html","out.php","outbound","p","page","pages","pay","payment","pdf","photo","photos","pic","pics","picture","pictures","play","player","playlist","post","posts","product","products","program","programs","project","qa","question","rank","ranking","read","readme","redirect","redirect.html","redirect.php","reg","register","res","resource","retrieve","sale","search","season","seasons","section","seller","series","service","services","setting","settings","share","shop","show","shows","site","soft","sort","source","special","star","stars","static","stock","store","stream","streaming","streams","student","study","tag","tags","task","teacher","team","tech","temp","test","thread","tool","tools","topic","topics","torrent","trade","travel","tv","txt","type","u","upload","uploads","url","urls","user","users","v","version","video","videos","view","vip","vod","watch","web","wenku","wiki","work","www","zh","zh-cn","zh-tw","zip"];
    const 随机数 = Math.floor(Math.random() * 4 + 1);
    const 随机路径 = 常用路径目录.sort(() => 0.5 - Math.random()).slice(0, 随机数).join('/');
    return `/${随机路径}`;
}

/**
 * @name 读取config_JSON
 * @description 读取和初始化配置文件，添加完整的配置验证和错误恢复
 */
async function 读取config_JSON(env, host, userID, 重置配置 = false) {
    const 初始化开始时间 = performance.now();
    
    /**
     * @name 验证配置完整性
     * @description 验证配置文件的必需字段和格式
     */
    function 验证配置完整性(config) {
        const 必需字段 = [
            'HOST', 'UUID', '协议类型', '传输协议', 
            '优选订阅生成', '订阅转换配置', '反代', 'TG', 'CF'
        ];
        
        const 缺失字段 = 必需字段.filter(field => !config[field]);
        if (缺失字段.length > 0) {
            throw new Error(`配置缺少必需字段: ${缺失字段.join(', ')}`);
        }
        
        // 验证UUID格式
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        if (!uuidRegex.test(config.UUID)) {
            throw new Error(`无效的UUID格式: ${config.UUID}`);
        }
        
        // 验证协议类型
        const 有效协议 = ["vless", "vmess", "trojan"];
        if (!有效协议.includes(config.协议类型)) {
            throw new Error(`无效的协议类型: ${config.协议类型}`);
        }
        
        // 验证传输协议
        const 有效传输协议 = ["ws", "tcp", "kcp", "h2"];
        if (!有效传输协议.includes(config.传输协议)) {
            throw new Error(`无效的传输协议: ${config.传输协议}`);
        }
        
        console.log('配置验证通过');
        return true;
    }
    
    /**
     * @name 修复损坏配置
     * @description 尝试修复部分损坏的配置
     */
    function 修复损坏配置(损坏配置, 默认配置) {
        const 修复后配置 = { ...默认配置, ...损坏配置 };
        
        // 确保嵌套对象存在
        if (!修复后配置.优选订阅生成 || typeof 修复后配置.优选订阅生成 !== 'object') {
            修复后配置.优选订阅生成 = { ...默认配置.优选订阅生成 };
        }
        
        if (!修复后配置.订阅转换配置 || typeof 修复后配置.订阅转换配置 !== 'object') {
            修复后配置.订阅转换配置 = { ...默认配置.订阅转换配置 };
        }
        
        if (!修复后配置.反代 || typeof 修复后配置.反代 !== 'object') {
            修复后配置.反代 = { ...默认配置.反代 };
        }
        
        // 修复常见字段类型
        if (typeof 修复后配置.跳过证书验证 !== 'boolean') {
            修复后配置.跳过证书验证 = Boolean(修复后配置.跳过证书验证);
        }
        
        if (typeof 修复后配置.启用0RTT !== 'boolean') {
            修复后配置.启用0RTT = Boolean(修复后配置.启用0RTT);
        }
        
        return 修复后配置;
    }

    const 默认配置JSON = {
        TIME: new Date().toISOString(),
        HOST: host,
        UUID: userID,
        协议类型: "vless",
        传输协议: "ws",
        跳过证书验证: true,
        启用0RTT: true,
        TLS分片: null,
        优选订阅生成: {
            local: true,
            本地IP库: {
                随机IP: true,
                随机数量: 16,
                指定端口: -1,
            },
            SUB: null,
            SUBNAME: "edgetunnel",
            SUBUpdateTime: 6,
            TOKEN: await MD5MD5(host + userID),
        },
        订阅转换配置: {
            SUBAPI: "https://SUBAPI.cmliussss.net",
            SUBCONFIG: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiMode.ini",
            SUBEMOJI: false,
        },
        反代: {
            PROXYIP: "auto",
            SOCKS5: {
                启用: 启用SOCKS5反代,
                全局: 启用SOCKS5全局反代,
                账号: 我的SOCKS5账号,
                白名单: SOCKS5白名单,
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
            Usage: {
                success: false,
                pages: 0,
                workers: 0,
                total: 0,
            },
        }
    };

    try {
        let configJSON = await env.KV.get('config.json');
        
        if (!configJSON || 重置配置 == true) {
            console.log('初始化或重置配置');
            await env.KV.put('config.json', JSON.stringify(默认配置JSON, null, 2));
            config_JSON = 默认配置JSON;
        } else {
            try {
                config_JSON = JSON.parse(configJSON);
                console.log('成功解析配置JSON');
                
                // 🔧 修复：验证配置完整性
                try {
                    验证配置完整性(config_JSON);
                    console.log('配置完整性验证通过');
                } catch (验证错误) {
                    console.warn('配置验证失败，尝试修复:', 验证错误.message);
                    config_JSON = 修复损坏配置(config_JSON, 默认配置JSON);
                    
                    // 保存修复后的配置
                    await env.KV.put('config.json', JSON.stringify(config_JSON, null, 2));
                    console.log('已修复并保存损坏的配置');
                }
                
            } catch (解析错误) {
                console.error('配置JSON解析失败，使用默认配置:', 解析错误.message);
                config_JSON = 默认配置JSON;
                // 重新保存正确的配置
                await env.KV.put('config.json', JSON.stringify(默认配置JSON, null, 2));
            }
        }
        
        // 🔧 修复：确保关键字段总是最新的
        config_JSON.HOST = host;
        config_JSON.UUID = userID;
        config_JSON.TIME = new Date().toISOString();
        
        // 重新生成动态字段
        config_JSON.PATH = config_JSON.反代.SOCKS5.启用 ? 
            ('/' + config_JSON.反代.SOCKS5.启用 + (config_JSON.反代.SOCKS5.全局 ? '://' : '=') + config_JSON.反代.SOCKS5.账号) : 
            (config_JSON.反代.PROXYIP === 'auto' ? '/' : `/proxyip=${config_JSON.反代.PROXYIP}`);
            
        const TLS分片参数 = config_JSON.TLS分片 == 'Shadowrocket' ? 
            `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : 
            config_JSON.TLS分片 == 'Happ' ? 
            `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
            
        config_JSON.LINK = `${config_JSON.协议类型}://${userID}@${host}:443?security=tls&type=${config_JSON.传输协议}&host=${host}&sni=${host}&path=${encodeURIComponent(config_JSON.启用0RTT ? config_JSON.PATH + '?ed=2560' : config_JSON.PATH) + TLS分片参数}&encryption=none${config_JSON.跳过证书验证 ? '&allowInsecure=1' : ''}#${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`;
        config_JSON.优选订阅生成.TOKEN = await MD5MD5(host + userID);

        // ... 其余TG和CF配置处理保持不变

        config_JSON.加载时间 = (performance.now() - 初始化开始时间).toFixed(2) + 'ms';
        
        console.log('配置加载完成:', {
            主机: config_JSON.HOST,
            UUID: config_JSON.UUID.substring(0, 8) + '...',
            加载时间: config_JSON.加载时间
        });
        
        return config_JSON;
        
    } catch (error) {
        console.error(`读取config_JSON严重错误: ${error.message}`);
        // 返回一个安全的默认配置
        return 默认配置JSON;
    }
}

async function 生成随机IP(request, count = 16, 指定端口 = -1) {
    const asnMap = { '9808': 'cmcc', '4837': 'cu', '4134': 'ct' }, asn = request.cf.asn;
    const cidr_url = asnMap[asn] ? `https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR/${asnMap[asn]}.txt` : 'https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt';
    const cfname = { '9808': 'CF移动优选', '4837': 'CF联通优选', '4134': 'CF电信优选' }[asn] || 'CF官方优选';
    const cfport = [443, 2053, 2083, 2087, 2096, 8443];
    let cidrList = [];
    try { const res = await fetch(cidr_url); cidrList = res.ok ? await 整理成数组(await res.text()) : ['104.16.0.0/13']; } catch { cidrList = ['104.16.0.0/13']; }

    const generateRandomIPFromCIDR = (cidr) => {
        const [baseIP, prefixLength] = cidr.split('/'), prefix = parseInt(prefixLength), hostBits = 32 - prefix;
        const ipInt = baseIP.split('.').reduce((a, p, i) => a | (parseInt(p) << (24 - i * 8)), 0);
        const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
        const mask = (0xFFFFFFFF << hostBits) >>> 0, randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;
        return [(randomIP >>> 24) & 0xFF, (randomIP >>> 16) & 0xFF, (randomIP >>> 8) & 0xFF, randomIP & 0xFF].join('.');
    };

    const randomIPs = Array.from({ length: count }, () => {
        const ip = generateRandomIPFromCIDR(cidrList[Math.floor(Math.random() * cidrList.length)]);
        return `${ip}:${指定端口 === -1 ? cfport[Math.floor(Math.random() * cfport.length)] : 指定端口}#${cfname}`;
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

async function 请求优选API(urls, 默认端口 = '443', 超时时间 = 3000) {
    if (!urls?.length) return [];
    const results = new Set();
    await Promise.allSettled(urls.map(async (url) => {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 超时时间);
            const response = await fetch(url, { signal: controller.signal });
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
            const lines = text.trim().split('\n').map(l => l.trim()).filter(l => l);
            const isCSV = lines.length > 1 && lines[0].includes(',');
            const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
            if (!isCSV) {
                lines.forEach(line => {
                    const hashIndex = line.indexOf('#');
                    const [hostPart, remark] = hashIndex > -1 ? [line.substring(0, hashIndex), line.substring(hashIndex)] : [line, ''];
                    let hasPort = false;
                    if (hostPart.startsWith('[')) {
                        hasPort = /\]:(\d+)$/.test(hostPart);
                    } else {
                        const colonIndex = hostPart.lastIndexOf(':');
                        hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
                    }
                    const port = new URL(url).searchParams.get('port') || 默认端口;
                    results.add(hasPort ? line : `${hostPart}:${port}${remark}`);
                });
            } else {
                const headers = lines[0].split(',').map(h => h.trim());
                const dataLines = lines.slice(1);
                if (headers.includes('IP地址') && headers.includes('端口') && headers.includes('数据中心')) {
                    const ipIdx = headers.indexOf('IP地址'), portIdx = headers.indexOf('端口');
                    const remarkIdx = headers.indexOf('国家') > -1 ? headers.indexOf('国家') :
                        headers.indexOf('城市') > -1 ? headers.indexOf('城市') : headers.indexOf('数据中心');
                    dataLines.forEach(line => {
                        const cols = line.split(',').map(c => c.trim());
                        const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
                        results.add(`${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`);
                    });
                } else if (headers.some(h => h.includes('IP')) && headers.some(h => h.includes('延迟')) && headers.some(h => h.includes('下载速度'))) {
                    const ipIdx = headers.findIndex(h => h.includes('IP'));
                    const delayIdx = headers.findIndex(h => h.includes('延迟'));
                    const speedIdx = headers.findIndex(h => h.includes('下载速度'));
                    const port = new URL(url).searchParams.get('port') || 默认端口;
                    dataLines.forEach(line => {
                        const cols = line.split(',').map(c => c.trim());
                        const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
                        results.add(`${wrappedIP}:${port}#CF优选 ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`);
                    });
                }
            }
        } catch (e) { }
    }));
    return Array.from(results);
}

async function 反代参数获取(request) {
    const url = new URL(request.url);
    const { pathname, searchParams } = url;
    const pathLower = pathname.toLowerCase();

    // 初始化
    我的SOCKS5账号 = searchParams.get('socks5') || searchParams.get('http') || null;
    启用SOCKS5全局反代 = searchParams.has('globalproxy') || false;

    // 统一处理反代IP参数 (优先级最高,使用正则一次匹配)
    const proxyMatch = pathLower.match(/\/(proxyip[.=]|pyip=|ip=)(.+)/);
    if (searchParams.has('proxyip')) {
        const 路参IP = searchParams.get('proxyip');
        反代IP = 路参IP.includes(',') ? 路参IP.split(',')[Math.floor(Math.random() * 路参IP.split(',').length)] : 路参IP;
        return;
    } else if (proxyMatch) {
        const 路参IP = proxyMatch[1] === 'proxyip.' ? `proxyip.${proxyMatch[2]}` : proxyMatch[2];
        反代IP = 路参IP.includes(',') ? 路参IP.split(',')[Math.floor(Math.random() * 路参IP.split(',').length)] : 路参IP;
        return;
    }

    // 处理SOCKS5/HTTP代理参数
    let socksMatch;
    if ((socksMatch = pathname.match(/\/(socks5?|http):\/?\/?(.+)/i))) {
        // 格式: /socks5://... 或 /http://...
        启用SOCKS5反代 = socksMatch[1].toLowerCase() === 'http' ? 'http' : 'socks5';
        我的SOCKS5账号 = socksMatch[2].split('#')[0];
        启用SOCKS5全局反代 = true;

        // 处理Base64编码的用户名密码
        if (我的SOCKS5账号.includes('@')) {
            const atIndex = 我的SOCKS5账号.lastIndexOf('@');
            let userPassword = 我的SOCKS5账号.substring(0, atIndex).replaceAll('%3D', '=');
            if (/^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i.test(userPassword) && !userPassword.includes(':')) {
                userPassword = atob(userPassword);
            }
            我的SOCKS5账号 = `${userPassword}@${我的SOCKS5账号.substring(atIndex + 1)}`;
        }
    } else if ((socksMatch = pathname.match(/\/(g?s5|socks5|g?http)=(.+)/i))) {
        // 格式: /socks5=... 或 /s5=... 或 /gs5=... 或 /http=... 或 /ghttp=...
        const type = socksMatch[1].toLowerCase();
        我的SOCKS5账号 = socksMatch[2];
        启用SOCKS5反代 = type.includes('http') ? 'http' : 'socks5';
        启用SOCKS5全局反代 = type.startsWith('g') || 启用SOCKS5全局反代; // gs5 或 ghttp 开头启用全局
    }

    // 解析SOCKS5地址
    if (我的SOCKS5账号) {
        try {
            parsedSocks5Address = await 获取SOCKS5账号(我的SOCKS5账号);
            启用SOCKS5反代 = searchParams.get('http') ? 'http' : 启用SOCKS5反代;
        } catch (err) {
            console.error('解析SOCKS5地址失败:', err.message);
            启用SOCKS5反代 = null;
        }
    } else 启用SOCKS5反代 = null;
}

async function 获取SOCKS5账号(address) {
    if (address.includes('@')) {
        const lastAtIndex = address.lastIndexOf('@');
        let userPassword = address.substring(0, lastAtIndex).replaceAll('%3D', '=');
        const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
        if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
        address = `${userPassword}@${address.substring(lastAtIndex + 1)}`;
    }
    const atIndex = address.lastIndexOf("@");
    const [hostPart, authPart] = atIndex === -1 ? [address, undefined] : [address.substring(atIndex + 1), address.substring(0, atIndex)];

    // 解析认证
    let username, password;
    if (authPart) {
        [username, password] = authPart.split(":");
        if (!password) throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
    }

    // 解析主机端口
    let hostname, port;
    if (hostPart.includes("]:")) { // IPv6带端口
        [hostname, port] = [hostPart.split("]:")[0] + "]", Number(hostPart.split("]:")[1].replace(/[^\d]/g, ''))];
    } else if (hostPart.startsWith("[")) { // IPv6无端口
        [hostname, port] = [hostPart, 80];
    } else { // IPv4/域名
        const parts = hostPart.split(":");
        [hostname, port] = parts.length === 2 ? [parts[0], Number(parts[1].replace(/[^\d]/g, ''))] : [hostPart, 80];
    }

    if (isNaN(port)) throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
    if (hostname.includes(":") && !/^\[.*\]$/.test(hostname)) throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');

    return { username, password, hostname, port };
}

async function getCloudflareUsage(Email, GlobalAPIKey, AccountID, APIToken) {
    const API = "https://api.cloudflare.com/client/v4";
    const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
    const cfg = { "Content-Type": "application/json" };

    try {
        if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, pages: 0, workers: 0, total: 0 };

        if (!AccountID) {
            const r = await fetch(`${API}/accounts`, {
                method: "GET",
                headers: { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey }
            });
            if (!r.ok) throw new Error(`账户获取失败: ${r.status}`);
            const d = await r.json();
            if (!d?.result?.length) throw new Error("未找到账户");
            const idx = d.result.findIndex(a => a.name?.toLowerCase().startsWith(Email.toLowerCase()));
            AccountID = d.result[idx >= 0 ? idx : 0]?.id;
        }

        const now = new Date();
        now.setUTCHours(0, 0, 0, 0);
        const hdr = APIToken ? { ...cfg, "Authorization": `Bearer ${APIToken}` } : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };

        const res = await fetch(`${API}/graphql`, {
            method: "POST",
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

        if (!res.ok) throw new Error(`查询失败: ${res.status}`);
        const result = await res.json();
        if (result.errors?.length) throw new Error(result.errors[0].message);

        const acc = result?.data?.viewer?.accounts?.[0];
        if (!acc) throw new Error("未找到账户数据");

        const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
        const workers = sum(acc.workersInvocationsAdaptive);
        const total = pages + workers;
        console.log(`统计结果 - Pages: ${pages}, Workers: ${workers}, 总计: ${total}`);
        return { success: true, pages, workers, total };

    } catch (error) {
        console.error('获取使用量错误:', error.message);
        return { success: false, pages: 0, workers: 0, total: 0 };
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

async function 解析地址端口(proxyIP) {
    proxyIP = proxyIP.toLowerCase();
    if (proxyIP.includes('.william')) {
        const williamResult = await (async function 解析William域名(william) {
            try {
                const response = await fetch(`https://1.1.1.1/dns-query?name=${william}&type=TXT`, { headers: { 'Accept': 'application/dns-json' } });
                if (!response.ok) return null;
                const data = await response.json();
                const txtRecords = (data.Answer || []).filter(record => record.type === 16).map(record => record.data);
                if (txtRecords.length === 0) return null;
                let txtData = txtRecords[0];
                if (txtData.startsWith('"') && txtData.endsWith('"')) txtData = txtData.slice(1, -1);
                const prefixes = txtData.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
                if (prefixes.length === 0) return null;
                return prefixes[Math.floor(Math.random() * prefixes.length)];
            } catch (error) {
                console.error('解析ProxyIP失败:', error);
                return null;
            }
        })(proxyIP);
        proxyIP = williamResult || proxyIP;
    }
    let 地址 = proxyIP, 端口 = 443;
    if (proxyIP.includes('.tp')) {
        const tpMatch = proxyIP.match(/\.tp(\d+)/);
        if (tpMatch) 端口 = parseInt(tpMatch[1], 10);
        return [地址, 端口];
    }
    if (proxyIP.includes(']:')) {
        const parts = proxyIP.split(']:');
        地址 = parts[0] + ']';
        端口 = parseInt(parts[1], 10) || 端口;
    } else if (proxyIP.includes(':') && !proxyIP.startsWith('[')) {
        const colonIndex = proxyIP.lastIndexOf(':');
        地址 = proxyIP.slice(0, colonIndex);
        端口 = parseInt(proxyIP.slice(colonIndex + 1), 10) || 端口;
    }
    return [地址, 端口];
}

async function SOCKS5可用性验证(代理协议 = 'socks5', 代理参数) {
    const startTime = Date.now();
    try { parsedSocks5Address = await 获取SOCKS5账号(代理参数); } catch (err) { return { success: false, error: err.message, proxy: 代理协议 + "://" + 代理参数, responseTime: Date.now() - startTime }; }
    const { username, password, hostname, port } = parsedSocks5Address;
    const 完整代理参数 = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
    try {
        const initialData = new Uint8Array(0);
        const tcpSocket = 代理协议 == 'socks5' ? await socks5Connect('check.socks5.090227.xyz', 80, initialData) : await httpConnect('check.socks5.090227.xyz', 80, initialData);
        if (!tcpSocket) return { success: false, error: '无法连接到代理服务器', proxy: 代理协议 + "://" + 完整代理参数, responseTime: Date.now() - startTime };
        try {
            const writer = tcpSocket.writable.getWriter(), encoder = new TextEncoder();
            await writer.write(encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: check.socks5.090227.xyz\r\nConnection: close\r\n\r\n`));
            writer.releaseLock();
            const reader = tcpSocket.readable.getReader(), decoder = new TextDecoder();
            let response = '';
            try { while (true) { const { done, value } = await reader.read(); if (done) break; response += decoder.decode(value, { stream: true }); } } finally { reader.releaseLock(); }
            await tcpSocket.close();
            return { success: true, proxy: 代理协议 + "://" + 完整代理参数, ip: response.match(/ip=(.*)/)[1], loc: response.match(/loc=(.*)/)[1], responseTime: Date.now() - startTime };
        } catch (error) {
            try { await tcpSocket.close(); } catch (e) { console.log('关闭连接时出错:', e); }
            return { success: false, error: error.message, proxy: 代理协议 + "://" + 完整代理参数, responseTime: Date.now() - startTime };
        }
    } catch (error) { return { success: false, error: error.message, proxy: 代理协议 + "://" + 完整代理参数, responseTime: Date.now() - startTime }; }
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
/////////////////////////////////////////////////////// Telegram Bot 权限管理系统 ///////////////////////////////////////////////

/**
 * @name 用户权限管理系统
 * @description 提供多级用户权限控制，支持管理员和普通用户的不同功能访问
 */

/**
 * @name 初始化管理员用户
 * @description 自动初始化第一个用户为管理员，后续用户为普通用户
 * @param {Object} env - 环境变量
 * @param {string} chatId - 用户聊天ID
 * @param {string} username - 用户名
 * @returns {Object} 更新后的用户列表
 */
async function initAdminUser(env, chatId, username) {
    try {
        const users = await getUsers(env);
        const userKey = chatId.toString();
        
        // 如果用户不存在，创建新用户
        if (!users[userKey]) {
            // 判断是否是第一个用户（自动成为管理员）
            const isFirstUser = Object.keys(users).length === 0;
            const permission = isFirstUser ? 'admin' : 'user';
            
            users[userKey] = {
                username: username || 'Unknown',
                permission: permission,
                joinTime: new Date().toISOString(),
                lastActive: new Date().toISOString(),
                isFirstAdmin: isFirstUser
            };
            
            await saveUsers(env, users);
            console.log(`✅ ${isFirstUser ? '初始化管理员' : '添加新用户'}: ${username} (${chatId}) - 权限: ${permission}`);
        } else {
            // 更新最后活跃时间和用户名（如果变化）
            users[userKey].lastActive = new Date().toISOString();
            if (username && users[userKey].username !== username) {
                users[userKey].username = username;
            }
            await saveUsers(env, users);
        }
        
        return users;
    } catch (error) {
        console.error('初始化用户失败:', error);
        return {};
    }
}

/**
 * @name 获取所有用户
 * @description 从 KV 存储中获取用户列表，增强错误处理和数据结构验证
 * @param {Object} env - 环境变量
 * @returns {Object} 用户列表对象
 */
async function getUsers(env) {
    // 🔧 修复：添加参数验证
    if (!env || !env.KV) {
        console.error('获取用户失败: env或env.KV参数无效');
        return {};
    }
    
    try {
        const usersText = await env.KV.get('telegram_users');
        
        if (!usersText) {
            console.log('用户列表为空，返回默认空对象');
            return {};
        }
        
        // 🔧 修复:验证JSON格式和数据结构
        let users;
        try {
            users = JSON.parse(usersText);
        } catch (parseError) {
            console.error('用户列表JSON解析失败:', parseError.message);
            // 尝试备份恢复
            await 备份损坏的用户数据(env, usersText);
            return {};
        }
        
        // 🔧 修复：验证数据结构完整性
        if (typeof users !== 'object' || users === null) {
            console.error('用户列表数据结构无效，期望对象但得到:', typeof users);
            return {};
        }
        
        // 验证每个用户对象的必需字段
        let 有效用户数 = 0;
        let 无效用户数 = 0;
        
        for (const [chatId, user] of Object.entries(users)) {
            if (!user || typeof user !== 'object') {
                console.warn(`无效用户数据被移除: ${chatId}`);
                delete users[chatId];
                无效用户数++;
                continue;
            }
            
            // 验证必需字段
            const 必需字段 = ['username', 'permission', 'joinTime'];
            const 缺失字段 = 必需字段.filter(field => !user[field]);
            
            if (缺失字段.length > 0) {
                console.warn(`用户 ${chatId} 缺少字段被修复: ${缺失字段.join(', ')}`);
                // 尝试修复缺失字段
                if (!user.username) user.username = 'Unknown';
                if (!user.permission) user.permission = 'user';
                if (!user.joinTime) user.joinTime = new Date().toISOString();
            }
            
            // 验证权限字段有效性
            const 有效权限 = ['banned', 'user', 'admin'];
            if (!有效权限.includes(user.permission)) {
                console.warn(`用户 ${chatId} 无效权限被重置: ${user.permission} -> user`);
                user.permission = 'user';
            }
            
            有效用户数++;
        }
        
        // 如果有无效数据，保存修复后的版本
        if (无效用户数 > 0) {
            console.log(`用户数据修复: 移除 ${无效用户数} 个无效用户，保留 ${有效用户数} 个有效用户`);
            await env.KV.put('telegram_users', JSON.stringify(users));
        }
        
        console.log(`成功获取用户列表: ${有效用户数} 个用户`);
        return users;
        
    } catch (error) {
        console.error('获取用户列表系统错误:', {
            error: error.message,
            stack: error.stack,
            timestamp: new Date().toISOString()
        });
        return {}; // 确保总是返回可用的对象
    }
}

/**
 * @name 备份损坏的用户数据
 * @description 备份损坏的用户数据以便恢复
 */
async function 备份损坏的用户数据(env, 损坏数据) {
    try {
        const 备份时间戳 = new Date().toISOString().replace(/[:.]/g, '-');
        const 备份键 = `backup_corrupted_users_${备份时间戳}`;
        await env.KV.put(备份键, 损坏数据);
        console.log(`已备份损坏的用户数据到: ${备份键}`);
    } catch (backupError) {
        console.error('备份损坏用户数据失败:', backupError);
    }
}
/**
 * @name 获取用户信息
 * @description 根据chatId获取用户信息
 * @param {Object} env - 环境变量
 * @param {string} chatId - 用户聊天ID
 * @returns {Object|null} 用户信息对象
 */
async function getUserInfo(env, chatId) {
    try {
        const users = await getUsers(env);
        return users[chatId.toString()] || null;
    } catch (error) {
        console.error('获取用户信息失败:', error);
        return null;
    }
}
/**
 * @name 保存用户数据
 * @description 将用户数据保存到 KV 存储
 * @param {Object} env - 环境变量
 * @param {Object} users - 用户数据对象
 */
async function saveUsers(env, users) {
    try {
        await env.KV.put('telegram_users', JSON.stringify(users));
    } catch (error) {
        console.error('保存用户数据失败:', error);
    }
}
/**
 * @name 处理添加用户命令
 * @description 管理员添加新用户
 * @param {string} text - 命令文本
 * @param {string} chatId - 发起者聊天ID
 * @param {Object} fromUser - 发起者用户信息
 * @param {Object} tgConfig - Telegram配置
 * @param {Object} env - 环境变量
 */
async function handleAddUserCommand(text, chatId, fromUser, tgConfig, env) {
    // 检查管理员权限
    if (!await checkUserPermission(env, chatId, 'admin')) {
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            '❌ 此命令仅管理员可用'
        );
        return;
    }

    const parts = text.split(' ');
    if (parts.length < 2) {
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            '❌ 用法: /adduser @用户名\n\n' +
            '💡 用户需要先与机器人对话一次才能被添加'
        );
        return;
    }

    const targetUsername = parts[1].replace('@', '');
    const users = await getUsers(env);
    
    // 查找用户（用户需要先与机器人对话过）
    const targetUser = Object.entries(users).find(([id, user]) => 
        user.username === targetUsername
    );
    
    if (!targetUser) {
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            `❌ 未找到用户: @${targetUsername}\n\n` +
            `💡 请确保用户已经与机器人对话过`
        );
        return;
    }

    const [targetChatId, userData] = targetUser;
    
    // 更新用户权限
    users[targetChatId].permission = 'user';
    users[targetChatId].addedBy = fromUser.username;
    users[targetChatId].addedTime = new Date().toISOString();
    
    await saveUsers(env, users);
    
    // 通知目标用户
    await sendTelegramMessage(tgConfig.BotToken, targetChatId, 
        `🎉 您已被管理员 @${fromUser.username} 授权使用此机器人\n\n` +
        `您现在可以使用所有用户命令了！\n` +
        `输入 /help 查看可用命令`
    );
    
    await sendTelegramMessage(tgConfig.BotToken, chatId, 
        `✅ 已授权用户: @${targetUsername}`
    );
}
/**
 * @name 检查用户权限
 * @description 验证用户是否具有所需权限，添加完整的参数验证和错误处理
 * @param {Object} env - 环境变量
 * @param {string} chatId - 用户聊天ID
 * @param {string} requiredPermission - 所需权限级别
 * @returns {boolean} 是否具有权限
 */
async function checkUserPermission(env, chatId, requiredPermission = 'user') {
    // 🔧 修复：添加参数验证
    if (!env) {
        console.error('权限检查错误: env参数为空');
        return false;
    }
    
    if (!chatId || typeof chatId !== 'string' && typeof chatId !== 'number') {
        console.error('权限检查错误: 无效的chatId参数', chatId);
        return false;
    }
    
    // 🔧 修复：验证权限参数的有效性
    const validPermissions = ['banned', 'user', 'admin'];
    if (!validPermissions.includes(requiredPermission)) {
        console.error('权限检查错误: 无效的权限级别', requiredPermission);
        return false; // 无效权限要求直接返回false
    }
    
    try {
        const users = await getUsers(env);
        const userKey = chatId.toString();
        const user = users[userKey];
        
        if (!user) {
            console.log(`权限检查: 用户 ${userKey} 不存在`);
            return false;
        }
        
        // 🔧 修复：验证用户权限字段的有效性
        if (!user.permission || !validPermissions.includes(user.permission)) {
            console.error(`权限检查错误: 用户 ${userKey} 有无效的权限字段`, user.permission);
            return false; // 用户权限无效，拒绝访问
        }
        
        if (user.permission === 'banned') {
            console.log(`权限检查: 用户 ${userKey} 已被封禁`);
            return false;
        }
        
        const permissionLevel = {
            'banned': 0,
            'user': 1,
            'admin': 2
        };
        
        const userLevel = permissionLevel[user.permission];
        const requiredLevel = permissionLevel[requiredPermission];
        
        // 🔧 修复：现在两个level都保证有效
        const hasPermission = userLevel >= requiredLevel;
        
        if (!hasPermission) {
            console.log(`权限检查: 用户 ${userKey} (${user.permission}) 权限不足，需要 ${requiredPermission}`);
        } else {
            console.log(`权限检查: 用户 ${userKey} (${user.permission}) 有足够权限执行 ${requiredPermission} 操作`);
        }
        
        return hasPermission;
        
    } catch (error) {
        console.error('权限检查系统错误:', {
            error: error.message,
            stack: error.stack,
            chatId: chatId,
            requiredPermission: requiredPermission
        });
        return false; // 系统错误时默认拒绝访问
    }
}
/**
 * @name 处理封禁用户命令
 * @description 管理员封禁指定用户
 * @param {string} text - 命令文本
 * @param {string} chatId - 发起者聊天ID
 * @param {Object} fromUser - 发起者用户信息
 * @param {Object} tgConfig - Telegram配置
 * @param {Object} env - 环境变量
 */
async function handleBanUserCommand(text, chatId, fromUser, tgConfig, env) {
    // 检查管理员权限
    if (!await checkUserPermission(env, chatId, 'admin')) {
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            '❌ 此命令仅管理员可用'
        );
        return;
    }

    const parts = text.split(' ');
    if (parts.length < 2) {
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            '❌ 用法: /banuser @用户名'
        );
        return;
    }

    const targetUsername = parts[1].replace('@', '');
    const users = await getUsers(env);
    
    // 查找用户
    const targetUser = Object.entries(users).find(([id, user]) => 
        user.username === targetUsername
    );
    
    if (!targetUser) {
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            `❌ 未找到用户: @${targetUsername}`
        );
        return;
    }

    const [targetChatId, userData] = targetUser;
    
    // 不能封禁自己
    if (targetChatId === chatId.toString()) {
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            '❌ 不能封禁自己'
        );
        return;
    }

    // 更新用户权限
    users[targetChatId].permission = 'banned';
    users[targetChatId].bannedBy = fromUser.username;
    users[targetChatId].bannedTime = new Date().toISOString();
    
    await saveUsers(env, users);
    
    // 通知目标用户
    await sendTelegramMessage(tgConfig.BotToken, targetChatId, 
        '❌ 您的账户已被管理员封禁，无法继续使用此机器人'
    );
    
    await sendTelegramMessage(tgConfig.BotToken, chatId, 
        `✅ 已封禁用户: @${targetUsername}`
    );
}

/**
 * @name 处理用户列表命令
 * @description 显示所有用户列表（管理员专用）
 * @param {string} chatId - 聊天ID
 * @param {Object} tgConfig - Telegram配置
 * @param {Object} env - 环境变量
 */
async function handleListUsersCommand(chatId, tgConfig, env) {
    // 检查管理员权限
    if (!await checkUserPermission(env, chatId, 'admin')) {
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            '❌ 此命令仅管理员可用'
        );
        return;
    }

    const users = await getUsers(env);
    
    if (Object.keys(users).length === 0) {
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            '📝 用户列表为空'
        );
        return;
    }

    let userList = `📋 用户列表 (${Object.keys(users).length} 人)\n\n`;
    
    Object.entries(users).forEach(([id, user], index) => {
        const joinTime = new Date(user.joinTime).toLocaleDateString('zh-CN');
        const lastActive = new Date(user.lastActive).toLocaleDateString('zh-CN');
        
        const status = user.permission === 'admin' ? '👑 管理员' : 
                      user.permission === 'banned' ? '❌ 封禁' : '👤 用户';
        
        userList += `${index + 1}. ${user.username}\n`;
        userList += `   ID: ${id}\n`;
        userList += `   权限: ${status}\n`;
        userList += `   加入: ${joinTime}\n`;
        userList += `   活跃: ${lastActive}\n`;
        
        if (user.addedBy) {
            userList += `   添加者: @${user.addedBy}\n`;
        }
        
        if (user.isFirstAdmin) {
            userList += `   ⭐ 初始管理员\n`;
        }
        
        userList += `\n`;
    });

    // 如果消息太长，分开发送
    if (userList.length > 4000) {
        const half = Math.ceil(userList.length / 2);
        const part1 = userList.substring(0, half);
        const part2 = userList.substring(half);
        
        await sendTelegramMessage(tgConfig.BotToken, chatId, part1);
        await sendTelegramMessage(tgConfig.BotToken, chatId, part2);
    } else {
        await sendTelegramMessage(tgConfig.BotToken, chatId, userList);
    }
}

/**
 * @name 处理我的权限命令
 * @description 显示当前用户的权限信息
 * @param {string} chatId - 聊天ID
 * @param {Object} fromUser - 用户信息
 * @param {Object} tgConfig - Telegram配置
 * @param {Object} env - 环境变量
 */
async function handleMyPermissionCommand(chatId, fromUser, tgConfig, env) {
    const userInfo = await getUserInfo(env, chatId);
    
    if (!userInfo) {
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            '❌ 未找到您的用户信息'
        );
        return;
    }

    const permissionText = {
        'admin': '👑 管理员',
        'user': '👤 普通用户', 
        'banned': '❌ 封禁用户'
    }[userInfo.permission];

    const joinTime = new Date(userInfo.joinTime).toLocaleString('zh-CN');
    
    let message = `👤 您的账户信息\n\n`;
    message += `📝 用户名: @${fromUser.username || fromUser.first_name}\n`;
    message += `🎯 权限等级: ${permissionText}\n`;
    message += `📅 加入时间: ${joinTime}\n`;
    
    if (userInfo.permission === 'admin') {
        message += `\n💪 管理员权限: 所有命令可用`;
    } else if (userInfo.permission === 'user') {
        message += `\n🔧 用户权限: 基础命令可用`;
    } else {
        message += `\n🚫 封禁状态: 无法使用任何命令`;
    }

    await sendTelegramMessage(tgConfig.BotToken, chatId, message);
}

/**
 * @name 处理帮助命令
 * @description 显示根据用户权限定制的帮助信息
 * @param {string} chatId - 聊天ID
 * @param {Object} tgConfig - Telegram配置
 * @param {Object} env - 环境变量
 * @param {Object} currentUser - 当前用户信息
 */
async function handleHelpCommand(chatId, tgConfig, env, currentUser) {
    const isAdmin = currentUser && currentUser.permission === 'admin';
    
    let helpText = `🤖 *EdgeTunnel Bot*\n\n`;
    helpText += `👤 您的权限: ${isAdmin ? '👑 管理员' : '👤 普通用户'}\n\n`;
    helpText += `*订阅相关命令:*\n`;
    helpText += `/sub - 获取订阅链接 (推荐)\n`;
    helpText += `/quicksub - 快速订阅链接\n`;
    helpText += `/subdetail - 详细订阅格式\n\n`;
    
    helpText += `*其他命令:*\n`;
    helpText += `/status - 查看服务状态\n`;
    helpText += `/mypermission - 查看我的权限\n`;
    helpText += `/admin - 管理面板链接\n`;
    helpText += `/help - 显示此帮助信息\n`;
    
    if (isAdmin) {
        helpText += `\n*👑 管理员专用:*\n`;
        helpText += `/usage - 查看用量统计\n`;
        helpText += `/adduser - 添加用户\n`;
        helpText += `/banuser - 封禁用户\n`;
        helpText += `/listusers - 用户列表\n`;
    }
    
    helpText += `\n💡 提示: 第一个使用机器人的用户会自动成为管理员`;

    await sendTelegramMessage(tgConfig.BotToken, chatId, helpText);
}

/**
 * @name 处理状态命令
 * @description 显示服务状态信息
 * @param {string} chatId - 聊天ID
 * @param {Object} tgConfig - Telegram配置
 * @param {Object} env - 环境变量
 */
async function handleStatusCommand(chatId, tgConfig, env) {
    try {
        const userInfo = await getUserInfo(env, chatId);
        const isAdmin = userInfo && userInfo.permission === 'admin';
        
        let statusMessage = `🟢 *服务状态*\n\n`;
        statusMessage += `📊 今日请求：${await getTodayStats(env, '访问次数')}\n`;
        statusMessage += `📨 订阅生成：${await getTodayStats(env, '订阅生成')}\n`;
        statusMessage += `👥 注册用户：${Object.keys(await getUsers(env)).length}\n`;
        
        if (isAdmin) {
            // 管理员可以看到更多信息
            const config = await 读取config_JSON(env, new URL(tgConfig.webhookUrl || 'https://example.com').hostname, 'default-user');
            if (config.CF.Usage.success) {
                statusMessage += `\n☁️ Cloudflare 用量：\n`;
                statusMessage += `• Pages: ${config.CF.Usage.pages}\n`;
                statusMessage += `• Workers: ${config.CF.Usage.workers}\n`;
                statusMessage += `• 总计: ${config.CF.Usage.total}/100000\n`;
                statusMessage += `• 使用率: ${((config.CF.Usage.total / 100000) * 100).toFixed(1)}%`;
            }
        }
        
        await sendTelegramMessage(tgConfig.BotToken, chatId, statusMessage);
    } catch (error) {
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            '❌ 获取服务状态时出错'
        );
    }
}

/**
 * @name 处理管理命令
 * @description 提供管理面板链接
 * @param {string} chatId - 聊天ID
 * @param {Object} fromUser - 用户信息
 * @param {Object} tgConfig - Telegram配置
 * @param {Object} env - 环境变量
 */
async function handleAdminCommand(chatId, fromUser, tgConfig, env) {
    const userInfo = await getUserInfo(env, chatId);
    const isAdmin = userInfo && userInfo.permission === 'admin';
    
    const adminUrl = `https://${new URL(tgConfig.webhookUrl || 'https://example.com').hostname}/admin`;
    
    if (isAdmin) {
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            `⚡ *管理面板*\n\n` +
            `🔗 管理地址：${adminUrl}\n\n` +
            `您可以直接访问管理面板进行配置。`
        );
    } else {
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            `🔗 管理面板：${adminUrl}\n\n` +
            `⚠️ 需要管理员密码才能访问。`
        );
    }
}

/**
 * @name 处理用量命令
 * @description 显示详细用量统计（管理员专用）
 * @param {string} chatId - 聊天ID
 * @param {Object} fromUser - 用户信息
 * @param {Object} tgConfig - Telegram配置
 * @param {Object} env - 环境变量
 */
async function handleUsageCommand(chatId, fromUser, tgConfig, env) {
    if (!await checkUserPermission(env, chatId, 'admin')) {
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            '❌ 此命令仅管理员可用'
        );
        return;
    }

    try {
        const config = await 读取config_JSON(env, new URL(tgConfig.webhookUrl || 'https://example.com').hostname, 'default-user');
        
        let usageMessage = `📈 *用量统计*\n\n`;
        
        // 今日统计
        const todayStats = await getTodayDetailedStats(env);
        usageMessage += `📅 今日统计：\n`;
        usageMessage += `• 总访问: ${todayStats.访问次数}\n`;
        usageMessage += `• 订阅生成: ${todayStats.订阅生成}\n`;
        usageMessage += `• 管理登录: ${todayStats.管理登录}\n`;
        usageMessage += `• 首次访问: ${new Date(todayStats.首次访问时间).toLocaleTimeString()}\n\n`;
        
        // Cloudflare 用量
        if (config.CF.Usage.success) {
            usageMessage += `☁️ Cloudflare 用量：\n`;
            usageMessage += `• Pages: ${config.CF.Usage.pages}\n`;
            usageMessage += `• Workers: ${config.CF.Usage.workers}\n`;
            usageMessage += `• 总计: ${config.CF.Usage.total}\n`;
            usageMessage += `• 限额: 100,000\n`;
            usageMessage += `• 使用率: ${((config.CF.Usage.total / 100000) * 100).toFixed(1)}%`;
        }
        
        await sendTelegramMessage(tgConfig.BotToken, chatId, usageMessage);
    } catch (error) {
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            '❌ 获取用量统计时出错'
        );
    }
}

/**
 * @name 处理订阅命令
 * @description 生成并发送订阅链接
 * @param {string} chatId - 聊天ID
 * @param {Object} fromUser - 用户信息
 * @param {Object} tgConfig - Telegram配置
 * @param {Object} env - 环境变量
 */
async function handleSubCommand(chatId, fromUser, tgConfig, env) {
    try {
        // 获取配置 - 使用与网页版相同的逻辑
        const host = new URL(tgConfig.webhookUrl || 'https://github1.xishuai.sbs').hostname;
        
        // 使用与网页版相同的UUID生成逻辑
        const 管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY;
        const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
        const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);
        const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
        const envUUID = env.UUID || env.uuid;
        const finalUserID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), userIDMD5.slice(16, 20), userIDMD5.slice(20)].join('-');
        
        const config = await 读取config_JSON(env, host, finalUserID);
        
        // 生成与网页版相同的订阅token
        const token = await MD5MD5(host + config.UUID);
        const baseUrl = `https://${host}/sub?token=${token}`;
        
        // 生成不同格式的订阅链接
        const subMessage = `🔗 *订阅链接*\n\n` +
            `📱 *通用订阅* (推荐):\n\`${baseUrl}\`\n\n` +
            `⚡ *Clash订阅*:\n\`${baseUrl}&target=clash\`\n\n` +
            `🎯 *SingBox订阅*:\n\`${baseUrl}&target=singbox\`\n\n` +
            `💥 *Surge订阅*:\n\`${baseUrl}&target=surge\`\n\n` +
            `💡 提示: 复制链接到对应的客户端即可使用`;
        
        await sendTelegramMessage(tgConfig.BotToken, chatId, subMessage, true);
        
    } catch (error) {
        console.error('处理订阅命令错误:', error);
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            '❌ 生成订阅链接时出错，请稍后重试\n错误信息: ' + error.message
        );
    }
}
/**
 * @name 处理详细订阅命令
 * @description 提供更详细的订阅格式选择
 * @param {string} chatId - 聊天ID
 * @param {Object} fromUser - 用户信息
 * @param {Object} tgConfig - Telegram配置
 * @param {Object} env - 环境变量
 */
async function handleSubDetailCommand(chatId, fromUser, tgConfig, env) {
    try {
        const host = new URL(tgConfig.webhookUrl || 'https://github1.xishuai.sbs').hostname;
        // 修复：删除这行错误的 userID 定义
        // const userID = fromUser.id.toString(); // 这行需要删除
        
        // 使用与网页版相同的UUID生成逻辑
        const 管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY;
        const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
        const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);
        const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
        const envUUID = env.UUID || env.uuid;
        const finalUserID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), userIDMD5.slice(16, 20), userIDMD5.slice(20)].join('-');
        
        const config = await 读取config_JSON(env, host, finalUserID);
        const token = await MD5MD5(host + config.UUID);
        const baseUrl = `https://${host}/sub?token=${token}`;

        // 生成不同客户端格式的订阅链接
        const subMessage = `🔗 *详细订阅格式*\n\n` +
            `📱 *通用订阅* (推荐):\n\`${baseUrl}\`\n\n` +
            `⚡ *Clash订阅*:\n\`${baseUrl}&target=clash\`\n\n` +
            `🎯 *SingBox订阅*:\n\`${baseUrl}&target=singbox\`\n\n` +
            `💥 *Surge订阅*:\n\`${baseUrl}&target=surge\`\n\n` +
            `🌐 *Shadowrocket订阅*:\n\`${baseUrl}&target=mixed\`\n\n` +
            `📋 *Quantumult X订阅*:\n\`${baseUrl}&target=mixed\`\n\n` +
            `💡 提示: 复制对应的链接到客户端即可使用`;
        await sendTelegramMessage(tgConfig.BotToken, chatId, subMessage, true);

    } catch (error) {
        console.error('处理详细订阅命令错误:', error);
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            '❌ 生成订阅链接时出错'
        );
    }
}
/**
 * @name 处理快速订阅命令
 * @description 提供最常用的订阅链接
 * @param {string} chatId - 聊天ID
 * @param {Object} fromUser - 用户信息
 * @param {Object} tgConfig - Telegram配置
 * @param {Object} env - 环境变量
 */
async function handleQuickSubCommand(chatId, fromUser, tgConfig, env) {
    try {
        const host = new URL(tgConfig.webhookUrl || 'https://github1.xishuai.sbs').hostname;

        const 管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY;
        const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
        const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);
        const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
        const envUUID = env.UUID || env.uuid;
        const finalUserID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), userIDMD5.slice(16, 20), userIDMD5.slice(20)].join('-');
        
        const config = await 读取config_JSON(env, host, finalUserID);
        const token = await MD5MD5(host + config.UUID);
        const baseUrl = `https://${host}/sub?token=${token}`;
        
        // 生成最常用的订阅链接
        const subMessage = `⚡ *快速订阅*\n\n` +
            `📱 *通用订阅* (推荐):\n\`${baseUrl}\`\n\n` +
            `⚡ *Clash订阅*:\n\`${baseUrl}&target=clash\`\n\n` +
            `🎯 *SingBox订阅*:\n\`${baseUrl}&target=singbox\`\n\n` +
            `💡 提示: 复制链接到对应的客户端即可使用`;

        await sendTelegramMessage(tgConfig.BotToken, chatId, subMessage, true);
    } catch (error) {
        console.error('处理快速订阅命令错误:', error);
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            '❌ 生成订阅链接时出错'
        );
    }
}

/**
 * @name 获取今日统计
 * @description 获取指定类型的今日统计数据
 * @param {Object} env - 环境变量
 * @param {string} type - 统计类型
 * @returns {number} 统计数值
 */
async function getTodayStats(env, type = '访问次数') {
    try {
        const today = new Date().toISOString().split('T')[0];
        const statsKey = `stats_${today}`;
        const statsText = await env.KV.get(statsKey);
        
        if (statsText) {
            const stats = JSON.parse(statsText);
            return stats[type] || 0;
        }
    } catch (error) {
        console.error('获取统计失败:', error);
    }
    return 0;
}

/**
 * @name 获取详细今日统计
 * @description 获取完整的今日统计数据
 * @param {Object} env - 环境变量
 * @returns {Object} 统计对象
 */
async function getTodayDetailedStats(env) {
    try {
        const today = new Date().toISOString().split('T')[0];
        const statsKey = `stats_${today}`;
        const statsText = await env.KV.get(statsKey);
        
        if (statsText) {
            return JSON.parse(statsText);
        }
    } catch (error) {
        console.error('获取详细统计失败:', error);
    }
    
    return {
        访问次数: 0,
        订阅生成: 0,
        管理登录: 0,
        首次访问时间: new Date().toISOString()
    };
}

/**
 * @name 发送Telegram消息
 * @description 向指定聊天发送Telegram消息
 * @param {string} botToken - 机器人Token
 * @param {string} chatId - 聊天ID
 * @param {string} text - 消息文本
 * @param {boolean} disableWebPagePreview - 是否禁用网页预览
 */
async function sendTelegramMessage(botToken, chatId, text, disableWebPagePreview = false) {
    if (!botToken) return;
    
    const url = `https://api.telegram.org/bot${botToken}/sendMessage`;
    
    const payload = {
        chat_id: chatId,
        text: text,
        parse_mode: 'Markdown',
        disable_web_page_preview: disableWebPagePreview
    };
    
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload)
        });
        
        if (!response.ok) {
            console.error('发送 Telegram 消息失败:', await response.text());
        }
    } catch (error) {
        console.error('发送 Telegram 消息错误:', error);
    }
}

/**
 * @name 获取Telegram配置
 * @description 从KV存储获取Telegram机器人配置
 * @param {Object} env - 环境变量
 * @returns {Object} Telegram配置对象
 */
async function getTelegramConfig(env) {
    try {
        const tgText = await env.KV.get('tg.json');
        if (tgText) {
            const config = JSON.parse(tgText);
            return {
                BotToken: config.BotToken,
                ChatID: config.ChatID,
                webhookUrl: config.webhookUrl || 'https://github1.xishuai.sbs'
            };
        }
    } catch (error) {
        console.error('读取 tg.json 失败:', error);
    }
    return { BotToken: null, ChatID: null, webhookUrl: 'https://github1.xishuai.sbs' };
}

/**
 * @name 处理Telegram命令
 * @description 统一处理所有Telegram命令，包含权限检查
 * @param {string} text - 命令文本
 * @param {string} chatId - 聊天ID
 * @param {Object} fromUser - 用户信息
 * @param {Object} tgConfig - Telegram配置
 * @param {Object} env - 环境变量
 */
async function handleTelegramCommand(text, chatId, fromUser, tgConfig, env) {
    console.log(`🔤 处理命令 - 原始文本: "${text}"`);
    
    // 统一初始化用户（确保用户存在）
    const users = await initAdminUser(env, chatId, fromUser.username || fromUser.first_name);
    const userKey = chatId.toString();
    const currentUser = users[userKey];
    
    // 检查用户是否被封禁
    if (currentUser.permission === 'banned') {
        await sendTelegramMessage(tgConfig.BotToken, chatId, 
            '❌ 您的账户已被封禁，无法使用此机器人'
        );
        return;
    }
    
    // 清理命令格式
    let command = text.split(' ')[0].toLowerCase();
    
    // 移除 @botusername 部分
    if (command.includes('@')) {
        command = command.split('@')[0];
    }
    
    console.log(`🎯 最终命令: "${command}", 用户权限: ${currentUser.permission}`);
    
    // 根据权限处理命令
    switch (command) {
        case '/start':
        case '/help':
            await handleHelpCommand(chatId, tgConfig, env, currentUser);
            break;
            
        case '/sub':
            await handleSubCommand(chatId, fromUser, tgConfig, env);
            break;
            
        case '/subdetail':
            await handleSubDetailCommand(chatId, fromUser, tgConfig, env);
            break;
            
        case '/quicksub':
            await handleQuickSubCommand(chatId, fromUser, tgConfig, env);
            break;
            
        case '/status':
            await handleStatusCommand(chatId, tgConfig, env);
            break;
            
        case '/mypermission':
            await handleMyPermissionCommand(chatId, fromUser, tgConfig, env);
            break;
            
        case '/admin':
            await handleAdminCommand(chatId, fromUser, tgConfig, env);
            break;
            
        case '/usage':
            if (!await checkUserPermission(env, chatId, 'admin')) {
                await sendTelegramMessage(tgConfig.BotToken, chatId, 
                    '❌ 此命令仅管理员可用'
                );
                return;
            }
            await handleUsageCommand(chatId, fromUser, tgConfig, env);
            break;
            
        case '/adduser':
            if (!await checkUserPermission(env, chatId, 'admin')) {
                await sendTelegramMessage(tgConfig.BotToken, chatId, 
                    '❌ 此命令仅管理员可用'
                );
                return;
            }
            await handleAddUserCommand(text, chatId, fromUser, tgConfig, env);
            break;
            
        case '/banuser':
            if (!await checkUserPermission(env, chatId, 'admin')) {
                await sendTelegramMessage(tgConfig.BotToken, chatId, 
                    '❌ 此命令仅管理员可用'
                );
                return;
            }
            await handleBanUserCommand(text, chatId, fromUser, tgConfig, env);
            break;
            
        case '/listusers':
            if (!await checkUserPermission(env, chatId, 'admin')) {
                await sendTelegramMessage(tgConfig.BotToken, chatId, 
                    '❌ 此命令仅管理员可用'
                );
                return;
            }
            await handleListUsersCommand(chatId, tgConfig, env);
            break;
            
        default:
            await sendTelegramMessage(tgConfig.BotToken, chatId, 
                '❌ 未知命令，请输入 /help 查看可用命令'
            );
            break;
    }
}

/**
 * @name 处理Telegram Webhook
 * @description 处理Telegram机器人Webhook请求
 * @param {Request} request - 请求对象
 * @param {Object} env - 环境变量
 * @returns {Response} 响应对象
 */
async function handleTelegramWebhook(request, env) {
    console.log('=== 🔔 Telegram Webhook 开始 ===');
    
    try {
        console.log('📨 请求方法:', request.method);
        console.log('🔗 请求URL:', request.url);

        if (request.method !== 'POST') {
            console.log('❌ 方法不允许');
            return new Response('Method not allowed', { status: 405 });
        }

        // 读取请求体
        const body = await request.text();
        console.log('📝 原始请求体:', body);
        
        let update;
        try {
            update = JSON.parse(body);
            console.log('📊 解析后的数据:', JSON.stringify(update, null, 2));
        } catch (parseError) {
            console.error('❌ JSON 解析错误:', parseError);
            return new Response('OK');
        }
        
        if (!update.message) {
            console.log('⚠️ 忽略非消息更新，更新类型:', Object.keys(update).join(', '));
            return new Response('OK');
        }

        const message = update.message;
        const chatId = message.chat.id;
        const text = message.text || '';
        const fromUser = message.from;

        console.log(`👤 用户ID: ${fromUser.id}, 用户名: ${fromUser.username}`);
        console.log(`💬 聊天ID: ${chatId}, 消息: "${text}"`);

        // 获取配置
        const tgConfig = await getTelegramConfig(env);
        console.log('🔧 Bot配置检查 - Token:', tgConfig.BotToken ? '已配置' : '未配置');
        console.log('🔧 ChatID配置:', tgConfig.ChatID || '未配置');
        
        if (!tgConfig.BotToken) {
            console.error('❌ Bot Token 未配置，无法回复消息');
            return new Response('OK');
        }

        console.log('🚀 开始处理命令...');
        await handleTelegramCommand(text, chatId, fromUser, tgConfig, env);
        console.log('✅ 命令处理完成');

        return new Response('OK');
    } catch (error) {
        console.error('💥 Webhook 严重错误:', error);
        console.error('💥 错误堆栈:', error.stack);
        return new Response('OK');
    } finally {
        console.log('=== 🔔 Telegram Webhook 结束 ===');
    }
}
