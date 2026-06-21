// ikuai_business.js - 移除爱快业务管理广告
let body = JSON.parse($response.body);

if (body.data && Array.isArray(body.data)) {
    // 过滤掉包含 banner 广告的项
    body.data = body.data.filter(item => {
        // 如果 ad 字段包含 _banner.png，则是广告，过滤掉
        return !(item.ad && item.ad.includes('_banner.png'));
    });
}

$done({ body: JSON.stringify(body) });
