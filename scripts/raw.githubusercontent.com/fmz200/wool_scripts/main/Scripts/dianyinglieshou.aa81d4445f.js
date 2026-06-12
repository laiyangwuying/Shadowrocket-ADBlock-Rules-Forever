/**
 * @author fmz200
 * @function ç”µå½±çŒ�æ‰‹
 * @date 2024-10-11 20:16:13
 */

let requestUrl = $request.url;
let responseBody = $response.body;

let obj = JSON.parse(responseBody);

// ^https:\/\/app-v1\.ecoliving168\.com\/api\/v1\/movie\/index_recommend\? url script-response-body https://raw.githubusercontent.com/fmz200/wool_scripts/main/Scripts/dianyinglieshou.js
// 
// hostname = app-v1.ecoliving168.com
if (requestUrl.includes("/api/v1/movie/index_recommend?")) {
  // åˆ¤æ–­obj.dataæ˜¯å�¦å­˜åœ¨ä¸”æ˜¯æ•°ç»„
  if (Array.isArray(obj.data)) {
    console.log('å�»å¹¿å‘Šå¼€å§‹ğŸ’•');
    // é��å�†obj.dataä¸­çš„æ¯�ä¸ªå…ƒç´ 
    obj.data = obj.data.filter(item => {
      // å¦‚æ�œitem.layoutç­‰äº�'advert_self'ï¼Œåˆ™ä¸�ä¿�ç•™è¿™ä¸ªå…ƒç´ 
      if (item.layout === 'advert_self') {
        return false;
      }

      // å¦‚æ�œitem.listæ˜¯æ•°ç»„ï¼Œåˆ™é��å�†å¹¶å¤„ç�†listä¸­çš„å…ƒç´ 
      if (Array.isArray(item.list)) {
        item.list = item.list.filter(subItem => subItem.type !== 3);
      }

      return true; // ä¿�ç•™å…¶ä»–å…ƒç´ 
    });
  }
  console.log('å�»å¹¿å‘Šç»“æ�ŸğŸ’•');
}

$done({body: JSON.stringify(obj)});
