/**
 * Created by Administrator on 2014/8/6.
 */
var httpProxy = require('http-proxy');
var proxy = httpProxy.createProxyServer();
var port = process.env.PORT || 3000;

require('http').createServer(function(req, res) {


if(!req.headers['ghost'])
	{
	res.write("notdata");
	res.end();
return ;
}
    var host;

	
    if((req.headers['ssl'])!='true'){
        host=req.headers.host=req.headers['ghost'];
        if(req.headers['hiddenip']=='true'){
            req.headers['x-real-ip']='';
            req.headers['x-forwarded-for']='';
        }
    console.log(req.headers);
    proxy.web(req, res, { target: 'http://'+host });
    }else{
        host=req.headers.host=req.headers['ghost'];
        proxy.web(req, res, { target: 'https://'+req.headers['ghost'] });
       // res.write("is ssl host:"+req.headers.host);
       // res.end();
    }

}).listen(port);



proxy.on('error', function(e){
    console.log(e.message);
});