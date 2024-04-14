window.onload = function() {  
  document.getElementById("info_text").innerHTML="欢迎使用安全网关"
  // 你的代码 
  MODPKICAshowgonggao1() 
};

function login_reloadyzm(){
  document.getElementsByName('verifycode')[0].value=Math.floor(Date.now() / 1000); 
}
function login_certlogin(){
var xhr;  
if (window.XMLHttpRequest) { // 大多数浏览器  
    xhr = new XMLHttpRequest();  
} else if (window.ActiveXObject) { // IE6 及更低版本  
    try {  
        xhr = new ActiveXObject("Microsoft.XMLHTTP");  
    } catch (e) {  
        // 处理错误，可能是因为 ActiveX 被禁用等  
        xhr = false;  
    }  
}  
if (!xhr) {  
    // 无法创建一个有效的 xhr 对象，可能是因为浏览器太旧或者不支持  
    alert('无法创建 XMLHttpRequest 对象');  
}
xhr.open("GET", "https://192.168.101.152:8443/admin", false); // 设置目标URL，true表示异步  
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded"); // 设置请求头  
xhr.onreadystatechange = function () {  
    if (xhr.readyState == 4) {  
        if (xhr.status == 200) {  
            // 请求成功，处理响应数据  
            var response = xhr.responseText; 
            var responseJSON = JSON.parse(response);   
            alert(responseJSON.status+":"+responseJSON.info)
            // 在这里处理响应数据  
        } else {  
            // 请求失败，处理错误信息  
            var error = xhr.statusText;  
            alert(error)
            // 在这里处理错误信息  
        }  
    }  
};  
xhr.send("username=张三&age=10"); // 发送请求，这里将参数作为查询字符串发送
}

function login_submit(){
  var cuid=document.getElementsByName('account')[0].value
  var ckey=document.getElementsByName('password')[0].value
  var vid=document.getElementsByName('verifycode')[0].value
  console.log(cuid,ckey,vid)
  if(cuid.length!=8){
    modsetinfotext("请输入8位登录账号")
    return
  }
  if(ckey.length != 6){
    modsetinfotext("请输入6位登录密码")
    return
  }
  if(Math.floor(Date.now() / 1000) - vid >5){
    modsetinfotext("验证码已经过期，请刷新验证码。")
    return
  }

  if(cuid=="88888888"  && ckey=="666666"){
    alert("欢迎使用安全网关")
  }else{
    modsetinfotext("登陆失败:账号或密码错误!")
    return
  }
}

function modsetinfotext(text){
  document.getElementById("info_text").innerHTML=text
  setTimeout(function() {  
    modsetinfotext("欢迎使用安全网关") 
}, 2000);
}

function MODPKICAclosegonggao1(){ //隐藏公告
  document.getElementById("MODPKICAgonggao1").style.display="none";
}
function MODPKICAclosegonggao2(){ //隐藏相关下载
  document.getElementById("MODPKICAgonggao2").style.display="none";
}
function MODPKICAshowgonggao2(){ //显示相关下载
  document.getElementById("MODPKICAgonggao2").style.display="";
}
function MODPKICAshowgonggao1(){ //显示公告
  document.getElementById("MODPKICAgonggao1").style.display="";
  document.getElementById("MODPKICAgonggao1").style="margin-left:360px;";
}